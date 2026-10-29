package parser

import (
	"fmt"
	"strconv"
	"strings"
)

// This file implements the OpenLibre olcrtc:// share-link format (URI
// format v1, docs/uri.md in the olcrtc repository) and its subscription
// metadata blocks (docs/sub.md). The grammar is NOT URI grammar:
//
//	olcrtc://<Provider>?<Transport>[<k=v&k=v>]@<RoomID>#<EncryptionKey>$<MIMO>
//
// The transport name and the <...> parameter payload sit where net/url
// would look for a host and a query, and a RoomID may itself be a full
// URL carrying its own "://" and "/" (jitsi rooms), so the link is cut
// by hand, never through url.Parse. The reference client (owenclave) is
// deliberately not copied where it is defective: it drops the <...>
// payload entirely and URL-decodes fields the documents emit raw. This
// parser keeps the payload, takes every field verbatim (no percent or
// form decoding anywhere — the spec leaves escaping to the client and
// the document examples are raw), and validates strictly.
//
// OutboundSpec representation (the package has no provider/endpoint
// fields shaped for this protocol, so the mapping is fixed here and in
// validate/StableKey):
//
//   - Protocol = "olcrtc", Transport = the olcrtc transport name,
//     Security = "olc2" (the OLC2 record layer the key feeds; not TLS).
//   - Host carries the RoomID verbatim and Port is 0: an olcrtc server
//     has no host:port endpoint — the provider's SFU is reached by room,
//     not by address. validate() exempts olcrtc from the port rule and
//     instead requires provider/transport/key shape, so a zero port is
//     an honest "no endpoint", never a dial target.
//   - Password carries the 64-hex encryption key (the credential field;
//     the vault document stores "password" like every other secret).
//   - Options["olcrtc_provider"] and Options["olcrtc_room"] carry the
//     provider and room under explicit keys, so a downstream consumer
//     (the future olcrtc transport) does not have to reinterpret Host.
//   - Transport parameters ride in Options under their URI key names
//     ("fps", "vp8-batch", "video-codec", ...), canonicalized: a known
//     parameter spelled with exactly its session-default value is not
//     stored, since the session layer applies that same default —
//     the same canonical form sora's parser produces, so a spec parsed
//     here is field-for-field the spec sora parses from the same link.
//     Subscription ## fields ride under "olcrtc_meta_<key>" (see
//     parseList).
//
// Ported 1-in-1 from sora's parser (commits 723b1fb6, 86651735 and
// the Z-1..Z-6 review fixes 4f5fa7c0) for import parity; see
// reports/openlibre/LEGACY-PARITY.md. One deliberate divergence:
// legacy has no share-link emitter anywhere (neither the Go core, the
// Dart app nor the C# client generates per-server links), so sora's
// ShareLink/emitOLCRTCParams are not ported — there is no caller for
// them here. The grammar, registries, dictionaries, canonicalization
// and error sentinels below are identical to sora's.
//   - DisplayName is the MIMO comment; a subscription ##name overrides
//     it (SPEC R-9: ##name outranks MIMO).

// olcrtcProviders is the closed provider registry of the olcrtc code
// (internal/engine/builtin RegisterDefaults).
var olcrtcProviders = map[string]bool{
	"jitsi": true, "telemost": true, "wbstream": true, "none": true,
}

// olcrtcTransports is the closed transport registry
// (internal/app/session RegisterDefaults).
var olcrtcTransports = map[string]bool{
	"datachannel": true, "vp8channel": true, "seichannel": true, "videochannel": true,
}

// olcrtcParamSpec describes one payload key of one transport. def is
// the session-layer default from the olcrtc code (the layer a YAML
// consumer actually runs with); the emitter omits values equal to it.
// Int keys carry an inclusive range; enum keys carry their values. A
// max of olcrtcNoMax means "no documented upper bound".
type olcrtcParamSpec struct {
	key  string
	def  string
	min  int
	max  int
	enum []string
}

const olcrtcNoMax = 1<<31 - 1

var olcrtcTransportParams = map[string][]olcrtcParamSpec{
	"datachannel": {},
	"vp8channel": {
		{key: "vp8-fps", def: "30", min: 1, max: 240},
		{key: "vp8-batch", def: "64", min: 1, max: olcrtcNoMax},
	},
	"seichannel": {
		{key: "fps", def: "30", min: 1, max: 240},
		{key: "batch", def: "64", min: 1, max: olcrtcNoMax},
		{key: "frag", def: "900", min: 1, max: 60000},
		{key: "ack-ms", def: "2000", min: 1, max: olcrtcNoMax},
	},
	"videochannel": {
		// video-w defaults to 1080 instead of 1920 when the effective
		// codec is tile; olcrtcDefault resolves that case.
		{key: "video-w", def: "1920", min: 16, max: 8192},
		{key: "video-h", def: "1080", min: 16, max: 8192},
		{key: "video-fps", def: "30", min: 1, max: 240},
		{key: "video-codec", def: "qrcode", enum: []string{"qrcode", "tile"}},
		{key: "video-qr-size", def: "0", min: 0, max: olcrtcNoMax},
		{key: "video-qr-recovery", def: "low", enum: []string{"low", "medium", "high", "highest"}},
		// The session layer leaves tile-module unset (0); its own
		// validation accepts 0 as "unset" inside the 1..270 range.
		{key: "video-tile-module", def: "0", min: 0, max: 270},
		{key: "video-tile-rs", def: "0", min: 0, max: 200},
	},
}

// The v1 payload keys video-bitrate and video-hw are deprecated: the
// current olcrtc runtime ignores them (docs/uri.md migration note).
// They need no table here — import preserves them like any other key
// (pinned by TestOLCRTCUnknownAndDeprecatedParams); producers are
// required to stop emitting them (sora's emitter never produces them;
// legacy has no emitter).

func olcrtcParamRule(transport, key string) (olcrtcParamSpec, bool) {
	for _, spec := range olcrtcTransportParams[transport] {
		if spec.key == key {
			return spec, true
		}
	}
	return olcrtcParamSpec{}, false
}

// olcrtcDefault returns the session default of one known key for one
// transport. codec is the payload's effective video codec ("" when
// absent), which moves the video-w default for tile.
func olcrtcDefault(transport, key, codec string) string {
	spec, ok := olcrtcParamRule(transport, key)
	if !ok {
		return ""
	}
	if transport == "videochannel" && key == "video-w" && codec == "tile" {
		return "1080"
	}
	return spec.def
}

// isOLCRTCLink reports whether raw carries the olcrtc scheme. The check
// is case-insensitive on the scheme only, matching how the ecosystem's
// clients route links; provider and transport names stay case-sensitive
// because the olcrtc registries compare exact strings.
func isOLCRTCLink(raw string) bool {
	s := strings.TrimSpace(raw)
	return len(s) >= len("olcrtc://") && strings.EqualFold(s[:len("olcrtc://")], "olcrtc://")
}

// parseOLCRTCLink parses one olcrtc:// link by the hand grammar above.
// Cuts, in order: the encryption key is located first (anchored on its
// strict shape — exactly 64 hex chars followed by end-of-link or the
// '$' that opens MIMO), then the room at the FIRST '@' of what remains
// (provider, transport and payload cannot contain '@', a room URL
// can), then provider/transport at the first '?', then the payload
// block hugging the transport name.
func parseOLCRTCLink(raw string) (OutboundSpec, error) {
	rest := strings.TrimSpace(raw)[len("olcrtc://"):]

	hash, key, mimo, err := splitOLCRTCKey(rest)
	if err != nil {
		return OutboundSpec{}, err
	}
	head := rest[:hash]
	at := strings.Index(head, "@")
	if at < 0 {
		return OutboundSpec{}, fmt.Errorf("%w: olcrtc link has no @ before the room id", ErrInvalid)
	}
	left, room := head[:at], head[at+1:]
	q := strings.Index(left, "?")
	if q < 0 {
		return OutboundSpec{}, fmt.Errorf("%w: olcrtc link has no ? before the transport", ErrInvalid)
	}
	provider, transportPart := left[:q], left[q+1:]
	if provider == "" {
		return OutboundSpec{}, fmt.Errorf("%w: olcrtc link has an empty provider", ErrInvalid)
	}
	if !olcrtcProviders[provider] {
		return OutboundSpec{}, fmt.Errorf("%w: olcrtc provider %q", ErrUnsupported, provider)
	}
	transport, payload, hasPayload, err := splitOLCRTCPayload(transportPart)
	if err != nil {
		return OutboundSpec{}, err
	}
	if transport == "" {
		return OutboundSpec{}, fmt.Errorf("%w: olcrtc link has an empty transport", ErrInvalid)
	}
	if !olcrtcTransports[transport] {
		return OutboundSpec{}, fmt.Errorf("%w: olcrtc transport %q", ErrUnsupported, transport)
	}
	if room == "" && provider != "none" {
		// Provider none is the one registry entry whose room is
		// optional in the olcrtc validator (it connects by engine URL
		// and token, which the URI cannot express at all).
		return OutboundSpec{}, fmt.Errorf("%w: olcrtc link has an empty room id", ErrInvalid)
	}
	if provider == "wbstream" && room == "any" {
		// The wbstream provider itself rejects the placeholder "any"
		// as an empty room (internal/auth/wbstream Issue).
		return OutboundSpec{}, fmt.Errorf("%w: olcrtc wbstream room id %q is a placeholder, not a room", ErrInvalid, room)
	}
	params, err := parseOLCRTCParams(transport, payload, hasPayload)
	if err != nil {
		return OutboundSpec{}, err
	}
	o := OutboundSpec{
		Protocol:    "olcrtc",
		Transport:   transport,
		Security:    "olc2",
		Host:        room,
		Password:    key,
		DisplayName: mimo,
		Options:     map[string]string{"olcrtc_provider": provider, "olcrtc_room": room},
	}
	codec := params["video-codec"]
	if codec == "" {
		codec = "qrcode"
	}
	for k, v := range params {
		if spec, known := olcrtcParamRule(transport, k); known &&
			olcrtcValueEquals(spec, v, olcrtcDefault(transport, k, codec)) {
			continue // canonical form: defaults are not stored
		}
		o.Options[k] = v
	}
	o.CountryCode = countryCode(o.DisplayName)
	return o, o.validate()
}

// splitOLCRTCKey finds the '#' that opens the encryption key and
// returns its index, the key, and the MIMO comment after an optional
// '$'. Anchoring on the key's exact shape (64 hex, then end or '$')
// keeps a '#' inside a room id or inside MIMO from being mistaken for
// the key separator — the failure mode of first-separator parsers.
func splitOLCRTCKey(rest string) (int, string, string, error) {
	for i := 0; i < len(rest); i++ {
		if rest[i] != '#' {
			continue
		}
		candidate := rest[i+1:]
		if len(candidate) < 64 || !isHex64(candidate[:64]) {
			continue
		}
		if len(candidate) == 64 {
			return i, candidate, "", nil
		}
		if candidate[64] == '$' {
			return i, candidate[:64], candidate[65:], nil
		}
	}
	if !strings.Contains(rest, "#") {
		return 0, "", "", fmt.Errorf("%w: olcrtc link has no # before the encryption key", ErrInvalid)
	}
	return 0, "", "", fmt.Errorf("%w: olcrtc encryption key must be exactly 64 hex characters", ErrInvalid)
}

// isHex64 reports whether s is exactly 64 hexadecimal characters.
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// splitOLCRTCPayload splits "<Transport><k=v&...>" into the transport
// name and the raw payload inside the angle brackets ("" when the
// block is absent — the block is dropped entirely when defaults are
// used). hasPayload reports whether a <...> block was present at
// all, which the empty string alone cannot express: datachannel
// rejects even an empty block (see parseOLCRTCParams). The block
// must hug the transport name and close the segment: anything after
// '>' belongs to the room side of the grammar and its presence here
// means the link is malformed.
func splitOLCRTCPayload(part string) (transport, payload string, hasPayload bool, err error) {
	lt := strings.Index(part, "<")
	if lt < 0 {
		if strings.Contains(part, ">") {
			return "", "", false, fmt.Errorf("%w: olcrtc transport %q has a stray >", ErrInvalid, part)
		}
		return part, "", false, nil
	}
	block := part[lt:]
	if len(block) < 2 || block[len(block)-1] != '>' {
		return "", "", false, fmt.Errorf("%w: olcrtc parameter block is not closed by >", ErrInvalid)
	}
	inner := block[1 : len(block)-1]
	if strings.ContainsAny(inner, "<>") {
		return "", "", false, fmt.Errorf("%w: olcrtc parameter block contains a nested bracket", ErrInvalid)
	}
	return part[:lt], inner, true, nil
}

// parseOLCRTCParams parses and validates the payload body. Known keys
// are validated strictly (type, range, enum, cross-field tile rules);
// unknown keys are preserved verbatim — a newer producer's settings
// must survive an older sora import instead of being silently dropped
// (the reference client's payload loss is the defect being avoided).
func parseOLCRTCParams(transport, payload string, hasPayload bool) (map[string]string, error) {
	params := map[string]string{}
	// Chosen strictly, matching the IMPORT.md validation table
	// ("any payload at datachannel is rejected"): datachannel is
	// specified as "No payload", so a present <...> block is a
	// payload even when empty — datachannel<> is rejected, not
	// silently treated as no block. For other transports an empty
	// block carries no parameters and stays equivalent to absence.
	if hasPayload && transport == "datachannel" {
		return nil, fmt.Errorf("%w: olcrtc datachannel takes no parameters, got <%s>", ErrInvalid, payload)
	}
	if payload == "" {
		return params, nil
	}
	for _, pair := range strings.Split(payload, "&") {
		k, v, found := strings.Cut(pair, "=")
		if !found || k == "" || v == "" {
			return nil, fmt.Errorf("%w: olcrtc parameter %q is not key=value", ErrInvalid, pair)
		}
		if strings.ContainsAny(k+v, " \t") {
			return nil, fmt.Errorf("%w: olcrtc parameter %q contains whitespace", ErrInvalid, pair)
		}
		if _, dup := params[k]; dup {
			return nil, fmt.Errorf("%w: olcrtc parameter %q appears twice", ErrInvalid, k)
		}
		params[k] = v
	}
	if err := validateOLCRTCParams(transport, params); err != nil {
		return nil, err
	}
	return params, nil
}

// validateOLCRTCParams applies the per-transport dictionary to a
// parameter set: known keys strictly, unknown keys untouched.
func validateOLCRTCParams(transport string, params map[string]string) error {
	if transport == "datachannel" && len(params) > 0 {
		return fmt.Errorf("%w: olcrtc datachannel takes no parameters", ErrInvalid)
	}
	for k, v := range params {
		spec, known := olcrtcParamRule(transport, k)
		if !known {
			continue
		}
		if spec.enum != nil {
			ok := false
			for _, e := range spec.enum {
				if v == e {
					ok = true
					break
				}
			}
			if !ok {
				return fmt.Errorf("%w: olcrtc parameter %s=%q, want one of %s", ErrInvalid, k, v, strings.Join(spec.enum, "/"))
			}
			continue
		}
		n, err := olcrtcInt(v)
		if err != nil {
			return fmt.Errorf("%w: olcrtc parameter %s=%q is not a decimal integer", ErrInvalid, k, v)
		}
		if n < spec.min || n > spec.max {
			return fmt.Errorf("%w: olcrtc parameter %s=%d, want %d..%d", ErrInvalid, k, n, spec.min, spec.max)
		}
	}
	// Cross-field tile rules: the tile-only keys require the tile
	// codec, and tile frames are strictly 1080x1080 when a dimension
	// is pinned (ErrTileCodecDimensions in the olcrtc validator).
	// A tile key spelled 0 is not "used" here: the session layer
	// treats 0 as unset for video-tile-module (its default is 0,
	// like video-tile-rs and video-qr-size in the dictionary), so
	// an explicit =0 neither requires the tile codec nor is
	// stored — canonicalization drops it as the default anyway.
	if transport == "videochannel" {
		codec := params["video-codec"]
		hasModule := olcrtcParamNonZero(params, "video-tile-module")
		hasRS := olcrtcParamNonZero(params, "video-tile-rs")
		if (hasModule || hasRS) && codec != "tile" {
			return fmt.Errorf("%w: olcrtc video-tile-* parameters require video-codec=tile", ErrInvalid)
		}
		if codec == "tile" {
			for _, k := range []string{"video-w", "video-h"} {
				if v, ok := params[k]; ok && v != "1080" {
					return fmt.Errorf("%w: olcrtc tile codec requires %s=1080, got %s", ErrInvalid, k, v)
				}
			}
		}
	}
	return nil
}

// olcrtcParamNonZero reports whether params carries key with a
// numerically non-zero value (an absent key, an unparsable value —
// already rejected by the per-key range check above — and an
// explicit 0 all count as unset).
func olcrtcParamNonZero(params map[string]string, key string) bool {
	v, ok := params[key]
	if !ok {
		return false
	}
	n, err := olcrtcInt(v)
	return err == nil && n != 0
}

// olcrtcInt parses a bare decimal integer: digits only, no sign, no
// spaces — the shape every documented producer emits.
func olcrtcInt(s string) (int, error) {
	if s == "" {
		return 0, strconv.ErrSyntax
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, strconv.ErrSyntax
		}
	}
	return strconv.Atoi(s)
}

// olcrtcValueEquals compares a parameter value with its default:
// numerically for int keys (so "064" equals the "64" default),
// literally for enums.
func olcrtcValueEquals(spec olcrtcParamSpec, value, def string) bool {
	if spec.enum != nil {
		return value == def
	}
	n, err := olcrtcInt(value)
	if err != nil {
		return false
	}
	d, err := olcrtcInt(def)
	return err == nil && n == d
}

// applyOLCRTCMeta binds one "##key: value" subscription line to the
// server at index idx of r.Servers (the nearest preceding olcrtc://
// line, tracked by parseList). ##name replaces the display name —
// it outranks the link's MIMO comment; every other key, known or not,
// is preserved under Options["olcrtc_meta_<key>"]. An orphan block
// (idx out of range) and a malformed line are import errors, reported
// by the caller through the report's invalid count.
func applyOLCRTCMeta(r *ImportResult, idx int, line string) error {
	if idx < 0 || idx >= len(r.Servers) {
		return fmt.Errorf("%w: ## metadata without a preceding olcrtc link", ErrInvalid)
	}
	key, value, found := strings.Cut(strings.TrimPrefix(line, "##"), ":")
	key = strings.ToLower(strings.TrimSpace(key))
	value = strings.TrimSpace(value)
	if !found || key == "" {
		return fmt.Errorf("%w: malformed ## metadata line %q", ErrInvalid, line)
	}
	o := &r.Servers[idx]
	if key == "name" {
		if value != "" {
			o.DisplayName = value
			o.CountryCode = countryCode(value)
		}
		return nil
	}
	if value == "" {
		return nil
	}
	if o.Options == nil {
		o.Options = map[string]string{}
	}
	o.Options["olcrtc_meta_"+key] = value
	return nil
}

// isSubscriptionMetaLine reports whether a list line is a global
// "#key: value" subscription header (sub.md globals, panel profile
// headers). Such lines are metadata for the subscription layer, never
// server candidates, so parseList skips them instead of counting them
// unsupported. Lines that merely start with '#' but carry no key are
// not metadata and keep the old parse attempt.
func isSubscriptionMetaLine(line string) bool {
	if !strings.HasPrefix(line, "#") || strings.HasPrefix(line, "##") {
		return false
	}
	rest := line[1:]
	i := strings.IndexByte(rest, ':')
	if i <= 0 {
		return false
	}
	for _, r := range rest[:i] {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}
