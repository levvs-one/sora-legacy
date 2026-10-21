// Package parser converts links, base64 lists, sing-box/Xray JSON, Clash YAML,
// and WireGuard configs to OutboundSpec. Detection is separate from parsing;
// unsupported or malformed items are reported without failing the entire
// import.
package parser

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
)

const (
	// MaxInputSize is the largest payload the parser is willing to inspect.
	MaxInputSize = 16 << 20
	// DefaultMaxItems caps how many outbounds a single import may produce.
	DefaultMaxItems = 20000
)

// Parser sentinel errors support errors.Is and contain no user data, making
// them safe to log.
var (
	ErrEmptySource   = errors.New("parser: empty source")
	ErrInputTooLarge = errors.New("parser: input exceeds 16 MiB")
	ErrUnsupported   = errors.New("parser: unsupported format")
	ErrInvalid       = errors.New("parser: invalid entry")
)

// Format names a subscription payload shape recognised by ImportDetector.
type Format string

// Detected formats do not guarantee that every contained item is parseable.
const (
	FormatUnknown          Format = "unknown"
	FormatSubscription     Format = "https-subscription"
	FormatHTTPSubscription Format = "http-subscription"
	FormatLink             Format = "share-link"
	FormatBase64           Format = "base64-list"
	FormatSIP008           Format = "sip008"
	FormatClash            Format = "clash-yaml"
	FormatSingBox          Format = "sing-box-json"
	FormatXray             Format = "xray-json"
	FormatWireGuard        Format = "wireguard-conf"
	FormatPlainList        Format = "plain-list"
)

// Detection records the detected Format and a short diagnostic Reason.
type Detection struct {
	Format Format
	Reason string
}

// ImportDetector identifies formats without parsing. MaxItems bounds list
// expansion; zero uses DefaultMaxItems. Concurrent use is safe.
type ImportDetector struct{ MaxItems int }

// Detect identifies src's format. Empty or oversized input returns an empty
// Detection; other errors include the best format guess.
func (d ImportDetector) Detect(src []byte) (Detection, error) {
	det, _, err := detect(src)
	return det, err
}

// detect is Detect plus the decoded payload for FormatBase64 input, so Parse
// does not have to decode twice.
func detect(src []byte) (Detection, []byte, error) {
	if len(bytes.TrimSpace(src)) == 0 {
		return Detection{}, nil, ErrEmptySource
	}
	if len(src) > MaxInputSize {
		return Detection{}, nil, ErrInputTooLarge
	}
	s := strings.TrimSpace(string(src))
	if hasPrefixFold(s, "https://") {
		return Detection{Format: FormatSubscription}, nil, nil
	}
	if hasPrefixFold(s, "http://") {
		return Detection{Format: FormatHTTPSubscription, Reason: "subscriptions require HTTPS"}, nil, nil
	}
	if hasScheme(s) {
		return Detection{Format: FormatLink}, nil, nil
	}
	if strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		var v any
		if json.Unmarshal([]byte(s), &v) == nil {
			return classifyJSON(v), nil, nil
		}
	}
	if strings.Contains(s, "proxies:") {
		return Detection{Format: FormatClash}, nil, nil
	}
	if looksWG(s) {
		return Detection{Format: FormatWireGuard}, nil, nil
	}
	if b, ok := decodeBase64(s); ok && (hasScheme(string(b)) || looksList(string(b))) {
		return Detection{Format: FormatBase64}, b, nil
	}
	if looksList(s) {
		return Detection{Format: FormatPlainList}, nil, nil
	}
	return Detection{Format: FormatUnknown, Reason: "no supported parser matched"}, nil, ErrUnsupported
}

// linkSchemes are the share-link URI schemes recognised by hasScheme.
var linkSchemes = []string{"vless://", "vmess://", "trojan://", "ss://", "socks://", "socks5://", "http://", "https://", "hysteria2://", "hy2://", "tuic://", "wireguard://", "wg://", "olcrtc://"}

// linkProtocols is the set of URI schemes parseLink handles directly (VMess
// and WireGuard links have dedicated parsers).
var linkProtocols = map[string]bool{"vless": true, "trojan": true, "ss": true, "socks": true, "socks5": true, "http": true, "https": true, "hysteria2": true, "hy2": true, "tuic": true}

// linkProtocolNames maps link schemes to engine protocol names when they
// differ.
var linkProtocolNames = map[string]string{"ss": "shadowsocks", "socks": "socks5", "hy2": "hysteria2", "https": "http"}

// linkExtraOptions are link query parameters copied verbatim into Options.
var linkExtraOptions = []string{"mport", "pinSHA256", "pin_sha256", "obfs", "obfs-password", "obfs_password", "congestion_control", "udp_relay_mode", "heartbeat", "upmbps", "downmbps", "hop-interval", "hopinterval", "hop-interval-max", "hopintervalmax", "bbr-profile", "bbr_profile", "ports", "token"}

// hasPrefixFold reports whether s starts with prefix, case-insensitively,
// without copying the input the way strings.ToLower would.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

func hasScheme(s string) bool {
	for _, l := range strings.Fields(s) {
		for _, x := range linkSchemes {
			if hasPrefixFold(l, x) {
				return true
			}
		}
	}
	return false
}
func looksList(s string) bool {
	n := 0
	for _, l := range strings.Split(s, "\n") {
		if hasScheme(l) {
			n++
		}
	}
	return n > 0
}
func looksWG(s string) bool {
	return strings.Contains(s, "[Interface]") && strings.Contains(s, "[Peer]")
}
func classifyJSON(v any) Detection {
	m, ok := v.(map[string]any)
	if !ok {
		if a, ok := v.([]any); ok && len(a) > 0 {
			if _, ok := a[0].(map[string]any); ok {
				return Detection{Format: FormatXray}
			}
		}
		return Detection{}
	}
	if _, ok := m["outbounds"]; ok {
		return Detection{Format: FormatSingBox}
	}
	if _, ok := m["servers"]; ok {
		return Detection{Format: FormatSIP008}
	}
	if _, ok := m["inbounds"]; ok {
		return Detection{Format: FormatXray}
	}
	return Detection{}
}
func decodeBase64(s string) ([]byte, bool) {
	// ':' appears in no base64 alphabet, so any input containing one (plain
	// share links always do) can never decode; skip the cleanup copy and
	// the four decoder attempts entirely.
	if strings.IndexByte(s, ':') >= 0 {
		return nil, false
	}
	clean := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		x := clean
		if n := len(x) % 4; n != 0 {
			x += strings.Repeat("=", 4-n)
		}
		if b, err := e.DecodeString(x); err == nil && utf8.Valid(b) {
			return b, true
		}
	}
	return nil, false
}

// OutboundSpec describes a parsed server independently of engines. Options
// retains additional fields to avoid silently losing unsupported settings
// during import.
type OutboundSpec struct {
	DisplayProtocol                                                                                 string
	ID, DisplayName, Protocol, Transport, Security                                                  string
	Host                                                                                            string
	Port                                                                                            uint16
	UUID, Password, User, Cipher                                                                    string
	PublicKey, ShortID, SpiderX, ServerName, Fingerprint, Flow, Path, HostHeader, ServiceName, Mode string
	ALPN                                                                                            []string
	CountryCode                                                                                     string
	AllowInsecure                                                                                   bool
	// DownloadAddress/DownloadPort carry the XHTTP up/down split from the
	// link's extra= JSON (see applyExtra). They travel
	// through the credential document into engine.Transport, where plan
	// validation and the Xray/mihomo renderers honour them.
	DownloadAddress string
	DownloadPort    uint16
	// Xmux*/XPaddingBytes carry the XHTTP reuse tuning and padding
	// range from the same extra= JSON (the xmux object and the
	// xPaddingBytes string), travelling the same path into
	// engine.Transport. Range values in the link ("16-32") import as
	// their lower bound: the plan models xmux fields as single ints,
	// so the reduction is deliberate and documented here, never a
	// silent parse accident (S5-SP4, ported from sora).
	XmuxMaxConcurrency  int
	XmuxMaxConnections  int
	XmuxMaxReuseTimes   int
	XmuxMaxRequestTimes int
	XPaddingBytes       string
	Options             map[string]string
	Peers               []WireGuardPeer
}

// WireGuardPeer is one WireGuard peer as described by a wg-conf file or a
// wireguard:// link. PersistentKeepalive is measured in seconds.
type WireGuardPeer struct {
	PublicKey, PreSharedKey, Endpoint string
	AllowedIPs, Reserved              []string
	PersistentKeepalive               int
}

// StableKey hashes protocol, endpoint, ID, and user to identify a server across
// imports without exposing IDs.
func (o OutboundSpec) StableKey() string {
	port := strconv.Itoa(int(o.Port))
	// Exclude passwords from identity to avoid storing password hashes.
	material := o.Protocol + "\x00" + o.Host + "\x00" + port + "\x00" + o.UUID + "\x00" + o.User
	// Names distinguish profiles sharing an endpoint. Exclude mutable
	// provider rules so updates preserve saved selections.
	if o.Protocol == "xray-profile" {
		material += "\x00" + o.DisplayName
	}
	// An olcrtc server's identity is provider + transport + room:
	// Host already carries the room, but two providers (or two
	// transports of one provider) can serve the same room id and are
	// different servers. The key, like other passwords, stays out.
	if o.Protocol == "olcrtc" {
		material += "\x00" + o.Options["olcrtc_provider"] + "\x00" + o.Transport
	}
	h := sha256.Sum256([]byte(material))
	var b strings.Builder
	b.Grow(len(o.Protocol) + len(o.Host) + len(port) + 3 + 16)
	b.WriteString(o.Protocol)
	b.WriteByte(':')
	b.WriteString(o.Host)
	b.WriteByte(':')
	b.WriteString(port)
	b.WriteByte(':')
	b.WriteString(hex.EncodeToString(h[:8]))
	return b.String()
}
func (o *OutboundSpec) validate() error {
	if o.Protocol == "" {
		return ErrInvalid
	}
	if o.Protocol == "olcrtc" {
		// olcrtc has no host:port endpoint (see olcrtc.go): Host
		// carries the RoomID and Port must stay 0. Validity is the
		// provider/transport registries plus the strict key shape;
		// the room is required for every provider except none, whose
		// connection data the URI cannot express at all.
		if o.Port != 0 || !olcrtcProviders[o.Options["olcrtc_provider"]] || !olcrtcTransports[o.Transport] {
			return ErrInvalid
		}
		if !isHex64(o.Password) {
			return ErrInvalid
		}
		if o.Options["olcrtc_provider"] != "none" && o.Host == "" {
			return ErrInvalid
		}
		return nil
	}
	// uint16 permits only zero as an invalid port here; larger values are
	// rejected during parsing.
	if o.Host == "" || o.Port < 1 {
		return ErrInvalid
	}
	if o.Protocol == "vless" || o.Protocol == "vmess" || o.Protocol == "tuic" {
		if o.UUID != "" && !uuidRE.MatchString(o.UUID) {
			return fmt.Errorf("%w: invalid UUID", ErrInvalid)
		}
	}
	return nil
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

// ToProto converts a validated canonical specification to the stable fields of
// the control-plane model.
func (o OutboundSpec) ToProto() (*corev1.OutboundSpec, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	return &corev1.OutboundSpec{Id: o.ID, DisplayName: o.DisplayName, Protocol: o.Protocol, DisplayProtocol: o.DisplayProtocol, Transport: o.Transport, Security: o.Security, Endpoint: &corev1.Endpoint{Host: o.Host, Port: uint32(o.Port)}, Credentials: &corev1.CredentialsRef{Reference: o.UUID}}, nil
}

// maxReportItems bounds the per-item reasons a report carries. The counters
// keep counting past the bound, so a 16 MB subscription cannot turn the
// report itself into a memory hog.
const maxReportItems = 100

func appendReason(reasons []ItemReason, reason ItemReason) []ItemReason {
	if len(reasons) >= maxReportItems {
		return reasons
	}
	return append(reasons, reason)
}

// ItemReason identifies a skipped source position and a stable readable reason.
type ItemReason struct {
	Index  int
	Reason string
}

// ImportReport counts all candidate items, including skipped entries, for a
// complete import summary.
type ImportReport struct {
	Imported, SkippedDuplicates, Unsupported, Invalid int
	UnsupportedItems, InvalidItems, DuplicateItems    []ItemReason
}

// ImportResult holds the detected format, validated outbounds, and skipped-item
// report.
type ImportResult struct {
	Format  Format
	Servers []OutboundSpec
	Report  ImportReport
}

// LinkParser parses without mutating src and is safe for concurrent use.
// MaxItems bounds results; zero uses DefaultMaxItems.
type LinkParser struct{ MaxItems int }

func (p LinkParser) limit() int {
	if p.MaxItems <= 0 {
		return DefaultMaxItems
	}
	return p.MaxItems
}

// Parse returns valid outbounds and reports skipped items. Errors indicate an
// unusable whole payload: empty, oversized, or unsupported format.
func (p LinkParser) Parse(src []byte) (ImportResult, error) {
	if len(src) > MaxInputSize {
		return ImportResult{}, ErrInputTooLarge
	}
	d, decoded, e := detect(src)
	if e != nil && d.Format != FormatHTTPSubscription && d.Format != FormatUnknown {
		return ImportResult{Format: d.Format}, e
	}
	if d.Format == FormatHTTPSubscription {
		return ImportResult{Format: d.Format}, ErrUnsupported
	}
	s := strings.TrimSpace(string(src))
	switch d.Format {
	case FormatBase64:
		s = string(decoded)
		d.Format = FormatPlainList
	case FormatSIP008, FormatSingBox, FormatXray:
		return p.parseJSON([]byte(s), d.Format)
	case FormatClash:
		return p.parseYAML([]byte(s))
	case FormatWireGuard:
		return p.parseWG(s)
	}
	return p.parseList(s, d.Format)
}
func (p LinkParser) parseList(s string, f Format) (ImportResult, error) {
	r := ImportResult{Format: f}
	// Pre-size the result and the dedup set from the line count so a large
	// subscription does not pay repeated growth reallocation.
	capItems := strings.Count(s, "\n") + 1
	if capItems > p.limit() {
		capItems = p.limit()
	}
	r.Servers = make([]OutboundSpec, 0, capItems)
	seen := make(map[string]int, capItems)
	// lastOlcrtc is the index in r.Servers that a "##key: value"
	// subscription block binds to: the nearest preceding olcrtc://
	// line (docs/sub.md). It resets when a non-olcrtc server becomes
	// the nearest preceding line and when an olcrtc line is rejected
	// (that line is the nearest preceding one but has no server, so
	// its block is an orphan), and a skipped duplicate still counts
	// as the preceding olcrtc line — its block binds to the entry the
	// duplicate deduplicated into.
	lastOlcrtc := -1
	for i, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "##") {
			if err := applyOLCRTCMeta(&r, lastOlcrtc, l); err != nil {
				r.Report.Invalid++
				r.Report.InvalidItems = appendReason(r.Report.InvalidItems, ItemReason{i, "invalid link fields"})
			}
			continue
		}
		if isSubscriptionMetaLine(l) {
			// Global "#key: value" headers are subscription
			// metadata (read by the subscription layer), not
			// server candidates.
			continue
		}
		if len(r.Servers) >= p.limit() {
			r.Report.Unsupported++
			r.Report.UnsupportedItems = appendReason(r.Report.UnsupportedItems, ItemReason{i, "item limit exceeded"})
			continue
		}
		o, e := parseLink(l)
		if e != nil {
			if isOLCRTCLink(l) {
				// A rejected olcrtc line is still the nearest
				// preceding olcrtc:// line for sub.md binding,
				// but it produced no server: a following ##
				// block must become an orphan (invalid), not
				// silently rebind to an earlier good server.
				lastOlcrtc = -1
			}
			if errors.Is(e, ErrUnsupported) {
				r.Report.Unsupported++
				r.Report.UnsupportedItems = appendReason(r.Report.UnsupportedItems, ItemReason{i, "unsupported protocol or option"})
			} else {
				r.Report.Invalid++
				r.Report.InvalidItems = appendReason(r.Report.InvalidItems, ItemReason{i, "invalid link fields"})
			}
			continue
		}
		k := o.StableKey()
		if idx, ok := seen[k]; ok {
			r.Report.SkippedDuplicates++
			r.Report.DuplicateItems = appendReason(r.Report.DuplicateItems, ItemReason{i, "duplicate server"})
			if o.Protocol == "olcrtc" {
				lastOlcrtc = idx
			}
			continue
		}
		seen[k] = len(r.Servers)
		r.Servers = append(r.Servers, o)
		r.Report.Imported++
		if o.Protocol == "olcrtc" {
			lastOlcrtc = len(r.Servers) - 1
		} else {
			lastOlcrtc = -1
		}
	}
	if len(r.Servers) == 0 && r.Report.Unsupported == 0 && r.Report.Invalid == 0 {
		return r, ErrUnsupported
	}
	return r, nil
}
func parseLink(raw string) (OutboundSpec, error) {
	// olcrtc links are cut by hand in olcrtc.go: their grammar puts a
	// transport name and a <...> payload where net/url expects a host,
	// and the room may be a full URL of its own. url.Parse would
	// mis-split or reject them (a raw MIMO comment may hold spaces).
	if isOLCRTCLink(raw) {
		return parseOLCRTCLink(raw)
	}
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil {
		return OutboundSpec{}, ErrInvalid
	}
	proto := strings.ToLower(u.Scheme)
	if proto == "vmess" {
		return parseVMess(raw, u)
	}
	if proto == "wireguard" || proto == "wg" {
		return parseWireURL(u)
	}
	if !linkProtocols[proto] {
		return OutboundSpec{}, ErrUnsupported
	}
	p, e := parsePort(u.Port())
	if e != nil {
		return OutboundSpec{}, e
	}
	q := u.Query()
	o := OutboundSpec{Protocol: proto, Host: u.Hostname(), Port: p, Transport: "tcp", Security: "none", Options: map[string]string{}}
	if u.User != nil {
		o.User = u.User.Username()
		o.Password, _ = u.User.Password()
	}
	for k, v := range q {
		if len(v) > 0 {
			o.Options[k] = v[0]
		}
	}
	// Fail closed on Hysteria2 certificate pinning: pinSHA256 never
	// reaches any engine (no plan field, no renderer), so importing a
	// pinned link today would silently unpin it. The link is skipped
	// and counted as unsupported instead (sora pass1-detail port).
	if (proto == "hysteria2" || proto == "hy2") && getq(q, "pinSHA256", "pin_sha256") != "" {
		return OutboundSpec{}, fmt.Errorf("%w: hy2 pinSHA256 certificate pinning is not implemented", ErrUnsupported)
	}
	switch proto {
	case "ss":
		o.Cipher = o.User
		if b, ok := decodeBase64(o.User); ok {
			parts := strings.SplitN(string(b), ":", 2)
			if len(parts) == 2 {
				o.Cipher, o.Password = parts[0], parts[1]
			}
		}
		if o.Password == "" {
			o.Password = getq(q, "password")
		}
		// SIP002 plugin: the combined form "plugin=v2ray-plugin;tls;host=x"
		// or the split form "plugin=v2ray-plugin" + "plugin_opts=tls;host=x".
		// Canonical keys keep the raw "plugin" copy (from the loop above)
		// from leaking into the credential document under two names.
		if opts := getq(q, "plugin_opts", "plugin-opts"); opts != "" {
			o.Options["ss_plugin_opts"] = opts
		}
		if plug := getq(q, "plugin"); plug != "" {
			name, rest, _ := strings.Cut(plug, ";")
			o.Options["ss_plugin"] = strings.TrimSpace(name)
			if o.Options["ss_plugin_opts"] == "" && rest != "" {
				o.Options["ss_plugin_opts"] = rest
			}
		}
	case "tuic":
		o.UUID = o.User
		o.Security = "tls"
	case "trojan", "hysteria2", "hy2":
		// Password-only protocols: the credential is the userinfo
		// username (trojan://<password>@host, hysteria2://<password>@host —
		// the canonical share forms). The generic branch parks the
		// username in UUID and leaves Password empty, so every such
		// link imported without its credential and engines rejected
		// the rendered plan ("unset fields: password") or failed
		// authentication. Mirrors sora's parser (integration fix
		// 1b094621, WAVE-INTEGRATION E2E); pinned by
		// TestParsePasswordOnlyCredentials in both repos.
		if o.Password == "" {
			o.Password = o.User
		}
		o.Transport = getq(q, "type", "transport")
		o.Security = getq(q, "security")
	default:
		o.UUID = o.User
		o.Transport = getq(q, "type", "transport")
		o.Security = getq(q, "security")
		if o.Security == "" && proto == "vless" {
			o.Security = "none"
		}
	}
	o.Path = getq(q, "path")
	o.HostHeader = getq(q, "host")
	o.ServiceName = getq(q, "serviceName", "service_name")
	o.Mode = getq(q, "mode")
	o.PublicKey = getq(q, "pbk", "public-key")
	o.ShortID = getq(q, "sid", "short-id")
	o.SpiderX = getq(q, "spx")
	o.ServerName = getq(q, "sni")
	o.Fingerprint = getq(q, "fp")
	o.Flow = getq(q, "flow")
	o.AllowInsecure = parseBool(getq(q, "allowInsecure", "insecure", "skip-cert-verify"))
	if a := getq(q, "alpn"); a != "" {
		o.ALPN = strings.Split(a, ",")
	}
	for _, k := range linkExtraOptions {
		if v := getq(q, k); v != "" {
			o.Options[k] = v
		}
	}
	// The XHTTP split, xmux tuning and padding ride in the
	// extra=<url-encoded JSON> parameter (de-facto link standard).
	// Garbage there is provider decoration, never an import error:
	// it is ignored, not fatal.
	o.applyExtra(getq(q, "extra"))
	if o.Security == "" {
		// Default security follows protocol semantics: trojan,
		// hysteria2, and HTTPS use TLS; others do not. Empty security
		// would incorrectly enable TLS for plain SOCKS downstream.
		switch proto {
		case "trojan", "hysteria2", "hy2", "https":
			o.Security = "tls"
		default:
			o.Security = "none"
		}
	}
	// Normalize link schemes to engine protocol names.
	o.Protocol = linkProtocolNames[proto]
	if o.Protocol == "" {
		o.Protocol = proto
	}
	o.DisplayName = fragmentName(u.Fragment)
	o.CountryCode = countryCode(o.DisplayName)
	return o, o.validate()
}

// extraDownloadSettings is the Xray camelCase shape of the
// downloadSettings object inside a share link's extra=<url-encoded JSON>
// parameter — the de-facto link standard (mihomo's common/convert/v.go).
// Only the recognized fields are read; every other key inside extra
// (session placement, ...) is ignored by the parser.
type extraDownloadSettings struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// extraXmux is the xmux object of the same extra= document. Its
// values are Xray xmux range fields: a JSON number, a numeric
// string, or a "min-max" range string, so each is kept raw and
// reduced by xmuxRangeValue.
type extraXmux struct {
	MaxConcurrency  json.RawMessage `json:"maxConcurrency"`
	MaxConnections  json.RawMessage `json:"maxConnections"`
	MaxReuseTimes   json.RawMessage `json:"cMaxReuseTimes"`
	MaxRequestTimes json.RawMessage `json:"hMaxRequestTimes"`
}

// xmuxRangeValue reduces one xmux range value to the single int the
// plan models: the lower bound of a range, the value itself for a
// scalar. Unusable values reduce to 0 (engine default).
func xmuxRangeValue(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var n float64
	if err := json.Unmarshal(raw, &n); err == nil {
		if n < 0 {
			return 0
		}
		return int(n)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0
	}
	if lo, _, found := strings.Cut(s, "-"); found {
		s = lo
	}
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || v < 0 {
		return 0
	}
	return v
}

// extraParams is the top level of a share link's extra= JSON document.
type extraParams struct {
	DownloadSettings *extraDownloadSettings `json:"downloadSettings"`
	Xmux             *extraXmux             `json:"xmux"`
	XPaddingBytes    string                 `json:"xPaddingBytes"`
}

// applyExtra parses the XHTTP data carried by a link's
// extra=<url-encoded JSON> query parameter into the spec: the
// up/down split, the xmux reuse tuning and the padding range. Each
// section applies independently — a missing, malformed, or unusable
// section is ignored without taking the others down: extra is
// provider decoration, and losing it must never fail the import.
// Surviving values are validated again at plan level
// (engine.validateXHTTP); on non-XHTTP transports the split is a
// hard plan error, not a silent drop.
func (o *OutboundSpec) applyExtra(raw string) {
	if raw == "" {
		return
	}
	var x extraParams
	if err := json.Unmarshal([]byte(raw), &x); err != nil {
		return
	}
	if ds := x.DownloadSettings; ds != nil && ds.Address != "" && ds.Port >= 1 && ds.Port <= 65535 {
		o.DownloadAddress = ds.Address
		o.DownloadPort = uint16(ds.Port)
	}
	if xm := x.Xmux; xm != nil {
		o.XmuxMaxConcurrency = xmuxRangeValue(xm.MaxConcurrency)
		o.XmuxMaxConnections = xmuxRangeValue(xm.MaxConnections)
		o.XmuxMaxReuseTimes = xmuxRangeValue(xm.MaxReuseTimes)
		o.XmuxMaxRequestTimes = xmuxRangeValue(xm.MaxRequestTimes)
	}
	o.XPaddingBytes = x.XPaddingBytes
}
func parseBool(s string) bool { v, _ := strconv.ParseBool(s); return v }
func parsePort(s string) (uint16, error) {
	n, e := strconv.Atoi(s)
	if e != nil || n < 1 || n > 65535 {
		return 0, ErrInvalid
	}
	return uint16(n), nil
}
// getq returns the first non-empty value for the given query keys. The
// query values are parsed once per link by the caller and passed in,
// because re-parsing them per key dominated import CPU profiles.
func getq(q url.Values, ks ...string) string {
	for _, k := range ks {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}
func fragmentName(s string) string {
	v, e := url.QueryUnescape(s)
	if e == nil {
		return v
	}
	return s
}
func countryCode(s string) string {
	r := []rune(s)
	if len(r) >= 2 && r[0] >= 0x1F1E6 && r[0] <= 0x1F1FF && r[1] >= 0x1F1E6 && r[1] <= 0x1F1FF {
		return string(r[:2])
	}
	return ""
}
func parseVMess(raw string, u *url.URL) (OutboundSpec, error) {
	// The classic VMess share link is vmess://<base64 JSON>. url.Parse
	// puts the blob in u.Host (and splits it at any "/" into u.Path), so
	// the payload must be recovered from the raw link text: the former
	// code read u.Opaque/u.Path, which never hold the blob, and the
	// base64 branch was unreachable — every classic VMess link failed
	// validation and was silently dropped from mixed imports (parity
	// with sora; AUDIT-PARITY §3 neighbor #3).
	if blob, frag, ok := vmessBlob(raw); ok {
		if b, isB64 := decodeBase64(blob); isB64 {
			var v map[string]any
			if json.Unmarshal(b, &v) == nil {
				if _, classic := v["add"]; classic {
					return mapVMessJSON(v, frag)
				}
				if _, classic := v["id"]; classic {
					return mapVMessJSON(v, frag)
				}
				return mapJSONSpec(v, "vmess")
			}
		}
	}
	if u.Hostname() == "" {
		return OutboundSpec{}, ErrInvalid
	}
	o := OutboundSpec{Protocol: "vmess", Host: u.Hostname(), Transport: "tcp", Security: "auto", Options: map[string]string{}}
	o.Port, _ = parsePort(u.Port())
	if u.User != nil {
		o.UUID = u.User.Username()
		o.Password, _ = u.User.Password()
	}
	q := u.Query()
	for k, v := range q {
		if len(v) > 0 {
			o.Options[k] = v[0]
		}
	}
	o.Transport = getq(q, "type", "transport")
	if o.Transport == "" {
		o.Transport = "tcp"
	}
	// Every value of every alterId spelling is checked, not just
	// the first non-empty one getq would return (REVIEW-GFOLLOWUP
	// G2-F3): ?aid=0&alter_id=16 — and likewise a repeated key —
	// must refuse, because whichever value the rendering engine
	// honoured, a non-zero one names the pre-AEAD protocol.
	for _, k := range []string{"aid", "alterId", "alter_id"} {
		for _, aid := range q[k] {
			if aid != "" && aid != "0" {
				return OutboundSpec{}, fmt.Errorf("%w: vmess alterId %q is legacy pre-AEAD; sora renders AEAD (alterId 0) only", ErrUnsupported, aid)
			}
		}
	}
	o.Security = getq(q, "security")
	if o.Security == "" {
		o.Security = "auto"
	}
	o.DisplayName = fragmentName(u.Fragment)
	return o, o.validate()
}

// vmessBlob extracts the payload of a classic vmess://<base64> link:
// everything after the scheme, minus an optional query and fragment.
// The fragment is returned separately as a fallback display name. ok is
// false when the link has no payload at all (the URL-style form, which
// parseVMess handles from the parsed URL instead).
func vmessBlob(raw string) (blob, frag string, ok bool) {
	s := strings.TrimSpace(raw)
	i := strings.Index(s, "://")
	if i < 0 {
		return "", "", false
	}
	rest := s[i+3:]
	if j := strings.Index(rest, "#"); j >= 0 {
		frag = fragmentName(rest[j+1:])
		rest = rest[:j]
	}
	if j := strings.Index(rest, "?"); j >= 0 {
		rest = rest[:j]
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", "", false
	}
	return rest, frag, true
}

// mapVMessJSON maps the classic VMess JSON document (the v2rayN field
// set every provider emits) onto an OutboundSpec. "add"/"id" are the
// dialect markers: the generic JSON mapper reads sing-box-style keys
// (server/uuid) and would leave both empty here.
func mapVMessJSON(m map[string]any, frag string) (OutboundSpec, error) {
	o := OutboundSpec{Protocol: "vmess", Transport: "tcp", Security: "none", Options: map[string]string{}}
	o.Host = stringValue(m["add"])
	if o.Host == "" {
		o.Host = stringValue(m["address"])
	}
	o.Port = portNumber(m["port"])
	o.UUID = stringValue(m["id"])
	o.DisplayName = stringValue(m["ps"])
	if o.DisplayName == "" {
		o.DisplayName = frag
	}
	o.Cipher = stringValue(m["scy"])
	if o.Cipher == "" {
		o.Cipher = "auto"
	}
	// Legacy VMess (alterId > 0) is the pre-AEAD protocol: sora renders
	// AEAD only (alterId 0 on every engine), so importing such a link
	// silently would hand the user a server that can never authenticate
	// while looking imported. Refuse it as unsupported, in the open —
	// the same discipline as the hy2 pinSHA256 refusal above. This is
	// the G2 check, now reachable on the classic-link path as well.
	// The camelCase and snake_case spellings are refused here too
	// (REVIEW-G G2 follow-up; see mapJSONSpec for the divergence
	// note) — a classic document carrying them is the same legacy
	// pre-AEAD dialect under a different key name.
	for _, k := range []string{"aid", "alterId", "alter_id"} {
		if err := checkVMessAlterID(m[k]); err != nil {
			return OutboundSpec{}, err
		}
	}
	if net := stringValue(m["net"]); net != "" {
		o.Transport = net
	}
	switch tls := stringValue(m["tls"]); tls {
	case "":
		// Security stays "none".
	case "tls":
		o.Security = "tls"
	default:
		o.Security = tls
	}
	o.ServerName = stringValue(m["sni"])
	o.HostHeader = stringValue(m["host"])
	o.Path = stringValue(m["path"])
	o.Fingerprint = stringValue(m["fp"])
	if a := stringValue(m["alpn"]); a != "" {
		o.ALPN = strings.Split(a, ",")
	}
	o.AllowInsecure = jsonBool(m["insecure"]) || jsonBool(m["allowInsecure"])
	o.CountryCode = countryCode(o.DisplayName)
	return o, o.validate()
}

func parseWireURL(u *url.URL) (OutboundSpec, error) {
	p, e := parsePort(u.Port())
	if e != nil {
		return OutboundSpec{}, e
	}
	o := OutboundSpec{Protocol: "wireguard", Host: u.Hostname(), Port: p, Transport: "udp", DisplayName: fragmentName(u.Fragment), Options: map[string]string{}}
	for k, v := range u.Query() {
		if len(v) > 0 {
			o.Options[k] = v[0]
		}
	}
	if u.User != nil {
		o.Password = u.User.String()
	}
	return o, o.validate()
}
func mapJSONSpec(m map[string]any, fallback string) (OutboundSpec, error) {
	o := OutboundSpec{Protocol: fallback, Transport: "tcp", Options: map[string]string{}}
	if s, ok := m["type"].(string); ok {
		o.Protocol = s
	}
	for _, k := range []string{"server", "address", "host"} {
		if s, ok := m[k].(string); ok && o.Host == "" {
			o.Host = s
		}
	}
	o.Port = portNumber(m["server_port"])
	if o.Port == 0 {
		o.Port = portNumber(m["port"])
	}
	o.UUID = stringValue(m["uuid"])
	o.Password = stringValue(m["password"])
	o.Cipher = stringValue(m["method"])
	o.Transport = stringValue(m["network"])
	if o.Transport == "" {
		o.Transport = stringValue(m["transport"])
	}
	if o.Transport == "" {
		o.Transport = "tcp"
	}
	o.Flow = stringValue(m["flow"])
	o.DisplayName = stringValue(m["tag"])
	if o.DisplayName == "" {
		// SIP008 names its entries "remarks", not "tag".
		o.DisplayName = stringValue(m["remarks"])
	}
	o.Security = stringValue(m["security"])
	if strings.EqualFold(o.Protocol, "vmess") {
		// The type match is case-insensitive (REVIEW-GFOLLOWUP
		// G2-F2): providers also write "VMess"/"VMESS", and a
		// case-sensitive gate let those documents skip the alterId
		// check entirely while checkProfileVMessAlterID already
		// matched EqualFold. sing-box-shaped VMess documents spell
		// it alter_id and Clash documents spell it alterId; every
		// spelling is legacy pre-AEAD when non-zero (see
		// checkVMessAlterID). The alterId check is a deliberate
		// divergence BEYOND sora (REVIEW-G G2 follow-up): the
		// reference still accepts the camelCase key in JSON/Clash
		// documents, legacy refuses it — stricter here on purpose,
		// not a parity break to repair.
		for _, k := range []string{"aid", "alter_id", "alterId"} {
			if err := checkVMessAlterID(m[k]); err != nil {
				return OutboundSpec{}, err
			}
		}
	}
	for k, v := range m {
		if b, err := json.Marshal(v); err == nil {
			o.Options[k] = string(b)
		}
	}
	return o, o.validate()
}

// checkVMessAlterID refuses a VMess alterId that is not AEAD: a
// non-zero integer is the legacy pre-AEAD protocol, and anything that
// is not a non-negative integer at all is refused rather than coerced
// (REVIEW-GFOLLOWUP G2-F1, deliberately stricter than sora exactly as
// the spellings in 6ac5553 were). The loosely typed number() path
// used to coerce silently — a float64 -1 or 0.5 and a bool true all
// read as 0 there and passed, while an Xray profile carried such a
// value into the runtime verbatim. Zero, "0", "" and an absent value
// (nil — JSON null included, it decodes to nil) are AEAD and pass.
// An integer-valued float (64.0, as JSON/YAML emit it) counts as the
// integer it denotes, in number and string form alike.
func checkVMessAlterID(v any) error {
	if v == nil {
		return nil
	}
	n, ok := alterIDInteger(v)
	if !ok || n < 0 {
		return fmt.Errorf("%w: vmess alterId %v is not a non-negative integer", ErrUnsupported, v)
	}
	if n != 0 {
		return fmt.Errorf("%w: vmess alterId %d is legacy pre-AEAD; sora renders AEAD (alterId 0) only", ErrUnsupported, n)
	}
	return nil
}

// alterIDInteger reads v as an integer alterId: JSON/YAML numbers
// (float and int forms), numeric strings, and integer-valued floats
// in either form ("64.0", 64.0). ok is false for booleans, fractional
// values, non-numeric strings and every other type — callers must
// refuse those, not coerce them to zero the way number() does.
func alterIDInteger(v any) (int64, bool) {
	switch x := v.(type) {
	case string:
		if x == "" {
			return 0, true
		}
		if n, err := strconv.ParseInt(x, 10, 64); err == nil {
			return n, true
		}
		f, err := strconv.ParseFloat(x, 64)
		if err != nil || f != math.Trunc(f) {
			return 0, false
		}
		return int64(f), true
	case float64:
		if x != math.Trunc(x) {
			return 0, false
		}
		return int64(x), true
	case float32:
		f := float64(x)
		if f != math.Trunc(f) {
			return 0, false
		}
		return int64(f), true
	case int:
		return int64(x), true
	case int64:
		return x, true
	case uint64:
		if x > math.MaxInt64 {
			return 0, false
		}
		return int64(x), true
	}
	return 0, false
}

// jsonBool reads the loosely typed boolean flags of share-link JSON
// (true, 1, "1", "true" in the wild).
func jsonBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x == "1" || strings.EqualFold(x, "true")
	}
	return false
}

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// portNumber returns zero outside 1..65535 so validation rejects invalid ports
// instead of truncating them.
func portNumber(v any) uint16 {
	n := number(v)
	if n < 1 || n > math.MaxUint16 {
		return 0
	}
	return uint16(n)
}

// number converts JSON number representations to int, returning zero for
// invalid or overflowing values.
func number(v any) int {
	switch n := v.(type) {
	case float64:
		if n < 0 || n > math.MaxInt32 {
			return 0
		}
		return int(n)
	case int:
		return n
	case uint64:
		if n > uint64(math.MaxInt32) {
			return 0
		}
		return int(n)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}
func (p LinkParser) parseJSON(b []byte, f Format) (ImportResult, error) {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return ImportResult{Format: f}, ErrInvalid
	}
	items := []any{}
	switch x := v.(type) {
	case []any:
		items = x
	case map[string]any:
		if a, ok := x["outbounds"].([]any); ok {
			items = a
		} else if a, ok := x["servers"].([]any); ok {
			items = a
		} else if a, ok := x["outbound"].([]any); ok {
			items = a
		} else if f == FormatXray {
			items = xrayItems(x)
		} else {
			items = []any{x}
		}
	}
	r := ImportResult{Format: f}
	// Treat full Xray configurations, including Remnawave lists, as
	// separate provider profiles.
	if m, ok := v.(map[string]any); ok && isXrayConfig(m) {
		items = []any{m}
	}
	// Deduplicate by StableKey exactly as parseList does: without it a
	// subscription listing the same endpoint+UUID under two names yields
	// two specs with the same identity.
	seen := map[string]struct{}{}
	for i, it := range items {
		if len(r.Servers) >= p.limit() {
			r.Report.Unsupported++
			r.Report.UnsupportedItems = appendReason(r.Report.UnsupportedItems, ItemReason{i, "item limit exceeded"})
			continue
		}
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if isXrayConfig(m) {
			o, e := profileSpec(m)
			if e != nil {
				r.Report.Invalid++
				continue
			}
			k := o.StableKey()
			if _, ok := seen[k]; ok {
				r.Report.SkippedDuplicates++
				r.Report.DuplicateItems = appendReason(r.Report.DuplicateItems, ItemReason{i, "duplicate server"})
				continue
			}
			seen[k] = struct{}{}
			r.Servers = append(r.Servers, o)
			r.Report.Imported++
			continue
		}
		// SIP008 entries carry no "type": the format is Shadowsocks
		// by definition, so the protocol comes from the format, not
		// the entry. Without this fallback every real SIP008
		// document imported zero servers (the entry failed
		// validation on its empty protocol).
		fallback := ""
		if f == FormatSIP008 {
			fallback = "shadowsocks"
		}
		o, e := mapJSONSpec(m, fallback)
		if e != nil {
			r.Report.Invalid++
			continue
		}
		if o.Protocol == "" {
			r.Report.Unsupported++
			continue
		}
		// SIP008/sing-box JSON entries carry the SIP002 plugin under its
		// plain names; map them onto the canonical option keys the
		// credential document copies (the generic Options dump
		// JSON-quotes them under their raw names). DisplayName already
		// comes from "remarks" via mapJSONSpec above.
		if s, ok := m["plugin"].(string); ok && s != "" {
			o.Options["ss_plugin"] = s
		}
		if s, ok := m["plugin_opts"].(string); ok && s != "" {
			o.Options["ss_plugin_opts"] = s
		}
		k := o.StableKey()
		if _, ok := seen[k]; ok {
			r.Report.SkippedDuplicates++
			r.Report.DuplicateItems = appendReason(r.Report.DuplicateItems, ItemReason{i, "duplicate server"})
			continue
		}
		seen[k] = struct{}{}
		r.Servers = append(r.Servers, o)
		r.Report.Imported++
	}
	return r, nil
}

// isXrayConfig distinguishes full configurations by Xray-shaped outbounds with
// protocol and settings fields.
func isXrayConfig(m map[string]any) bool {
	outs, ok := m["outbounds"].([]any)
	if !ok || len(outs) == 0 {
		return false
	}
	first, ok := outs[0].(map[string]any)
	if !ok {
		return false
	}
	_, hasProtocol := first["protocol"]
	return hasProtocol
}

// profileSpec stores compacted configuration in Options["profile"]. The default
// outbound supplies endpoint, transport, and security for display and
// measurement.
func profileSpec(m map[string]any) (OutboundSpec, error) {
	// A full Xray profile runs as written (the xray renderProfile
	// preserves provider outbounds), so a VMess outbound inside one
	// never passes through mapJSONSpec: a non-zero alterId nested in
	// its users would import — and run — verbatim. Refuse it here
	// with the same check (REVIEW-G G2 follow-up, third path; sora
	// still accepts it there, legacy is stricter on purpose).
	if err := checkProfileVMessAlterID(m); err != nil {
		return OutboundSpec{}, err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return OutboundSpec{}, ErrInvalid
	}
	o := OutboundSpec{Protocol: "xray-profile", Options: map[string]string{"profile": string(raw)}}
	o.DisplayName = strings.TrimSpace(stringValue(m["remarks"]))
	for _, it := range m["outbounds"].([]any) {
		ob, ok := it.(map[string]any)
		if !ok {
			continue
		}
		switch stringValue(ob["protocol"]) {
		case "freedom", "blackhole", "dns", "loopback", "":
			continue
		}
		o.Host, o.Port = xrayEndpoint(ob)
		o.DisplayProtocol = stringValue(ob["protocol"])
		if ss, ok := ob["streamSettings"].(map[string]any); ok {
			o.Transport = stringValue(ss["network"])
			o.Security = stringValue(ss["security"])
		}
		break
	}
	if o.Transport == "" {
		o.Transport = "tcp"
	}
	if o.Security == "" {
		o.Security = "none"
	}
	if o.DisplayName == "" {
		o.DisplayName = o.Host
	}
	o.CountryCode = countryCode(o.DisplayName)
	return o, o.validate()
}

// checkProfileVMessAlterID scans a full Xray configuration for VMess
// outbounds and refuses any non-zero alterId in their users, in every
// key spelling checkVMessAlterID understands plus the Xray-native
// camelCase one. Users are looked for under settings.vnext/settings.
// servers entries and, defensively, directly under settings.
func checkProfileVMessAlterID(m map[string]any) error {
	outbounds, _ := m["outbounds"].([]any)
	for _, it := range outbounds {
		ob, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if !strings.EqualFold(stringValue(ob["protocol"]), "vmess") {
			continue
		}
		settings, _ := ob["settings"].(map[string]any)
		var userLists [][]any
		if users, ok := settings["users"].([]any); ok {
			userLists = append(userLists, users)
		}
		for _, key := range []string{"vnext", "servers"} {
			entries, _ := settings[key].([]any)
			for _, entry := range entries {
				e, ok := entry.(map[string]any)
				if !ok {
					continue
				}
				if users, ok := e["users"].([]any); ok {
					userLists = append(userLists, users)
				}
			}
		}
		for _, users := range userLists {
			for _, u := range users {
				user, ok := u.(map[string]any)
				if !ok {
					continue
				}
				for _, k := range []string{"alterId", "alter_id", "aid"} {
					if err := checkVMessAlterID(user[k]); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// xrayEndpoint reads settings.vnext, settings.servers, or newer flat
// settings.address endpoints.
func xrayEndpoint(ob map[string]any) (string, uint16) {
	settings, _ := ob["settings"].(map[string]any)
	for _, key := range []string{"vnext", "servers", "peers"} {
		if list, ok := settings[key].([]any); ok && len(list) > 0 {
			if first, ok := list[0].(map[string]any); ok {
				host := stringValue(first["address"])
				if host == "" {
					host = stringValue(first["endpoint"])
				}
				return host, portNumber(first["port"])
			}
		}
	}
	return stringValue(settings["address"]), portNumber(settings["port"])
}

func xrayItems(m map[string]any) []any {
	if a, ok := m["outbounds"].([]any); ok {
		return a
	}
	return []any{m}
}
func (p LinkParser) parseYAML(b []byte) (ImportResult, error) {
	var root struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if yaml.Unmarshal(b, &root) != nil {
		return ImportResult{Format: FormatClash}, ErrInvalid
	}
	r := ImportResult{Format: FormatClash}
	// Deduplicate by StableKey exactly as parseList does (see parseJSON).
	seen := map[string]struct{}{}
	for i, m := range root.Proxies {
		if len(r.Servers) >= p.limit() {
			r.Report.Unsupported++
			r.Report.UnsupportedItems = appendReason(r.Report.UnsupportedItems, ItemReason{i, "item limit exceeded"})
			continue
		}
		o, e := mapJSONSpec(m, "")
		if e != nil {
			r.Report.Invalid++
			continue
		}
		o.DisplayName = stringValue(m["name"])
		k := o.StableKey()
		if _, ok := seen[k]; ok {
			r.Report.SkippedDuplicates++
			r.Report.DuplicateItems = appendReason(r.Report.DuplicateItems, ItemReason{i, "duplicate server"})
			continue
		}
		seen[k] = struct{}{}
		r.Servers = append(r.Servers, o)
		r.Report.Imported++
	}
	return r, nil
}
func (p LinkParser) parseWG(s string) (ImportResult, error) {
	o := OutboundSpec{Protocol: "wireguard", Transport: "udp", Options: map[string]string{}}
	section := ""
	var peer WireGuardPeer
	r := ImportResult{Format: FormatWireGuard}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			if section == "[peer]" {
				if len(o.Peers) >= p.limit() {
					r.Report.Unsupported++
				} else {
					o.Peers = append(o.Peers, peer)
				}
				peer = WireGuardPeer{}
			}
			section = strings.ToLower(line)
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := strings.TrimSpace(kv[1])
		if section == "[interface]" {
			o.Options[k] = v
		}
		if section == "[peer]" {
			switch k {
			case "publickey":
				peer.PublicKey = v
			case "presharedkey":
				peer.PreSharedKey = v
			case "endpoint":
				peer.Endpoint = v
				h, p, e := net.SplitHostPort(v)
				if e == nil {
					o.Host = h
					o.Port, _ = parsePort(p)
				}
			case "allowedips":
				peer.AllowedIPs = strings.Split(v, ",")
			case "persistentkeepalive":
				peer.PersistentKeepalive, _ = strconv.Atoi(v)
			}
		}
	}
	if section == "[peer]" {
		if len(o.Peers) >= p.limit() {
			r.Report.Unsupported++
		} else {
			o.Peers = append(o.Peers, peer)
		}
	}
	if e := o.validate(); e != nil {
		return ImportResult{Format: FormatWireGuard}, e
	}
	r.Servers = []OutboundSpec{o}
	r.Report.Imported = 1
	return r, nil
}
