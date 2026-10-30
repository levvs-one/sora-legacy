package control

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/errs"
	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
	"github.com/levvs-one/sora-client/core/parser"
	"github.com/levvs-one/sora-client/core/routing"
)

// Enforce contract request limits before allocating plan data.
const (
	// MaxPlanBytes is the largest plan the contract accepts.
	MaxPlanBytes = 4 << 20
	// MaxImportBytes is the largest payload ParseImport accepts.
	MaxImportBytes = 16 << 20
	// MaxProbeEndpoints is the largest number of endpoints one probe
	// request
	// may carry.
	MaxProbeEndpoints = 256
)

// resolver resolves plan references to credentials for the engine. Resolved
// material is never returned to the client.
type resolver interface {
	Get(reference string) ([]byte, error)
}

// parseCredential reads the import pipeline's flat credential map. Only the
// JSON document produced by credentialDocument is accepted; anything else
// (a raw proxy URL, truncated or foreign bytes) fails closed instead of
// yielding an empty, partially configured credential (SORA-M8).
func parseCredential(material []byte) (map[string]string, error) {
	if len(bytes.TrimSpace(material)) == 0 {
		return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanOutbounds,
			"control: credential material is empty")
	}
	out := make(map[string]string, 12)
	if err := json.Unmarshal(material, &out); err != nil {
		return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanOutbounds,
			"control: credential material is not a credential document: %v", err)
	}
	// "null", "{}", and documents of only unknown keys all unmarshal
	// cleanly into a map applyCredential would drop field by field: each
	// yields the empty credential SORA-M8 rejects. credentialDocument
	// writes only known keys with non-empty values, so a document without
	// any is foreign or empty and fails closed.
	known := false
	for key, value := range out {
		if _, ok := credentialKeys[key]; ok && value != "" {
			known = true
			break
		}
	}
	if !known {
		return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanOutbounds,
			"control: credential material holds no credential field")
	}
	return out, nil
}

// credentialKeys lists every field credentialDocument may store. Only
// these fields survive applyCredential; anything else is dropped.
var credentialKeys = map[string]struct{}{
	"uuid": {}, "password": {}, "method": {}, "user": {}, "flow": {},
	"public_key": {}, "short_id": {}, "server_name": {}, "fingerprint": {},
	"spider_x": {}, "mode": {}, "path": {}, "host_header": {},
	"service_name": {}, "headers": {}, "alpn": {}, "security": {}, "encryption": {},
	"obfs": {}, "obfs_param": {}, "private_key": {}, "addresses": {},
	"peers": {}, "insecure": {}, "xray_profile": {}, "amneziawg": {},
	"ss_plugin": {}, "ss_plugin_opts": {},
	"olcrtc_provider": {}, "olcrtc_room": {}, "olcrtc_transport": {},
	"olcrtc_channel": {}, "olcrtc_auth_token": {}, "olcrtc_mode": {},
	"olcrtc_params": {}, "olcrtc_meta": {},
	"download_address": {}, "download_port": {},
	"x_padding_bytes": {}, "xmux_max_concurrency": {}, "xmux_max_connections": {},
	"xmux_max_request_times": {}, "xmux_max_reuse_times": {},
}

// credentialDocument serializes only supported credential fields for storage.
func credentialDocument(spec parser.OutboundSpec) ([]byte, error) {
	// sing-box and Clash imports carry REALITY/TLS/transport settings
	// only as raw blobs in Options (S5-SP6): resolve them onto the typed
	// fields first, so the document below stores the same values a
	// share link would have produced. A blob that claims REALITY
	// without its public key, or that does not parse, fails here
	// instead of storing a silently half-configured credential.
	resolved, headers, err := resolveImportedSpec(spec)
	if err != nil {
		return nil, err
	}
	spec = resolved
	// Only non-empty values enter the map: empty entries are deleted
	// before the marshal below anyway, so inserting them changes no
	// stored byte — but every dead insert grows the map's bucket array
	// (~2.3 KB per server once the W1 tuning keys pushed a typical
	// document past the growth threshold). sora's credentialDocument
	// gates the same way: its field writer skips empty values.
	values := make(map[string]string, 16)
	set := func(key, value string) {
		if value != "" {
			values[key] = value
		}
	}
	set("uuid", spec.UUID)
	set("password", spec.Password)
	set("method", spec.Cipher)
	set("user", spec.User)
	set("flow", spec.Flow)
	set("public_key", spec.PublicKey)
	set("short_id", spec.ShortID)
	set("server_name", spec.ServerName)
	set("fingerprint", spec.Fingerprint)
	set("spider_x", spec.SpiderX)
	set("mode", spec.Mode)
	set("path", spec.Path)
	set("host_header", spec.HostHeader)
	set("service_name", spec.ServiceName)
	set("alpn", strings.Join(spec.ALPN, ","))
	set("security", spec.Security)
	set("encryption", spec.Options["encryption"])
	// Copy only known obfuscation options from untrusted links. Normalize
	// the three password aliases to one vault key.
	set("obfs", spec.Options["obfs"])
	for _, key := range []string{"obfs_param", "obfs-password", "obfs_password"} {
		if value := spec.Options[key]; value != "" {
			values["obfs_param"] = value
			break
		}
	}
	// Hysteria2/TUIC tuning (W1, ported from sora): bandwidth caps,
	// port hopping, BBR profile, TUIC congestion/relay/heartbeat and
	// the TUIC v4 token travel inside the credential document like
	// the XHTTP tuning below, so no contract change is needed. Hop
	// ports arrive as mport (official hy2 links) or ports
	// (mihomo-style links); the first spelling present wins.
	firstOpt := func(keys ...string) string {
		for _, key := range keys {
			if value := spec.Options[key]; value != "" {
				return value
			}
		}
		return ""
	}
	set("upmbps", spec.Options["upmbps"])
	set("downmbps", spec.Options["downmbps"])
	set("hop_ports", firstOpt("mport", "ports"))
	set("hop_interval", firstOpt("hop-interval", "hopinterval"))
	set("hop_interval_max", firstOpt("hop-interval-max", "hopintervalmax"))
	set("bbr_profile", firstOpt("bbr-profile", "bbr_profile"))
	set("congestion_control", spec.Options["congestion_control"])
	set("udp_relay_mode", spec.Options["udp_relay_mode"])
	set("heartbeat", spec.Options["heartbeat"])
	set("token", spec.Options["token"])
	// SIP002 plugin/plugin_opts for Shadowsocks. The raw "plugin" query
	// key stays in Options but is never stored under that name; only the
	// parser's canonical ss_plugin keys reach the vault.
	set("ss_plugin", spec.Options["ss_plugin"])
	set("ss_plugin_opts", spec.Options["ss_plugin_opts"])
	// XHTTP up/down split, padding range and xmux reuse tuning from
	// the link's extra= JSON (S5-SP4): they travel inside the
	// credential document, not the proto contract, so no contract
	// change is needed. Zero tuning is the engine default and is not
	// stored.
	set("download_address", spec.DownloadAddress)
	if spec.DownloadPort != 0 {
		values["download_port"] = strconv.Itoa(int(spec.DownloadPort))
	}
	set("x_padding_bytes", spec.XPaddingBytes)
	if spec.XmuxMaxConcurrency != 0 {
		values["xmux_max_concurrency"] = strconv.Itoa(spec.XmuxMaxConcurrency)
	}
	if spec.XmuxMaxConnections != 0 {
		values["xmux_max_connections"] = strconv.Itoa(spec.XmuxMaxConnections)
	}
	if spec.XmuxMaxRequestTimes != 0 {
		values["xmux_max_request_times"] = strconv.Itoa(spec.XmuxMaxRequestTimes)
	}
	if spec.XmuxMaxReuseTimes != 0 {
		values["xmux_max_reuse_times"] = strconv.Itoa(spec.XmuxMaxReuseTimes)
	}
	// Transport headers from a sing-box transport blob or a Clash
	// *-opts blob (S5-SP6) have no flat spec field: they travel as one
	// JSON document, restored by applyCredential like the peers block.
	if len(headers) > 0 {
		raw, err := json.Marshal(headers)
		if err != nil {
			return nil, errs.Wrap(err, errs.CodeInternal, errs.KeySecretStoreUnavailable)
		}
		values["headers"] = string(raw)
	}
	if strings.EqualFold(spec.Protocol, "wireguard") {
		key, addresses, peers := wireguardMaterial(spec)
		set("private_key", key)
		set("addresses", strings.Join(addresses, ","))
		if len(peers) > 0 {
			raw, err := json.Marshal(peers)
			if err != nil {
				return nil, errs.Wrap(err, errs.CodeInternal, errs.KeySecretStoreUnavailable)
			}
			values["peers"] = string(raw)
		}
		if awg := amneziaMaterial(spec.Options); len(awg) > 0 {
			raw, err := json.Marshal(awg)
			if err != nil {
				return nil, errs.Wrap(err, errs.CodeInternal, errs.KeySecretStoreUnavailable)
			}
			values["amneziawg"] = string(raw)
		}
	}
	// OpenLibre (olcrtc): the whole server definition rides the
	// document — provider, room, transport and every transport
	// parameter of the link, plus the ## subscription metadata —
	// because outboundToProto carries only a room-shaped endpoint
	// and the key (as "password"): the proto has no field for the
	// provider or the parameters. Without this block an imported
	// olcrtc server lost everything but the room and the key at the
	// first restart — the same vault gap sora's import review found
	// (IMPORT-REVIEW Z-7) and sora later closed in its credential
	// document; the document keys and shapes here mirror sora's, so
	// a future legacy transport restores from the same fields
	// (olcrtc_params/olcrtc_meta are JSON documents like peers and
	// headers above). Restoring them into an engine outbound is the
	// transport's job: legacy has no olcrtc transport, and plan
	// validation refuses the protocol until one exists.
	if strings.EqualFold(spec.Protocol, "olcrtc") {
		set("olcrtc_provider", spec.Options["olcrtc_provider"])
		room := spec.Options["olcrtc_room"]
		if room == "" {
			room = spec.Host
		}
		set("olcrtc_room", room)
		set("olcrtc_transport", spec.Transport)
		set("olcrtc_channel", spec.Options["olcrtc_channel"])
		set("olcrtc_auth_token", spec.Options["olcrtc_auth_token"])
		set("olcrtc_mode", spec.Options["olcrtc_mode"])
		params := map[string]string{}
		meta := map[string]string{}
		for k, v := range spec.Options {
			switch {
			case k == "olcrtc_provider" || k == "olcrtc_room" || k == "olcrtc_channel" ||
				k == "olcrtc_auth_token" || k == "olcrtc_mode":
				// Carried by their own document fields above.
			case strings.HasPrefix(k, "olcrtc_meta_"):
				meta[strings.TrimPrefix(k, "olcrtc_meta_")] = v
			default:
				params[k] = v
			}
		}
		if len(params) > 0 {
			raw, err := json.Marshal(params)
			if err != nil {
				return nil, errs.Wrap(err, errs.CodeInternal, errs.KeySecretStoreUnavailable)
			}
			values["olcrtc_params"] = string(raw)
		}
		if len(meta) > 0 {
			raw, err := json.Marshal(meta)
			if err != nil {
				return nil, errs.Wrap(err, errs.CodeInternal, errs.KeySecretStoreUnavailable)
			}
			values["olcrtc_meta"] = string(raw)
		}
	}
	if spec.AllowInsecure {
		values["insecure"] = "1"
	}
	if profile := spec.Options["profile"]; profile != "" {
		packed, err := packProfile(profile)
		if err != nil {
			return nil, err
		}
		values["xray_profile"] = packed
	}
	for key, value := range values {
		if value == "" {
			delete(values, key)
		}
	}
	document, err := json.Marshal(values)
	if err != nil {
		return nil, errs.Wrap(err, errs.CodeInternal, errs.KeySecretStoreUnavailable)
	}
	return document, nil
}

// blobFields holds the typed settings extracted from the raw option
// blobs of a sing-box or Clash import (S5-SP6). The parser stores every
// field of those documents JSON-encoded in OutboundSpec.Options and
// fills only the flat fields (server, uuid, network, flow), so REALITY
// keys, the TLS server name and the stream-transport path/host used to
// stop at the credential document: a REALITY server imported from a
// sing-box or Clash subscription reached the plan with no public key
// and ran — silently — without REALITY.
type blobFields struct {
	security    string // "reality" or "tls", derived from the blobs
	publicKey   string
	shortID     string
	serverName  string
	fingerprint string
	insecure    bool
	transport   string
	path        string
	host        string
	serviceName string
	mode        string
	alpn        []string
	headers     map[string]string
	// realityClaimed reports that a blob itself turned REALITY on
	// (a sing-box tls.reality block or a Clash reality-opts block),
	// as opposed to a bare security=reality label. Only a claimed
	// REALITY is required to carry its public key at import time;
	// share links and Xray profiles keep their existing behaviour
	// and are judged by plan validation instead.
	realityClaimed bool
}

// blobError reports a malformed or partial import blob in the style of
// this package: invalid_argument against the plan's outbounds.
func blobError(format string, args ...any) error {
	return errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanOutbounds,
		"control: "+format, args...)
}

// resolveImportedSpec fills the typed fields of spec from its option
// blobs wherever the typed field is still empty, and returns the
// transport headers the spec type cannot hold. Typed fields win over
// blob values for every scalar: the blobs are the fallback for the
// formats whose parser cannot represent them, never an override of a
// share link's explicit values. Two deliberate exceptions, both
// unreachable for real parser output, exist where the blob is the
// primary source: the transport (the parser defaults the flat field
// to "tcp" for a document whose transport object names the real type,
// so the blob always replaces it), and security (a REALITY claim
// outranks any typed label; any other blob label loses to any typed
// security, including "none" — Clash spells the tls:true plus
// reality-opts pair that the first half of that rule governs).
// Insecure is monotonic in the blob's favour in the same limited
// sense: a blob may only turn it on over a typed false, never turn a
// typed true off.
func resolveImportedSpec(spec parser.OutboundSpec) (parser.OutboundSpec, map[string]string, error) {
	f, err := extractBlobFields(spec)
	if err != nil {
		return parser.OutboundSpec{}, nil, err
	}
	out := spec
	if out.PublicKey == "" {
		out.PublicKey = f.publicKey
	}
	if out.ShortID == "" {
		out.ShortID = f.shortID
	}
	if out.ServerName == "" {
		out.ServerName = f.serverName
	}
	if out.Fingerprint == "" {
		out.Fingerprint = f.fingerprint
	}
	if f.insecure {
		out.AllowInsecure = true
	}
	if out.Path == "" {
		out.Path = f.path
	}
	if out.HostHeader == "" {
		out.HostHeader = f.host
	}
	if out.ServiceName == "" {
		out.ServiceName = f.serviceName
	}
	if out.Mode == "" {
		out.Mode = f.mode
	}
	if f.transport != "" {
		// The blob is the same source the parser derived Transport
		// from, in its structured form: a sing-box transport object
		// knows its type where the flat field only saw the parser's
		// "tcp" default.
		out.Transport = f.transport
	}
	switch {
	case f.security == "reality":
		out.Security = "reality"
	case out.Security == "":
		out.Security = f.security
	}
	if len(out.ALPN) == 0 {
		out.ALPN = f.alpn
	}
	if f.realityClaimed && out.PublicKey == "" {
		// Only absence is refused here. A present but malformed key
		// or short-id is deliberately not form-checked at import:
		// plan validation (Outbound.ValidateReality) names the defect
		// when the plan is built, in both repositories — the
		// reference's import performs no form check at all, so
		// refusing malformed forms here would make legacy stricter
		// than the reference on documents both accept at import.
		// TestImportedMalformedRealityFailsAtValidate pins the split.
		return parser.OutboundSpec{}, nil, blobError(
			"an imported %s outbound claims REALITY but carries no public key", orDefault(out.Protocol, "proxy"))
	}
	return out, f.headers, nil
}

// extractBlobFields reads the sing-box and Clash option blobs of a
// parsed spec. Values arrive JSON-encoded (the parser marshals every
// field of those documents into Options); plain scalars, which share
// links store raw, are accepted as-is. A value that looks like a JSON
// object but does not parse, or a field of the wrong shape inside a
// blob this conversion consumes, is an honest error — never a
// silently dropped setting.
func extractBlobFields(spec parser.OutboundSpec) (blobFields, error) {
	var f blobFields
	// sing-box: "tls" is an object; Clash: "tls" is a plain boolean.
	if v, ok, err := optionBlob(spec, "tls"); err != nil {
		return blobFields{}, err
	} else if ok {
		if err := f.applyTLSBlob(v); err != nil {
			return blobFields{}, err
		}
	}
	// Clash spells the TLS name "servername" or "sni"; the flat
	// JSON/YAML fields land in Options under the same names.
	for _, key := range []string{"servername", "sni"} {
		if f.serverName != "" {
			break
		}
		if v, ok, err := optionBlob(spec, key); err != nil {
			return blobFields{}, err
		} else if ok {
			name, err := blobString(v, key)
			if err != nil {
				return blobFields{}, err
			}
			f.serverName = name
		}
	}
	if v, ok, err := optionBlob(spec, "client-fingerprint"); err != nil {
		return blobFields{}, err
	} else if ok && f.fingerprint == "" {
		fp, err := blobString(v, "client-fingerprint")
		if err != nil {
			return blobFields{}, err
		}
		f.fingerprint = fp
	}
	if v, ok, err := optionBlob(spec, "skip-cert-verify"); err != nil {
		return blobFields{}, err
	} else if ok {
		skip, err := blobBool(v, "skip-cert-verify")
		if err != nil {
			return blobFields{}, err
		}
		if skip {
			f.insecure = true
		}
	}
	if v, ok, err := optionBlob(spec, "network"); err != nil {
		return blobFields{}, err
	} else if ok {
		network, err := blobString(v, "network")
		if err != nil {
			return blobFields{}, err
		}
		if network == "http" {
			// Clash "http" is an HTTP/1.1 transport with its own
			// http-opts dialect. No engine here carries it: the plan
			// whitelist (identical in the reference) holds no "http",
			// and the plan's "h2" is a different wire protocol in
			// this dialect, so renaming would silently change the
			// handshake. Refuse at import, where the cause can be
			// named, instead of after a successful import at session
			// build — the reference refuses the same plans there.
			return blobFields{}, blobError(
				"an imported %s outbound uses the http transport, which no engine carries (h2 is a different transport in the Clash dialect)", orDefault(spec.Protocol, "proxy"))
		}
		if network != "" {
			f.transport = network
		}
	}
	if v, ok, err := optionBlob(spec, "alpn"); err != nil {
		return blobFields{}, err
	} else if ok && len(f.alpn) == 0 {
		alpn, err := blobStringList(v, "alpn")
		if err != nil {
			return blobFields{}, err
		}
		f.alpn = alpn
	}
	// Clash REALITY: reality-opts {public-key, short-id}.
	if v, ok, err := optionBlob(spec, "reality-opts"); err != nil {
		return blobFields{}, err
	} else if ok {
		if err := f.applyRealityOpts(v); err != nil {
			return blobFields{}, err
		}
	}
	// sing-box transport object {type, path, host, headers,
	// service_name}; a plain string names the transport directly.
	if v, ok, err := optionBlob(spec, "transport"); err != nil {
		return blobFields{}, err
	} else if ok {
		if err := f.applyTransportBlob(v); err != nil {
			return blobFields{}, err
		}
	}
	// Clash per-transport option blocks.
	if v, ok, err := optionBlob(spec, "ws-opts"); err != nil {
		return blobFields{}, err
	} else if ok {
		if err := f.applyWSOpts(v); err != nil {
			return blobFields{}, err
		}
	}
	if v, ok, err := optionBlob(spec, "grpc-opts"); err != nil {
		return blobFields{}, err
	} else if ok {
		obj, err := blobObject(v, "grpc-opts")
		if err != nil {
			return blobFields{}, err
		}
		for _, key := range []string{"grpc-service-name", "service-name", "service_name"} {
			if raw, present := obj[key]; present {
				name, err := blobString(raw, "grpc-opts."+key)
				if err != nil {
					return blobFields{}, err
				}
				if name != "" && f.serviceName == "" {
					f.serviceName = name
				}
			}
		}
	}
	if v, ok, err := optionBlob(spec, "xhttp-opts"); err != nil {
		return blobFields{}, err
	} else if ok {
		obj, err := blobObject(v, "xhttp-opts")
		if err != nil {
			return blobFields{}, err
		}
		if err := f.applyPathHostMode(obj, "xhttp-opts"); err != nil {
			return blobFields{}, err
		}
	}
	if v, ok, err := optionBlob(spec, "h2-opts"); err != nil {
		return blobFields{}, err
	} else if ok {
		if err := f.applyH2Opts(v); err != nil {
			return blobFields{}, err
		}
	}
	return f, nil
}

// applyTLSBlob reads a "tls" option: a sing-box object, a Clash
// boolean, or a plain security label ("tls"/"reality") as the classic
// VMess JSON spells it.
func (f *blobFields) applyTLSBlob(v any) error {
	switch tlsValue := v.(type) {
	case bool:
		if tlsValue && f.security == "" {
			f.security = "tls"
		}
		return nil
	case string:
		switch strings.ToLower(strings.TrimSpace(tlsValue)) {
		case "", "none":
		case "tls", "reality":
			f.security = strings.ToLower(strings.TrimSpace(tlsValue))
		default:
			f.security = tlsValue
		}
		return nil
	case map[string]any:
		obj := tlsValue
		if raw, present := obj["server_name"]; present {
			name, err := blobString(raw, "tls.server_name")
			if err != nil {
				return err
			}
			f.serverName = name
		}
		if raw, present := obj["alpn"]; present && len(f.alpn) == 0 {
			alpn, err := blobStringList(raw, "tls.alpn")
			if err != nil {
				return err
			}
			f.alpn = alpn
		}
		if raw, present := obj["insecure"]; present {
			insecure, err := blobBool(raw, "tls.insecure")
			if err != nil {
				return err
			}
			if insecure {
				f.insecure = true
			}
		}
		if raw, present := obj["utls"]; present && raw != nil {
			utlsObj, err := blobObject(raw, "tls.utls")
			if err != nil {
				return err
			}
			if fpRaw, present := utlsObj["fingerprint"]; present {
				fp, err := blobString(fpRaw, "tls.utls.fingerprint")
				if err != nil {
					return err
				}
				f.fingerprint = fp
			}
		}
		if raw, present := obj["reality"]; present && raw != nil {
			realityObj, err := blobObject(raw, "tls.reality")
			if err != nil {
				return err
			}
			enabled := true
			if rawEnabled, present := realityObj["enabled"]; present && rawEnabled != nil {
				// A null enabled is an absent value: the block's
				// presence keeps its default (true) instead of
				// blobBool's generic false.
				enabled, err = blobBool(rawEnabled, "tls.reality.enabled")
				if err != nil {
					return err
				}
			}
			if enabled {
				f.realityClaimed = true
				f.security = "reality"
				if rawKey, present := realityObj["public_key"]; present {
					key, err := blobString(rawKey, "tls.reality.public_key")
					if err != nil {
						return err
					}
					f.publicKey = key
				}
				if rawID, present := realityObj["short_id"]; present {
					id, err := blobShortID(rawID, "tls.reality.short_id")
					if err != nil {
						return err
					}
					f.shortID = id
				}
			}
		}
		if f.security == "" {
			if raw, present := obj["enabled"]; present {
				enabled, err := blobBool(raw, "tls.enabled")
				if err != nil {
					return err
				}
				if enabled {
					f.security = "tls"
				}
			}
		}
		return nil
	default:
		return blobError("the tls option of an imported outbound is %T, not an object or a boolean", v)
	}
}

// applyRealityOpts reads a Clash reality-opts block. Its presence
// claims REALITY; resolveImportedSpec refuses the import when no
// public key survives.
func (f *blobFields) applyRealityOpts(v any) error {
	obj, err := blobObject(v, "reality-opts")
	if err != nil {
		return err
	}
	f.realityClaimed = true
	f.security = "reality"
	for _, key := range []string{"public-key", "public_key"} {
		if raw, present := obj[key]; present {
			pbk, err := blobString(raw, "reality-opts."+key)
			if err != nil {
				return err
			}
			if pbk != "" {
				f.publicKey = pbk
			}
		}
	}
	for _, key := range []string{"short-id", "short_id"} {
		if raw, present := obj[key]; present {
			sid, err := blobShortID(raw, "reality-opts."+key)
			if err != nil {
				return err
			}
			if sid != "" {
				f.shortID = sid
			}
		}
	}
	return nil
}

// applyTransportBlob reads a sing-box transport value: an object with
// type/path/host/headers/service_name, or a plain type name.
func (f *blobFields) applyTransportBlob(v any) error {
	if name, ok := v.(string); ok {
		if name != "" {
			f.transport = singBoxTransportName(name)
		}
		return nil
	}
	obj, err := blobObject(v, "transport")
	if err != nil {
		return err
	}
	if raw, present := obj["type"]; present {
		kind, err := blobString(raw, "transport.type")
		if err != nil {
			return err
		}
		if kind != "" {
			f.transport = singBoxTransportName(kind)
		}
	}
	if raw, present := obj["service_name"]; present {
		name, err := blobString(raw, "transport.service_name")
		if err != nil {
			return err
		}
		if name != "" && f.serviceName == "" {
			f.serviceName = name
		}
	}
	if raw, present := obj["headers"]; present {
		headers, err := blobHeaders(raw, "transport.headers")
		if err != nil {
			return err
		}
		f.mergeHeaders(headers)
	}
	return f.applyPathHostMode(obj, "transport")
}

// singBoxTransportName maps a sing-box transport type onto the plan
// vocabulary. sing-box spells its HTTP transport "http"; the plan
// calls the same transport "h2" (the plan whitelist, identical in the
// reference, holds no "http"), and the sing-box renderer spells "h2"
// back to "http" — the mapping is a rename between dialects, not a
// protocol change. The Clash network of the same name is NOT renamed
// (see the network handling in extractBlobFields): there "http" and
// "h2" are different wire protocols.
func singBoxTransportName(kind string) string {
	if kind == "http" {
		return "h2"
	}
	return kind
}

// applyH2Opts reads a Clash h2-opts block {path, host, headers}; the
// host is a list in this dialect, of which blobHost keeps the first
// entry, exactly as for the sing-box http transport's host list.
func (f *blobFields) applyH2Opts(v any) error {
	obj, err := blobObject(v, "h2-opts")
	if err != nil {
		return err
	}
	if raw, present := obj["headers"]; present {
		headers, err := blobHeaders(raw, "h2-opts.headers")
		if err != nil {
			return err
		}
		f.mergeHeaders(headers)
	}
	return f.applyPathHostMode(obj, "h2-opts")
}

// applyWSOpts reads a Clash ws-opts block {path, headers}.
func (f *blobFields) applyWSOpts(v any) error {
	obj, err := blobObject(v, "ws-opts")
	if err != nil {
		return err
	}
	if raw, present := obj["headers"]; present {
		headers, err := blobHeaders(raw, "ws-opts.headers")
		if err != nil {
			return err
		}
		f.mergeHeaders(headers)
	}
	return f.applyPathHostMode(obj, "ws-opts")
}

// applyPathHostMode fills path, host and mode from a transport-shaped
// object, wherever the fields are still empty. The Host header of a
// headers block, merged before this runs, is the host when the object
// carries no host field of its own.
func (f *blobFields) applyPathHostMode(obj map[string]any, what string) error {
	if raw, present := obj["path"]; present {
		path, err := blobString(raw, what+".path")
		if err != nil {
			return err
		}
		if path != "" && f.path == "" {
			f.path = path
		}
	}
	if raw, present := obj["host"]; present {
		host, err := blobHost(raw, what+".host")
		if err != nil {
			return err
		}
		if host != "" && f.host == "" {
			f.host = host
		}
	}
	if raw, present := obj["mode"]; present {
		mode, err := blobString(raw, what+".mode")
		if err != nil {
			return err
		}
		if mode != "" && f.mode == "" {
			f.mode = mode
		}
	}
	if f.host == "" {
		for key, value := range f.headers {
			if strings.EqualFold(key, "host") && value != "" {
				f.host = value
				break
			}
		}
	}
	return nil
}

// mergeHeaders adds headers that are not already present, keeping the
// extraction order (sing-box transport before Clash *-opts) stable.
func (f *blobFields) mergeHeaders(headers map[string]string) {
	if len(headers) == 0 {
		return
	}
	if f.headers == nil {
		f.headers = make(map[string]string, len(headers))
	}
	for key, value := range headers {
		if _, ok := f.headers[key]; !ok {
			f.headers[key] = value
		}
	}
}

// optionBlob decodes one Options value. JSON/YAML imports store every
// field JSON-encoded; share links store plain scalars, which pass
// through unchanged. A value that opens like a JSON object, array or
// string but does not parse is a broken blob and fails closed.
func optionBlob(spec parser.OutboundSpec, key string) (any, bool, error) {
	raw := strings.TrimSpace(spec.Options[key])
	if raw == "" {
		return nil, false, nil
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err == nil {
		// A JSON null is an absent value in both dialects — an empty
		// "tls:" line in a Clash document, "tls": null in sing-box
		// JSON: the option is simply not there, never a shape error
		// that would fail the whole subscription.
		if v == nil {
			return nil, false, nil
		}
		return v, true, nil
	}
	if strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "[") || strings.HasPrefix(raw, "\"") {
		return nil, false, blobError("the %s option of an imported outbound is not readable JSON", key)
	}
	return raw, true, nil
}

// blobObject requires v to be a JSON object.
func blobObject(v any, what string) (map[string]any, error) {
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, blobError("the %s option of an imported outbound is %T, not an object", what, v)
	}
	return obj, nil
}

// blobString requires v to be a string (or absent/null, read as empty).
func blobString(v any, what string) (string, error) {
	switch value := v.(type) {
	case nil:
		return "", nil
	case string:
		return value, nil
	default:
		return "", blobError("the %s option of an imported outbound is %T, not a string", what, v)
	}
}

// blobShortID reads a REALITY short-id. A string passes through; an
// integral JSON number converts to its decimal form: YAML decoders
// turn an unquoted all-digit short-id (12345678) into a number, and
// mihomo — whose field is a string — reads the same document back as
// exactly those digits, so converting is the dialect's own reading,
// not a guess. A fractional or negative number is a short-id in no
// dialect and fails closed like any other wrong shape. A number at
// or above 2^53 fails closed the same way: optionBlob decodes every
// JSON number to float64, which cannot represent every integer in
// [2^53, 10^16) exactly — 9007199254740993 silently became
// 9007199254740992, a different 16-digit short-id that plan
// validation (a hex and length check) would have accepted. Below
// 2^53 every integer is exact, so the conversion there is faithful;
// at or above it the raw digits cannot be trusted to survive the
// decode, so the import refuses them instead of storing a rounded
// short-id. (Decoding optionBlob with json.Number would preserve
// the digits, but it would change the type of every number in
// every blob — blobBool's 0/1 and blobString's strictness and
// diagnostics for a numeric public key included — for short-ids
// no provider writes that large; the bound closes the window with
// no change to the other consumers.) The public key deliberately
// gets no such treatment (it stays blobString): a valid key is
// never numeric, so a number there is a broken blob.
func blobShortID(v any, what string) (string, error) {
	if n, ok := v.(float64); ok {
		if n < 0 || n >= 9007199254740992 || n != math.Trunc(n) {
			return "", blobError("the %s option of an imported outbound is %v, not a short-id", what, n)
		}
		return strconv.FormatFloat(n, 'f', 0, 64), nil
	}
	return blobString(v, what)
}

// blobBool reads a loosely typed boolean: a JSON boolean, a "true"/
// "false" string, or 0/1. A JSON null is an absent value (the F1
// null semantics), read as false; a caller whose field defaults to
// true when present (tls.reality.enabled) guards the null itself so
// the default survives.
func blobBool(v any, what string) (bool, error) {
	switch value := v.(type) {
	case nil:
		return false, nil
	case bool:
		return value, nil
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(value))
		if err != nil {
			return false, blobError("the %s option of an imported outbound is %q, not a boolean", what, value)
		}
		return parsed, nil
	case float64:
		if value == 0 {
			return false, nil
		}
		if value == 1 {
			return true, nil
		}
	}
	return false, blobError("the %s option of an imported outbound is %T, not a boolean", what, v)
}

// blobStringList reads a string or a list of strings (an ALPN list in
// either spelling). A JSON null is an absent value, read as no list.
func blobStringList(v any, what string) ([]string, error) {
	switch value := v.(type) {
	case nil:
		return nil, nil
	case string:
		if strings.TrimSpace(value) == "" {
			return nil, nil
		}
		parts := strings.Split(value, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
		return out, nil
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			s, err := blobString(item, what)
			if err != nil {
				return nil, err
			}
			if s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	default:
		return nil, blobError("the %s option of an imported outbound is %T, not a string or a list", what, v)
	}
}

// blobHost reads a transport host: one name, or the first entry of a
// host list (the http transport's spelling).
func blobHost(v any, what string) (string, error) {
	if list, ok := v.([]any); ok {
		if len(list) == 0 {
			return "", nil
		}
		return blobString(list[0], what)
	}
	return blobString(v, what)
}

// blobHeaders reads a headers object into a flat string map. Header
// values are strings in both dialects; anything else is a shape the
// engines would misapply, so it fails closed like the other blobs.
// A JSON null is an absent value, read as no headers — and the F1
// null semantics apply per entry as well (REVIEW-SP6B-MICRO): a
// header whose value is null is absent, never stored, so
// {"X-Custom": null} does not become a header with an empty value
// on its way to the engine.
func blobHeaders(v any, what string) (map[string]string, error) {
	if v == nil {
		return nil, nil
	}
	obj, err := blobObject(v, what)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(obj))
	for key, raw := range obj {
		if raw == nil {
			continue
		}
		value, err := blobString(raw, what+"."+key)
		if err != nil {
			return nil, err
		}
		out[key] = value
	}
	return out, nil
}

func kinds(names []string) []engine.Kind {
	out := make([]engine.Kind, 0, len(names))
	for _, n := range names {
		out = append(out, engine.Kind(n))
	}
	return out
}

// planFromProto validates the request's outbounds and limits, then resolves
// credential references into the engine plan. Credentials remain inside the
// core.
func planFromProto(in *corev1.SessionPlan, sessionID string, secrets resolver) (*engine.Plan, error) {
	if in == nil {
		return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanEmpty, "control: the request carries no plan")
	}
	if len(in.GetOutbounds()) == 0 {
		return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanEmpty, "control: the plan has no outbounds")
	}
	if len(in.GetOutbounds()) > engine.MaxOutbounds {
		return nil, errs.Newf(errs.CodeResourceExhausted, errs.KeyPlanTooLarge,
			"control: the plan carries %d outbounds, the limit is %d", len(in.GetOutbounds()), engine.MaxOutbounds)
	}
	if len(in.GetRoutes()) > engine.MaxRules {
		return nil, errs.Newf(errs.CodeResourceExhausted, errs.KeyPlanTooLarge,
			"control: the plan carries %d rules, the limit is %d", len(in.GetRoutes()), engine.MaxRules)
	}

	defences := in.GetAntiCensorship()
	plan := &engine.Plan{
		SessionID: sessionID,
		Engines:   kinds(in.GetEngines()),
		// Outbounds and rules are known up front: size for the request so
		// large plans do not regrow the slices one power of two at a time.
		Outbounds: make([]engine.Outbound, 0, len(in.GetOutbounds())),
		Rules:     make([]engine.Rule, 0, len(in.GetRoutes())),
		// Keep engines at debug level so capture-level changes apply
		// immediately without restarting connections.
		Options: engine.Options{Mode: "rule", LogLevel: "debug", TestURL: engine.TestURLProduction, IPv6: in.GetIpv6(), Fragment: engine.Fragment{
			Enabled:  defences.GetTlsFragment(),
			Packets:  defences.GetFragmentPackets(),
			Length:   defences.GetFragmentLength(),
			Interval: defences.GetFragmentInterval(),
		}},
		// A TUN adapter needs routes to carry traffic.
		Tun: engine.Tun{
			Enabled:    in.GetTunnelMode() == corev1.TunnelMode_TUNNEL_MODE_SYSTEM,
			Stack:      in.GetTunStack(),
			AutoRoute:  true,
			DeviceName: engine.TunDevice,
			// Windows races DNS across adapters; strict routing
			// blocks other adapters' DNS to prevent leaks.
			StrictRoute: runtime.GOOS == "windows",
		},
		PrivateControl: !in.GetNetworkControlAllowed(),
	}
	if plan.Tun.Stack != "" && !plan.Tun.Enabled {
		return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanTunnel, "control: selecting a stack requires TUN mode")
	}
	// System proxy mode requires the configured listener and cannot use
	// proxy authentication.
	local := in.GetLocalProxy()
	plan.LocalProxy = engine.LocalProxy{
		Enabled:  local.GetEnabled() || !plan.Tun.Enabled,
		Username: local.GetUsername(),
		Password: local.GetPassword(),
	}
	if !plan.Tun.Enabled && local.GetUsername() != "" {
		return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanLocalProxy,
			"control: the system proxy cannot carry a login for the local proxy")
	}
	if (local.GetUsername() == "") != (local.GetPassword() == "") {
		return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanLocalProxy,
			"control: the local proxy login needs both a username and a password")
	}
	seen := make(map[string]struct{}, len(in.GetOutbounds()))
	for index, spec := range in.GetOutbounds() {
		outbound, err := outboundFromProto(index, spec, secrets)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[outbound.ID]; duplicate {
			return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanDuplicateID,
				"control: two outbounds share the id %q", outbound.ID)
		}
		seen[outbound.ID] = struct{}{}
		plan.Outbounds = append(plan.Outbounds, outbound)
	}
	if mode := in.GetTunnelMode(); mode == corev1.TunnelMode_TUNNEL_MODE_UNSPECIFIED {
		return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanTunnel,
			"control: the plan does not say which tunnel it wants")
	}
	groups, err := groupsFromProto(in.GetGroups(), seen)
	if err != nil {
		return nil, err
	}
	plan.Groups = groups
	for _, g := range groups {
		seen[g.Name] = struct{}{}
	}
	// Derive rule types from destinations so the contract's
	// destination/target pairs have consistent semantics across engines.
	for _, route := range in.GetRoutes() {
		rule, err := ruleFromProto(route)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[rule.Target]; !ok && !engine.IsBuiltInTarget(rule.Target) {
			return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanUnknownTarget,
				"control: rule %q points at %q, which is not in this plan", rule.Value, rule.Target)
		}
		plan.Rules = append(plan.Rules, rule)
	}
	routingOpts := in.GetRouting()
	if target := routingOpts.GetProxyTarget(); target != "" {
		if _, ok := seen[target]; !ok {
			return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanUnknownTarget,
				"control: the routing target %q is not an outbound or a group of this plan", target)
		}
	}
	plan.Rules, err = routing.Apply(plan.Rules, routing.Options{
		Preset: routingOpts.GetPreset(), ProxyTarget: routingOpts.GetProxyTarget(), BlockAds: routingOpts.GetBlockAds(),
	})
	if err != nil {
		return nil, errs.Wrap(err, errs.CodeInvalidArgument, errs.KeyPlanRuleInvalid)
	}
	plan.DNS = dnsFromProto(in.GetDnsPolicy(), plan.Tun.Enabled)
	if err := checkDNS(plan.DNS); err != nil {
		return nil, err
	}
	for _, entry := range in.GetBypassSettings().GetRules() {
		if err := checkBypass(entry); err != nil {
			return nil, err
		}
	}
	if err := plan.Validate(); err != nil {
		return nil, errs.Wrap(err, errs.CodeInvalidArgument, errs.KeyPlanGroupsInvalid)
	}
	return plan, nil
}

// groupTypes maps the contract's group types onto the plan's.
var groupTypes = map[corev1.GroupType]engine.GroupType{
	corev1.GroupType_GROUP_TYPE_SELECT:       engine.GroupSelect,
	corev1.GroupType_GROUP_TYPE_URL_TEST:     engine.GroupURLTest,
	corev1.GroupType_GROUP_TYPE_FALLBACK:     engine.GroupFallback,
	corev1.GroupType_GROUP_TYPE_LOAD_BALANCE: engine.GroupLoadBalance,
}

// groupsFromProto converts groups after collecting all names, allowing forward
// references. Plan validation rejects cycles.
func groupsFromProto(in []*corev1.GroupSpec, outbounds map[string]struct{}) ([]engine.Group, error) {
	if len(in) > engine.MaxGroups {
		return nil, errs.Newf(errs.CodeResourceExhausted, errs.KeyPlanTooLarge,
			"control: the plan carries %d groups, the limit is %d", len(in), engine.MaxGroups)
	}
	names := make(map[string]struct{}, len(in))
	out := make([]engine.Group, 0, len(in))
	for _, spec := range in {
		name := strings.TrimSpace(spec.GetName())
		kind, ok := groupTypes[spec.GetType()]
		switch {
		case name == "":
			return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanGroupsInvalid, "control: a group has no name")
		case !ok:
			return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanGroupsInvalid, "control: group %q has no type", name)
		}
		if _, clash := outbounds[name]; clash {
			return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanGroupsInvalid, "control: group %q has the id of an outbound", name)
		}
		if _, dup := names[name]; dup {
			return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanGroupsInvalid, "control: two groups are named %q", name)
		}
		names[name] = struct{}{}
		group := engine.Group{Name: name, Type: kind, Outbounds: spec.GetMembers(), URL: spec.GetTestUrl(), Tolerance: int(min(spec.GetToleranceMs(), 60000))}
		if d := spec.GetTestInterval(); d != nil {
			group.Interval = int(min(max(d.AsDuration(), time.Minute), 24*time.Hour) / time.Second)
		}
		out = append(out, group)
	}
	for _, g := range out {
		for _, member := range g.Outbounds {
			_, isOutbound := outbounds[member]
			_, isGroup := names[member]
			if !isOutbound && !isGroup && !engine.IsBuiltInTarget(member) {
				return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanGroupsInvalid,
					"control: group %q names %q, which is not in this plan", g.Name, member)
			}
		}
	}
	return out, nil
}

// checkDNS validates resolvers and returns a problem-specific error key.
func checkDNS(dns engine.DNS) error {
	for _, server := range dns.Servers {
		if server.Address == "" {
			return errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanDNSInvalid,
				"control: a resolver has no address")
		}
	}
	return nil
}

// checkBypass rejects entries that are empty or contain whitespace. It does
// not validate the domain, address, or network shape; matching happens
// downstream when the rules are applied.
func checkBypass(entry string) error {
	trimmed := strings.TrimSpace(entry)
	if trimmed == "" {
		return errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanBypassInvalid,
			"control: a bypass entry is empty")
	}
	if strings.ContainsAny(trimmed, " \t\r\n") {
		return errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanBypassInvalid,
			"control: a bypass entry holds whitespace")
	}
	return nil
}

// outboundFromProto converts one outbound and resolves its credential
// reference.
func outboundFromProto(index int, spec *corev1.OutboundSpec, secrets resolver) (engine.Outbound, error) {
	id := strings.TrimSpace(spec.GetId())
	if id == "" {
		return engine.Outbound{}, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanOutbounds,
			"control: outbound %d has no id", index)
	}
	port := spec.GetEndpoint().GetPort()
	if port > 0xffff {
		return engine.Outbound{}, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanOutbounds,
			"control: outbound %q has port %d, which is not a port", id, port)
	}
	outbound := engine.Outbound{
		ID:       id,
		Name:     spec.GetDisplayName(),
		Protocol: engine.Protocol(spec.GetProtocol()),
		Server:   spec.GetEndpoint().GetHost(),
		Port:     uint16(port),
		Transport: engine.Transport{
			Type: orDefault(spec.GetTransport(), "tcp"),
		},
		TLS: engine.TLS{Enabled: !strings.EqualFold(spec.GetSecurity(), "none")},
	}
	if outbound.Protocol == engine.ProtocolWireGuard {
		// WireGuard has no stream transport: the parser labels its
		// specs "udp" (a datagram protocol, not an engine transport),
		// and custom specs arrive with no transport at all, which the
		// default above turns into "tcp". Both spellings failed plan
		// validation ("unknown transport") or misdescribed the
		// outbound, so a WireGuard server imported from a link or a
		// .conf could never build a plan. The engine's WireGuard
		// outbound carries no transport type. (Ported from sora,
		// B1 servers audit — sora's parser spells "udp" identically
		// and its plan vocabulary is the same set, so the fix lives
		// in this converter, not in the parser or the whitelist.)
		//
		// Only those producer spellings ("", "tcp", "udp") are
		// normalized. Any other value is not a WireGuard transport
		// at all: erasing it unconditionally would let wireguard/
		// "bogus" — and wireguard/"ws" or "grpc", which the plan
		// whitelist accepts for other protocols — silently become
		// valid plans, hence the honest rejection here, in the
		// converter that knows the protocol (B1 review in sora).
		switch outbound.Transport.Type {
		case "", "tcp", "udp":
			outbound.Transport.Type = ""
		default:
			return engine.Outbound{}, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanOutbounds,
				"control: outbound %q: wireguard has no stream transport, got %q", id, outbound.Transport.Type)
		}
	}
	if outbound.Name == "" {
		outbound.Name = id
	}
	if b := spec.GetBypass(); b != nil {
		outbound.Bypass = &engine.BypassStrategy{
			SplitPos: b.GetSplitPos(), Disorder: b.GetDisorder(), OOB: b.GetOob(), TLSRecord: b.GetTlsRecord(),
			HostCase: b.GetHostCase(), DomainCase: b.GetDomainCase(), MethodEOL: b.GetMethodEol(),
		}
	}
	if reference := spec.GetCredentials().GetReference(); reference != "" {
		if secrets == nil {
			return engine.Outbound{}, errs.Newf(errs.CodeFailedPrecondition, errs.KeySecretStoreUnavailable,
				"control: outbound %q needs a secret but the core has no store", id)
		}
		material, err := secrets.Get(reference)
		if err != nil {
			return engine.Outbound{}, errs.Wrap(err, errs.CodeNotFound, errs.KeySecretNotFound)
		}
		values, err := parseCredential(material)
		if err != nil {
			return engine.Outbound{}, err
		}
		if err := applyCredential(&outbound, values); err != nil {
			return engine.Outbound{}, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanOutbounds,
				"control: outbound %q: %v", id, err)
		}
	}
	return outbound, nil
}

// atoiNonNegative parses a non-negative integer from a credential
// document value; anything else (missing, malformed, negative) is 0,
// the engine default for the tuning fields it restores.
func atoiNonNegative(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// applyCredential restores only fields written by credentialDocument from
// stored material.
func applyCredential(outbound *engine.Outbound, values map[string]string) error {
	outbound.UUID = values["uuid"]
	outbound.Password = values["password"]
	outbound.Cipher = values["method"]
	outbound.UserID = values["user"]
	outbound.Flow = values["flow"]
	// Obfuscation settings, boxed only when the document carries
	// any (or a box already exists), like the QUIC group below.
	obfs := engine.ObfsSettings{
		Type:       values["obfs"],
		Param:      values["obfs_param"],
		Plugin:     values["ss_plugin"],
		PluginOpts: values["ss_plugin_opts"],
	}
	if outbound.Obfs != nil || obfs != (engine.ObfsSettings{}) {
		*outbound.ObfsBox() = obfs
	}
	// Hysteria2/TUIC tuning restored from the credential document;
	// atoiNonNegative keeps a forged document from smuggling negative
	// tuning into the plan (hard validation is Outbound.Validate).
	// The QUIC box is allocated only when the document actually
	// carries tuning (or one is already boxed): a TCP outbound's
	// credential must not pay for a group it never fills.
	quic := engine.QUICSettings{
		UpMbps:            atoiNonNegative(values["upmbps"]),
		DownMbps:          atoiNonNegative(values["downmbps"]),
		HopPorts:          values["hop_ports"],
		HopInterval:       atoiNonNegative(values["hop_interval"]),
		HopIntervalMax:    atoiNonNegative(values["hop_interval_max"]),
		BBRProfile:        values["bbr_profile"],
		CongestionControl: values["congestion_control"],
		UDPRelayMode:      values["udp_relay_mode"],
		TUICHeartbeat:     atoiNonNegative(values["heartbeat"]),
		Token:             values["token"],
	}
	if outbound.QUIC != nil || quic != (engine.QUICSettings{}) {
		*outbound.QUICBox() = quic
	}
	outbound.PublicKey = values["public_key"]
	outbound.ShortID = values["short_id"]
	outbound.Encryption = values["encryption"]
	outbound.TLS.ServerName = values["server_name"]
	outbound.TLS.Fingerprint = values["fingerprint"]
	if insecure, ok := values["insecure"]; ok {
		outbound.TLS.Insecure = insecure == "1" || strings.EqualFold(insecure, "true")
	}
	if alpn := values["alpn"]; alpn != "" {
		outbound.TLS.ALPN = strings.Split(alpn, ",")
	}
	// REALITY requires its public key and short ID in the engine's TLS
	// block.
	if strings.EqualFold(values["security"], "reality") {
		outbound.TLS.Enabled = true
		outbound.TLS.Reality = &engine.RealitySettings{
			PublicKey: values["public_key"],
			ShortID:   values["short_id"],
			SpiderX:   values["spider_x"],
		}
	}
	outbound.Transport.Path = values["path"]
	outbound.Transport.Host = values["host_header"]
	outbound.Transport.Service = values["service_name"]
	// The XHTTP box is allocated only when the document carries
	// XHTTP data (or one is already boxed), for the same reason as
	// the QUIC box above.
	xhttp := engine.XHTTPSettings{Mode: values["mode"]}
	// XHTTP up/down split from the link's extra= JSON (S5-SP4): the
	// address rides the credential document; the port is bounded again
	// here so a forged document cannot smuggle an invalid one.
	xhttp.DownloadAddress = values["download_address"]
	if port := atoiNonNegative(values["download_port"]); port >= 0 && port <= 65535 {
		xhttp.DownloadPort = uint16(port)
	}
	// XHTTP padding and xmux tuning from the same extra= data;
	// atoiNonNegative keeps a forged document from smuggling negative
	// tuning into the plan.
	xhttp.XPaddingBytes = values["x_padding_bytes"]
	xhttp.XmuxMaxConcurrency = atoiNonNegative(values["xmux_max_concurrency"])
	xhttp.XmuxMaxConnections = atoiNonNegative(values["xmux_max_connections"])
	xhttp.XmuxMaxRequestTimes = atoiNonNegative(values["xmux_max_request_times"])
	xhttp.XmuxMaxReuseTimes = atoiNonNegative(values["xmux_max_reuse_times"])
	if outbound.Transport.XHTTP != nil || xhttp != (engine.XHTTPSettings{}) {
		*outbound.Transport.XHTTPBox() = xhttp
	}
	if raw := values["headers"]; raw != "" {
		// A broken headers document fails closed like the peers
		// document below: silently dropping headers would change
		// the handshake the server expects.
		if err := json.Unmarshal([]byte(raw), &outbound.Transport.Headers); err != nil {
			return fmt.Errorf("control: a stored transport headers document is unreadable: %w", err)
		}
	}
	// WireGuard material, boxed only when the document carries any
	// (or a box already exists), like the QUIC/XHTTP groups above.
	if outbound.WireGuard != nil || values["private_key"] != "" || values["addresses"] != "" || values["peers"] != "" {
		outbound.WireGuardBox().PrivateKey = values["private_key"]
		if addresses := values["addresses"]; addresses != "" {
			outbound.WireGuardBox().Addresses = strings.Split(addresses, ",")
		}
		if peers := values["peers"]; peers != "" {
			// A broken peers document fails closed like xray_profile and
			// amneziawg above: silently dropping peers would leave the
			// WireGuard outbound without its endpoints.
			if err := json.Unmarshal([]byte(peers), &outbound.WireGuardBox().Peers); err != nil {
				return fmt.Errorf("control: a stored peers document is unreadable: %w", err)
			}
		}
	}
	if packed := values["xray_profile"]; packed != "" {
		profile, err := unpackProfile(packed)
		if err != nil {
			return err
		}
		outbound.Profile = &profile
	}
	if raw := values["amneziawg"]; raw != "" {
		awg, err := amneziaFrom(raw)
		if err != nil {
			return err
		}
		outbound.Amnezia = awg
	}
	return nil
}

// amneziaKeys lists supported AmneziaWG parameters using the parser's lowercase
// interface keys.
var amneziaKeys = []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
	"i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3", "itime"}

// amneziaMaterial copies only known AmneziaWG keys from an untrusted import.
func amneziaMaterial(options map[string]string) map[string]string {
	out := map[string]string{}
	for _, key := range amneziaKeys {
		if v := strings.TrimSpace(options[key]); v != "" {
			out[key] = v
		}
	}
	return out
}

// amneziaFrom restores AmneziaWG parameters and rejects invalid numeric values.
func amneziaFrom(raw string) (*engine.AmneziaWG, error) {
	var v map[string]string
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil, err
	}
	number := func(key string) (int, error) {
		if v[key] == "" {
			return 0, nil
		}
		n, err := strconv.Atoi(v[key])
		if err != nil {
			return 0, fmt.Errorf("amneziawg %s: %q is not a number", key, v[key])
		}
		return n, nil
	}
	a := &engine.AmneziaWG{H1: v["h1"], H2: v["h2"], H3: v["h3"], H4: v["h4"],
		I1: v["i1"], I2: v["i2"], I3: v["i3"], I4: v["i4"], I5: v["i5"], J1: v["j1"], J2: v["j2"], J3: v["j3"]}
	for key, field := range map[string]*int{"jc": &a.Jc, "jmin": &a.Jmin, "jmax": &a.Jmax,
		"s1": &a.S1, "s2": &a.S2, "s3": &a.S3, "s4": &a.S4, "itime": &a.Itime} {
		n, err := number(key)
		if err != nil {
			return nil, err
		}
		*field = n
	}
	return a, nil
}

// wireguardMaterial collects keys, addresses, and peers from .conf sections or
// wireguard:// user info and query fields.
func wireguardMaterial(spec parser.OutboundSpec) (key string, addresses []string, peers []engine.WireGuardPeer) {
	key = spec.Options["privatekey"]
	if key == "" {
		key, _ = url.PathUnescape(spec.Password)
	}
	for _, a := range strings.Split(spec.Options["address"], ",") {
		a = strings.TrimSpace(a)
		switch {
		case a == "":
			continue
		case !strings.Contains(a, "/") && strings.Contains(a, ":"):
			a += "/128"
		case !strings.Contains(a, "/"):
			a += "/32"
		}
		addresses = append(addresses, a)
	}
	split := func(list []string) []string {
		var out []string
		for _, v := range list {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	for _, p := range spec.Peers {
		peers = append(peers, engine.WireGuardPeer{
			PublicKey: p.PublicKey, PreSharedKey: p.PreSharedKey, Endpoint: p.Endpoint,
			AllowedIPs: split(p.AllowedIPs), PersistentKeepalive: p.PersistentKeepalive,
		})
	}
	if len(peers) == 0 && spec.Options["publickey"] != "" {
		peers = append(peers, engine.WireGuardPeer{
			PublicKey:    spec.Options["publickey"],
			PreSharedKey: spec.Options["presharedkey"],
			Endpoint:     net.JoinHostPort(spec.Host, strconv.Itoa(int(spec.Port))),
			AllowedIPs:   split(strings.Split(spec.Options["allowedips"], ",")),
		})
	}
	return key, addresses, peers
}

// ruleFromProto converts one routing rule.
func ruleFromProto(route *corev1.RoutingRule) (engine.Rule, error) {
	destination := strings.TrimSpace(route.GetDestination())
	if destination == "" {
		return engine.Rule{}, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanRuleInvalid,
			"control: a rule has no destination")
	}
	target := strings.TrimSpace(route.GetOutboundId())
	if target == "" {
		return engine.Rule{}, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanRuleInvalid,
			"control: rule %q has no target", destination)
	}
	kind := ruleTypeOf(destination)
	value := ruleValue(kind, destination)
	if kind == engine.RuleDomain || kind == engine.RuleDomainSuffix {
		ascii, err := ruleIDNA.ToASCII(value)
		if err != nil {
			return engine.Rule{}, errs.Wrap(err, errs.CodeInvalidArgument, errs.KeyPlanRuleInvalid)
		}
		value = ascii
	}
	return engine.Rule{Type: kind, Value: value, Target: target}, nil
}

// Convert only exact and suffix domains, preserving process names and patterns.
var ruleIDNA = idna.New(idna.MapForLookup(), idna.StrictDomainName(true), idna.ValidateLabels(true), idna.VerifyDNSLength(true), idna.BidiRule())

// ruleValue strips the type prefix: the engines add their own.
func ruleValue(kind engine.RuleType, destination string) string {
	if prefix, ok := rulePrefixes[kind]; ok {
		return strings.TrimPrefix(destination, prefix)
	}
	return destination
}

// rulePrefixes follows Xray syntax: "domain:" includes subdomains; "full:"
// matches one exact name.
var rulePrefixes = map[engine.RuleType]string{
	engine.RuleGeoSite:      "geosite:",
	engine.RuleGeoIP:        "geoip:",
	engine.RuleRuleSet:      "ruleset:",
	engine.RuleDomainSuffix: "domain:",
	engine.RuleDomain:       "full:",
	engine.RuleProcess:      "process:",
}

// ruleTypeOf derives the rule type from the shape of a destination.
func ruleTypeOf(destination string) engine.RuleType {
	switch {
	case strings.HasPrefix(destination, "geosite:"):
		return engine.RuleGeoSite
	case strings.HasPrefix(destination, "geoip:"):
		return engine.RuleGeoIP
	case strings.HasPrefix(destination, "ruleset:"):
		return engine.RuleRuleSet
	case strings.HasPrefix(destination, "domain:"):
		return engine.RuleDomainSuffix
	case strings.HasPrefix(destination, "full:"):
		return engine.RuleDomain
	case strings.HasPrefix(destination, "process:"):
		return engine.RuleProcess
	case strings.Contains(destination, "/"):
		return engine.RuleIPCIDR
	case isIPLiteral(destination):
		// A bare address is not a network, a port, or a domain: reject it
		// as an invalid CIDR instead of misreading "::1" as a port or
		// "1.2.3.4" as a domain keyword.
		return engine.RuleIPCIDR
	case strings.Contains(destination, ":"):
		return engine.RulePort
	default:
		return engine.RuleDomainKeyword
	}
}

// isIPLiteral reports whether s is a bare IP address without a prefix
// length.
func isIPLiteral(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// defaultTunResolvers supplies DNS for TUN plans without resolvers.
// Address-based DNS over HTTPS avoids bootstrap resolution and encrypts
// lookups.
var defaultTunResolvers = []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}

// dnsFromProto converts the resolver settings of a request.
func dnsFromProto(policy *corev1.DnsPolicy, tun bool) engine.DNS {
	servers := policy.GetServers()
	if len(servers) == 0 && tun {
		servers = defaultTunResolvers
	}
	if len(servers) == 0 {
		return engine.DNS{}
	}
	out := engine.DNS{
		Enabled: true,
		Mode:    "rule",
		Sniff:   true,
	}
	for index, address := range servers {
		if len(out.Servers) >= engine.MaxDNSServers {
			break
		}
		host, port, transport := splitDNSServer(address)
		out.Servers = append(out.Servers, engine.DNSServer{
			Tag:       "dns-" + strconv.Itoa(index),
			Transport: transport,
			Address:   host,
			Port:      port,
		})
	}
	return out
}

// splitDNSServer splits a resolver such as "tls://dns.example.com:853". Invalid
// numeric ports leave the address unchanged.
func splitDNSServer(address string) (host string, port uint16, transport engine.DNSTransport) {
	transport = engine.DNSPlain
	rest := strings.TrimSpace(address)
	for _, candidate := range []struct {
		prefix    string
		transport engine.DNSTransport
	}{
		{"https://", engine.DNSHTTPS},
		{"h3://", engine.DNSHTTPS},
		{"tls://", engine.DNSTLS},
		{"tcp://", engine.DNSTCP},
		{"quic://", engine.DNSQUIC},
	} {
		if strings.HasPrefix(strings.ToLower(rest), candidate.prefix) {
			transport = candidate.transport
			rest = rest[len(candidate.prefix):]
			break
		}
	}
	rest = strings.TrimSuffix(rest, "/dns-query")
	if head, tail, found := strings.Cut(rest, ":"); found {
		if parsed, err := strconv.ParseUint(tail, 10, 16); err == nil {
			return head, uint16(parsed), transport
		}
	}
	return rest, 0, transport
}

// orDefault returns value when it is not empty and fallback otherwise.
func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// referenceOf derives a stable secret reference from server identity.
// Re-imports overwrite credentials instead of accumulating duplicate entries
// that cannot be safely removed.
func referenceOf(spec parser.OutboundSpec) (string, error) {
	sum := sha256.Sum256([]byte(spec.StableKey()))
	// The digest avoids exposing host or server names in references that
	// may be stored or logged.
	return "s1_" + hex.EncodeToString(sum[:16]), nil
}

// outboundToProto converts a parsed server for the client, exposing only a
// credential reference. The core resolves it when applying the plan.
func outboundToProto(spec parser.OutboundSpec, reference string) *corev1.OutboundSpec {
	// The wire spec carries Transport and Security, which a sing-box
	// or Clash import leaves in its option blobs (S5-SP6): resolve
	// them so the client — and planFromProto after it — see the real
	// transport and REALITY, not the parser's defaults. Extraction
	// errors are reported by credentialDocument, which parsePayload
	// runs before this conversion; the fallback here only keeps a
	// direct caller's display spec at the typed fields.
	if resolved, _, err := resolveImportedSpec(spec); err == nil {
		spec = resolved
	}
	return &corev1.OutboundSpec{
		Id:              spec.StableKey(),
		DisplayName:     spec.DisplayName,
		Protocol:        spec.Protocol,
		DisplayProtocol: spec.DisplayProtocol,
		Transport:       spec.Transport,
		Security:        spec.Security,
		Endpoint:        &corev1.Endpoint{Host: spec.Host, Port: uint32(spec.Port)},
		Credentials:     &corev1.CredentialsRef{Reference: reference},
	}
}

// packProfile compresses provider configuration to fit the secret store's 64
// KiB entry limit.
func packProfile(profile string) (string, error) {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(profile)); err != nil {
		return "", errs.Wrap(err, errs.CodeInternal, errs.KeySecretStoreUnavailable)
	}
	if err := w.Close(); err != nil {
		return "", errs.Wrap(err, errs.CodeInternal, errs.KeySecretStoreUnavailable)
	}
	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

// unpackProfile decompresses a stored profile and rejects output above the plan
// limit before reading it all into memory.
func unpackProfile(packed string) (json.RawMessage, error) {
	raw, err := base64.StdEncoding.DecodeString(packed)
	if err != nil {
		return nil, errs.Wrap(err, errs.CodeInvalidArgument, errs.KeyPlanOutbounds)
	}
	r, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, errs.Wrap(err, errs.CodeInvalidArgument, errs.KeyPlanOutbounds)
	}
	profile, err := io.ReadAll(io.LimitReader(r, MaxPlanBytes+1))
	if err != nil || len(profile) > MaxPlanBytes {
		return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyPlanOutbounds, "control: a stored Xray profile is unreadable or too large")
	}
	return profile, nil
}
