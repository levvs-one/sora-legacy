package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Secrets returns every value of the plan that must never reach a log, an
// event or a diagnostic archive.
func (p *Plan) Secrets() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.Outbounds)*4+1)
	for _, o := range p.Outbounds {
		out = append(out, o.Secrets()...)
	}
	if len(p.LocalProxy.Password) >= 4 {
		out = append(out, p.LocalProxy.Password)
	}
	return out
}

// Secrets lists the secret fields of one outbound. Values shorter than four
// characters are skipped: masking them would destroy ordinary log text.
func (o Outbound) Secrets() []string {
	candidates := []string{o.UUID, o.Password, o.UserID, o.ObfsOrZero().Param, o.ObfsOrZero().PluginOpts, o.QUICOrZero().Token, o.WireGuardOrZero().PrivateKey}
	// Secret-typed plugin option values (shadow-tls/restls/jls
	// passwords, kcptun keys) live ONLY inside the PluginOpts string:
	// masking the whole string does not mask a log line that quotes
	// just the value, so the values are registered separately (SP3b).
	if spec := SSPluginByName(o.ObfsOrZero().Plugin); spec != nil {
		if pairs, err := parseSSPluginOpts(o.ObfsOrZero().PluginOpts); err == nil {
			for _, pr := range pairs {
				if kind, ok := spec.optKind(pr.key); ok && kind == ssOptSecret {
					candidates = append(candidates, pr.val)
				}
			}
		}
	}
	if o.Encryption != "none" {
		candidates = append(candidates, o.Encryption)
	}
	// A WebSocket/XHTTP path and custom header values are routinely
	// used as bearer tokens by providers ("secret path" deployments);
	// they were registered nowhere, so a dial error echoing the
	// request line or headers leaked them (CENSOR-LEAK in sora,
	// REVIEW-SP45 §6 here). Header values are taken in sorted key
	// order so the list is deterministic.
	candidates = append(candidates, o.Transport.Path)
	headerKeys := make([]string, 0, len(o.Transport.Headers))
	for k := range o.Transport.Headers {
		headerKeys = append(headerKeys, k)
	}
	sort.Strings(headerKeys)
	for _, k := range headerKeys {
		candidates = append(candidates, o.Transport.Headers[k])
	}
	for _, p := range o.WireGuardOrZero().Peers {
		candidates = append(candidates, p.PreSharedKey)
	}
	candidates = append(candidates, profileSecrets(o.ProfileBytes())...)
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if len(c) >= 4 {
			out = append(out, c)
		}
	}
	return out
}

// Identifiers returns the server host and host:port for privacy redaction.
// These are not credentials but identify user connections and providers.
func (o Outbound) Identifiers() []string {
	out := make([]string, 0, 3)
	reality := o.TLS.RealityOrZero()
	xhttp := o.Transport.XHTTPOrZero()
	if o.Server != "" {
		out = append(out, o.Server)
		if o.Port != 0 {
			out = append(out, net.JoinHostPort(o.Server, strconv.Itoa(int(o.Port))))
		}
	}
	if o.TLS.ServerName != "" {
		out = append(out, o.TLS.ServerName)
	}
	// REALITY parameters are public but identify the server (sora
	// SORA-L9, ported by S5 seams): they join the redaction set so a
	// server's key, shortId and spider path never reach a log verbatim.
	if reality.PublicKey != "" {
		out = append(out, reality.PublicKey)
	}
	if reality.ShortID != "" {
		out = append(out, reality.ShortID)
	}
	if reality.SpiderX != "" {
		out = append(out, reality.SpiderX)
	}
	out = append(out, o.Name)
	// The transport's fronting host and gRPC service name identify
	// the provider's infrastructure in the same sense as the server
	// and SNI above — the host is the fronting domain of exactly the
	// class the download address below was added for — so both join
	// the redaction set (REVIEW-SP45 §6, ported from sora).
	if o.Transport.Host != "" {
		out = append(out, o.Transport.Host)
	}
	if o.Transport.Service != "" {
		out = append(out, o.Transport.Service)
	}
	// The XHTTP download split names a second server: it identifies
	// the connection exactly like the uplink address does, so it joins
	// the redaction set (S5-SP4, ported from sora).
	if xhttp.DownloadAddress != "" {
		out = append(out, xhttp.DownloadAddress)
		if xhttp.DownloadPort != 0 {
			out = append(out, net.JoinHostPort(xhttp.DownloadAddress, strconv.Itoa(int(xhttp.DownloadPort))))
		}
	}
	// An Xray profile carries its own server addresses, SNI names and
	// REALITY dest inside the profile JSON; without extracting them
	// here they were registered with no redactor at all (CENSOR-LEAK
	// in sora, ported with profileIdentifiers).
	out = append(out, profileIdentifiers(o.ProfileBytes())...)
	return out
}

// Identifiers returns plan server identifiers for redaction alongside Secrets.
func (p *Plan) Identifiers() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.Outbounds)*3)
	for _, o := range p.Outbounds {
		out = append(out, o.Identifiers()...)
	}
	return out
}

// Warnings returns codes for allowed risky settings. Clients localize them; the
// core stores no user-facing text.
func (o Outbound) Warnings() []string {
	var out []string
	if o.TLS.Insecure && o.Protocol != ProtocolDirect {
		out = append(out, "insecure-certificate")
	}
	if o.TLS.Enabled && o.TLS.ServerName == "" && o.Protocol != ProtocolDirect {
		out = append(out, "tls-server-name-missing")
	}
	if o.Transport.Type == "ws" && !o.TLS.Enabled {
		out = append(out, "websocket-without-tls")
	}
	if o.Transport.Type == "xhttp" {
		// XHTTP is under active development upstream: the client and
		// server cores must run matching versions, or the stream fails
		// with "strange glitches". The core cannot probe the server's
		// version, so every XHTTP outbound carries the reminder
		// (mirrors sora's Warnings).
		out = append(out, "xhttp-version-sync")
		// Reverse proxies (nginx default 128) cap concurrent streams;
		// above it the connection breaks instead of degrading.
		if o.Transport.XHTTPOrZero().XmuxMaxConcurrency > 128 {
			out = append(out, "xhttp-xmux-proxy-limit")
		}
	}
	// REALITY hardening (T002): vision/TLS-in-TLS and dest-shape warnings.
	out = append(out, o.RealityWarnings()...)
	return out
}

// Validate checks one outbound on its own, without engine capabilities.
func (o Outbound) Validate() error {
	var errs []error
	if o.ID == "" {
		errs = append(errs, errors.New("outbound: empty id"))
	} else if len(o.ID) > MaxIDLen {
		errs = append(errs, fmt.Errorf("outbound %q: id longer than %d bytes", o.ID, MaxIDLen))
	}
	// The "outbound <id>" subject is built once: it used to be
	// concatenated separately for every sub-validator (three
	// allocations per outbound on the plan admit path).
	what := "outbound " + o.ID
	if err := validateDisplayName(what, o.Name); err != nil {
		errs = append(errs, err)
	}
	if o.Protocol == "" {
		errs = append(errs, fmt.Errorf("outbound %s: empty protocol", o.ID))
	} else if !validProtocols[o.Protocol] {
		errs = append(errs, fmt.Errorf("outbound %s: unknown protocol %q", o.ID, o.Protocol))
	}
	if !validTransports[o.Transport.Type] {
		errs = append(errs, fmt.Errorf("outbound %s: unknown transport %q", o.ID, o.Transport.Type))
	}
	serverless := o.Protocol == ProtocolDirect || o.Protocol == ProtocolBypass
	if !serverless && o.Port == 0 {
		errs = append(errs, fmt.Errorf("outbound %s: port must be between 1 and 65535", o.ID))
	}
	if err := validateServer(what, o.Server, !serverless); err != nil {
		errs = append(errs, err)
	}
	if o.Protocol == ProtocolBypass {
		errs = append(errs, o.Bypass.validate(o.ID))
	}
	if o.Protocol == ProtocolXrayProfile {
		var profile struct {
			Outbounds []json.RawMessage `json:"outbounds"`
		}
		if err := json.Unmarshal(o.ProfileBytes(), &profile); err != nil || len(profile.Outbounds) == 0 {
			errs = append(errs, fmt.Errorf("outbound %s: the Xray profile has no outbounds", o.ID))
		}
	}
	if len(o.TLS.ALPN) > 8 {
		errs = append(errs, fmt.Errorf("outbound %s: too many ALPN entries", o.ID))
	}
	errs = append(errs, o.TLS.validate(what)...)
	// Early fingerprint-name validation (§8.8): a garbage uTLS
	// fingerprint name used to pass plan validation and fail only
	// late, at the engine binary's config check. The name catalog
	// is the reference's (fingerprint.go, pinned by
	// TestFingerprintCatalogParityPin); a name no engine can spell
	// is refused here, by name, before any renderer runs.
	if fp := o.TLS.Fingerprint; fp != "" && !ValidFingerprintName(fp) {
		errs = append(errs, fmt.Errorf("outbound %s: fingerprint %q is not a known uTLS fingerprint", o.ID, fp))
	}
	if len(o.Transport.Headers) > MaxHeaderCount {
		errs = append(errs, fmt.Errorf("outbound %s: more than %d headers", o.ID, MaxHeaderCount))
	}
	for k, v := range o.Transport.Headers {
		if !validHeaderToken(k) || strings.ContainsAny(v, "\r\n") {
			errs = append(errs, fmt.Errorf("outbound %s: header %q is not a safe HTTP header", o.ID, k))
		}
	}
	if o.Amnezia != nil {
		if o.Protocol != ProtocolWireGuard {
			errs = append(errs, fmt.Errorf("outbound %s: AmneziaWG parameters require the wireguard protocol", o.ID))
		} else {
			errs = append(errs, validateAmneziaWG(o.ID, o.Amnezia)...)
		}
	}
	// Shadowsocks plugin fields (explicit SIP002 plugin and the
	// legacy Obfs/ObfsParam simple-obfs mapping) fail closed against
	// the plugin catalog: the renderers interpolate them into plugin
	// configs, so an unknown plugin, an unknown option or a separator
	// in the obfs-host would otherwise surface as a silently
	// unobfuscated plan or as injected plugin options (SP3b).
	errs = append(errs, validateShadowsocksPlugin(o)...)
	for _, peer := range o.WireGuardOrZero().Peers {
		if err := validatePeerEndpoint(o.ID, peer.Endpoint); err != nil {
			errs = append(errs, err)
		}
	}
	// REALITY hardening (T002, ported from sora by S5 seams): malformed
	// keys or shortIds fail here, not at the engine.
	if err := o.ValidateReality(); err != nil {
		errs = append(errs, err)
	}
	if o.Protocol == ProtocolHysteria2 {
		errs = append(errs, validateHysteria2Tuning(o)...)
	}
	if o.Protocol == ProtocolTUIC {
		errs = append(errs, validateTUICTuning(o)...)
	}
	errs = append(errs, validateXHTTP(o)...)
	return errors.Join(errs...)
}

// validProtocols whitelists the protocols a plan may hold, so an
// unknown protocol fails validation with a clear error instead of
// surfacing late at engine apply (sora SORA-L16, ported by S5 seams).
// The set is exactly sora's: every Protocol constant of this package.
var validProtocols = map[Protocol]bool{
	ProtocolVLESS: true, ProtocolVMess: true, ProtocolTrojan: true,
	ProtocolShadowsocks: true, ProtocolHysteria2: true, ProtocolTUIC: true,
	ProtocolWireGuard: true, ProtocolSOCKS5: true, ProtocolHTTP: true,
	ProtocolAnyTLS: true, ProtocolBypass: true, ProtocolXrayProfile: true,
	ProtocolDirect: true,
}

// validTransports whitelists the stream transports a plan may hold.
// "h2" is accepted at plan level for sing-box; engines that dropped it
// (Xray) reject it when rendering. Same set as sora.
var validTransports = map[string]bool{
	"": true, "tcp": true, "ws": true, "grpc": true,
	"h2": true, "httpupgrade": true, "xhttp": true,
}

// validXHTTPModes whitelists the XHTTP stream modes every engine
// implements. Same set as sora.
var validXHTTPModes = map[string]bool{
	"": true, "auto": true, "packet-up": true, "stream-up": true, "stream-one": true,
}

// xhttpPaddingRange parses an XHTTP padding range: "min-max" or a single
// number. Engines read it as a string, so the check is syntactic plus a
// sanity bound (larger than any plausible MTU is a typo, not a setting).
var xhttpPaddingRange = regexp.MustCompile(`^([0-9]{1,5})(-([0-9]{1,5}))?$`)

// validateXHTTP checks the XHTTP-only transport options engine-independently,
// so a broken combination fails at plan validation instead of surfacing as
// a runtime failure in whichever engine renders it. Full port of sora's
// validateXHTTP (S5-SP4): mode whitelist, vision flow, downloadSettings
// pairing and stream-one exclusion, xmux negativity and exclusivity,
// xPaddingBytes format, ALPN h3 gating — plus the stray-field rejection
// that keeps the split/tuning from being silently dropped by renderers
// of other transports.
func validateXHTTP(o Outbound) []error {
	t := o.Transport
	x := t.XHTTPOrZero()
	if t.Type != "xhttp" {
		// The split/tuning fields belong to XHTTP; on another transport
		// they would be silently dropped by every renderer.
		var errs []error
		if x.DownloadAddress != "" || x.DownloadPort != 0 {
			errs = append(errs, fmt.Errorf("outbound %s: downloadSettings needs the xhttp transport, not %q", o.ID, t.Type))
		}
		if x.XmuxMaxConcurrency != 0 || x.XmuxMaxConnections != 0 || x.XmuxMaxReuseTimes != 0 || x.XmuxMaxRequestTimes != 0 {
			errs = append(errs, fmt.Errorf("outbound %s: xmux tuning needs the xhttp transport, not %q", o.ID, t.Type))
		}
		if x.XPaddingBytes != "" {
			errs = append(errs, fmt.Errorf("outbound %s: xPaddingBytes needs the xhttp transport, not %q", o.ID, t.Type))
		}
		return errs
	}
	var errs []error
	bad := func(format string, args ...any) {
		args = append([]any{o.ID}, args...)
		errs = append(errs, fmt.Errorf("outbound %s: xhttp "+format, args...))
	}
	if !validXHTTPModes[x.Mode] {
		bad("mode %q is not one of auto, packet-up, stream-up, stream-one", x.Mode)
	}
	if strings.HasPrefix(o.Flow, "xtls-rprx-vision") && !o.HasVLESSEncryption() {
		// XTLS is available only under TCP+TLS/REALITY — or under
		// VLESS Encryption, which carries the flow on any transport
		// (https://xtls.github.io/en/config/outbounds/vless.html).
		// Without Encryption, vision on XHTTP cannot work; XHTTP's
		// protection against TLS-in-TLS comes from xmux and the
		// up/down split instead.
		bad("flow %q cannot be combined with the xhttp transport (Vision needs TCP or VLESS Encryption)", o.Flow)
	}
	if x.DownloadAddress != "" || x.DownloadPort != 0 {
		if x.DownloadAddress == "" || x.DownloadPort == 0 {
			bad("downloadSettings needs both a download address and a download port")
		} else if err := validateServer("outbound "+o.ID+" download", x.DownloadAddress, true); err != nil {
			errs = append(errs, err)
		}
		if x.Mode == "stream-one" {
			// stream-one carries both directions on one connection; a
			// separate downlink contradicts it. stream-up is the
			// two-leg mode (auto+reality degrades to stream-one only
			// without downloadSettings).
			bad("downloadSettings is incompatible with mode stream-one (use stream-up)")
		}
	}
	if x.XmuxMaxConcurrency < 0 || x.XmuxMaxConnections < 0 || x.XmuxMaxReuseTimes < 0 || x.XmuxMaxRequestTimes < 0 {
		bad("xmux values must not be negative")
	}
	if x.XmuxMaxConcurrency > 0 && x.XmuxMaxConnections > 0 {
		bad("xmux maxConcurrency and maxConnections are mutually exclusive")
	}
	if x.XPaddingBytes != "" {
		m := xhttpPaddingRange.FindStringSubmatch(x.XPaddingBytes)
		if m == nil {
			bad("xPaddingBytes %q is not a \"min-max\" range or a single number", x.XPaddingBytes)
		} else {
			lo, _ := strconv.Atoi(m[1])
			hi := lo
			if m[3] != "" {
				hi, _ = strconv.Atoi(m[3])
			}
			if lo > hi {
				bad("xPaddingBytes %q has its lower bound above the upper bound", x.XPaddingBytes)
			}
			if hi > 65535 {
				bad("xPaddingBytes %q exceeds 65535 bytes", x.XPaddingBytes)
			}
		}
	}
	if slices.Contains(o.TLS.ALPN, "h3") && !o.TLS.Enabled && (o.TLS.Reality == nil) {
		// Xray dials QUIC for XHTTP only when ALPN is exactly ["h3"] on
		// a TLS stream; without TLS the option does nothing.
		bad("ALPN h3 needs TLS (or REALITY) on the xhttp transport")
	}
	return errs
}

// validate enforces the ECH honesty rules (ported from sora, S5-SP5):
//   - ECH without TLS is meaningless;
//   - ECH and REALITY are incompatible: REALITY owns the ClientHello, an
//     ECH extension on top of it is misconfiguration, not stealth.
//
// QueryServerName is NOT rejected here: sing-box renders it
// (ech.query_server_name, available since 1.13) and mihomo renders
// it (ech-opts.query-server-name). Selection gates the plan per
// engine build instead (FeatureECHQueryServerName: sing-box builds
// at the 1.12.0 floor, e.g. the shipped payload 1.12.12, refuse the
// rendered field at load — probed, LEGACY-PLAT-OBFS). The Xray
// path, which renders ECH without a query-name spelling, is closed
// by the gate and by the renderer's own refusal, not by validation
// (SP5-render, from sora snapshot 63faf1d).
func (t TLS) validate(what string) []error {
	var errs []error
	keyShare := t.RealityOrZero().KeyShare
	// KeyShare is the REALITY key-share knob: only the two documented
	// values. It lives inside the REALITY box, so a KeyShare without
	// REALITY cannot be represented — the pre-boxing "key_share needs
	// REALITY" rejection has no state left to fire on.
	switch keyShare {
	case "", "classical", "hybrid":
	default:
		errs = append(errs, fmt.Errorf("%s: reality key_share %q is not \"classical\" or \"hybrid\"", what, keyShare))
	}
	ech := t.ECHOrZero()
	if !ech.Enabled {
		return errs
	}
	if !t.Enabled {
		errs = append(errs, fmt.Errorf("%s: ECH is enabled but TLS is not", what))
	}
	if t.Reality != nil {
		errs = append(errs, fmt.Errorf("%s: ECH and REALITY are incompatible", what))
	}
	if len(ech.Config) > 0 {
		// A pinned list every renderer must decode: garbage here
		// would otherwise surface as an engine startup refusal or a
		// silently unparseable echConfigList.
		if _, err := ECHConfigListBytes(ech.Config); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", what, err))
		}
	}
	return errs
}

// hasEncryptedServer reports whether the plan carries a DNS transport a
// passive censor cannot read. ECH without a pinned config fetches the
// ECHConfigList from the DNS HTTPS record; over plaintext or system DNS
// that bootstrap query leaks the target domain before TLS even starts.
// Legacy's DNS transports have no h3 constant (sora's set checks it
// too); the encrypted set here is DoH, DoT and DoQ.
func (d DNS) hasEncryptedServer() bool {
	if !d.Enabled {
		return false
	}
	for _, s := range d.Servers {
		switch s.Transport {
		case DNSHTTPS, DNSTLS, DNSQUIC:
			return true
		}
	}
	return false
}

// validatePeerEndpoint checks the host:port of a WireGuard peer. Renderers
// split it without further checks, so an invalid port must fail here.
func validatePeerEndpoint(id, endpoint string) error {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("outbound %s: peer endpoint %q is not host:port", id, endpoint)
	}
	if host == "" {
		return fmt.Errorf("outbound %s: peer endpoint %q has no host", id, endpoint)
	}
	if port, err := strconv.Atoi(portText); err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("outbound %s: peer port %q is not valid", id, portText)
	}
	return nil
}

// Validate checks the plan as a whole: limits, identifiers, references between
// rules and groups, and the engine-independent rules of every outbound.
func (p *Plan) Validate() error {
	if p == nil {
		return errors.New("plan: nil plan")
	}
	var errs []error
	if strings.TrimSpace(p.SessionID) == "" {
		errs = append(errs, errors.New("plan: empty session id"))
	}
	if len(p.Outbounds) == 0 {
		errs = append(errs, errors.New("plan: no outbounds"))
	}
	if len(p.Outbounds) > MaxOutbounds {
		errs = append(errs, fmt.Errorf("plan: %d outbounds exceeds the limit of %d", len(p.Outbounds), MaxOutbounds))
	}
	if len(p.Groups) > MaxGroups {
		errs = append(errs, fmt.Errorf("plan: %d groups exceeds the limit of %d", len(p.Groups), MaxGroups))
	}
	if len(p.Rules) > MaxRules {
		errs = append(errs, fmt.Errorf("plan: %d rules exceeds the limit of %d", len(p.Rules), MaxRules))
	}

	ids := make(map[string]struct{}, len(p.Outbounds))
	for _, o := range p.Outbounds {
		errs = append(errs, o.Validate())
		if _, dup := ids[o.ID]; dup {
			errs = append(errs, fmt.Errorf("plan: duplicate outbound id %q", o.ID))
		}
		ids[o.ID] = struct{}{}
	}
	// Profiles run alone because combining provider routing with other
	// profiles or groups changes its semantics.
	if slices.ContainsFunc(p.Outbounds, func(o Outbound) bool { return o.Protocol == ProtocolXrayProfile }) &&
		(len(p.Outbounds) > 1 || len(p.Groups) > 0) {
		errs = append(errs, errors.New("plan: an Xray profile runs alone, without other outbounds or groups"))
	}

	// Collect all group names before validating members to allow nested and
	// forward references.
	members := make(map[string][]string, len(p.Groups))
	for _, g := range p.Groups {
		members[g.Name] = g.Outbounds
		if _, clash := ids[g.Name]; clash {
			errs = append(errs, fmt.Errorf("plan: group %q has the id of an outbound", g.Name))
		}
	}
	if (p.LocalProxy.Username == "") != (p.LocalProxy.Password == "") {
		errs = append(errs, errors.New("plan: the local proxy login needs both a username and a password"))
	}
	if strings.ContainsAny(p.LocalProxy.Username, ":@ \r\n") {
		errs = append(errs, errors.New("plan: the local proxy username contains a separator"))
	}
	names := make(map[string]struct{}, len(p.Groups))
	for _, g := range p.Groups {
		errs = append(errs, g.validate())
		if g.needsProbe() && g.URL == "" && p.Options.TestURL == "" {
			errs = append(errs, fmt.Errorf("plan: group %q measures latency, but the plan has no test url", g.Name))
		}
		errs = append(errs, validateTestURL("group "+g.Name, g.URL))
		if _, dup := names[g.Name]; dup {
			errs = append(errs, fmt.Errorf("plan: duplicate group name %q", g.Name))
		}
		names[g.Name] = struct{}{}
		for _, ref := range g.Outbounds {
			_, isOutbound := ids[ref]
			_, isGroup := members[ref]
			if !isOutbound && !isGroup && !IsBuiltInTarget(ref) {
				errs = append(errs, fmt.Errorf("group %q: unknown outbound %q", g.Name, ref))
			}
		}
		if groupCycle(g.Name, members, map[string]bool{}) {
			errs = append(errs, fmt.Errorf("group %q: contains itself through its members", g.Name))
		}
	}

	for _, r := range p.Rules {
		errs = append(errs, r.validate())
		if r.Target == "" {
			errs = append(errs, fmt.Errorf("rule %s %q: empty target", r.Type, r.Value))
			continue
		}
		_, isOutbound := ids[r.Target]
		_, isGroup := names[r.Target]
		if !isOutbound && !isGroup && !IsBuiltInTarget(r.Target) {
			errs = append(errs, fmt.Errorf("rule %s %q: unknown target %q", r.Type, r.Value, r.Target))
		}
	}

	errs = append(errs, p.DNS.validate(), p.Tun.validate(), p.Options.validate())

	// ECH without a pinned config fetches the ECHConfigList from the DNS
	// HTTPS record: over a plaintext or system DNS path that
	// bootstrap query leaks the target domain before TLS even starts,
	// which defeats the purpose of hiding the SNI. Fail closed with a
	// message that names the fix (S5-SP5, ported from sora).
	for _, o := range p.Outbounds {
		if o.TLS.ECHOrZero().Enabled && len(o.TLS.ECHOrZero().Config) == 0 && !p.DNS.hasEncryptedServer() {
			errs = append(errs, fmt.Errorf("plan: outbound %s enables ECH without a pinned config, but the plan has no encrypted DNS transport; pin the ECH config or enable encrypted DNS", o.ID))
		}
	}
	return errors.Join(errs...)
}

// groupCycle reports whether group reaches itself through nested groups.
func groupCycle(group string, members map[string][]string, visiting map[string]bool) bool {
	if visiting[group] {
		return true
	}
	visiting[group] = true
	defer delete(visiting, group)
	for _, m := range members[group] {
		if _, isGroup := members[m]; isGroup && groupCycle(m, members, visiting) {
			return true
		}
	}
	return false
}

// bypassPosition is a zapret split position: bytes, bytes from the end, or a
// marker with an optional offset.
var bypassPosition = regexp.MustCompile(`^(-?[0-9]{1,4}|(method|host|endhost|sld|midsld|endsld|sniext)([+-][0-9]{1,4})?)$`)

func (s *BypassStrategy) validate(id string) error {
	if s == nil {
		return fmt.Errorf("outbound %s: a bypass outbound needs a strategy", id)
	}
	if len(s.SplitPos) == 0 && s.TLSRecord == "" && !s.HostCase && !s.DomainCase && !s.MethodEOL &&
		!s.HostDot && !s.HostTab && !s.HostNoSpace && !s.MethodSpace && !s.UnixEOL {
		return fmt.Errorf("outbound %s: the bypass strategy changes nothing", id)
	}
	if len(s.SplitPos) > 8 {
		return fmt.Errorf("outbound %s: more than 8 split positions", id)
	}
	for _, pos := range append(slices.Clone(s.SplitPos), s.TLSRecord) {
		if pos != "" && !bypassPosition.MatchString(pos) {
			return fmt.Errorf("outbound %s: %q is not a split position", id, pos)
		}
	}
	for _, scope := range []string{s.DisorderScope, s.OOBScope} {
		if scope != "" && scope != "http" && scope != "tls" {
			return fmt.Errorf("outbound %s: %q is not a protocol scope (http or tls)", id, scope)
		}
	}
	if s.DisorderScope != "" && !s.Disorder {
		return fmt.Errorf("outbound %s: a disorder scope needs disorder", id)
	}
	if s.OOBScope != "" && !s.OOB {
		return fmt.Errorf("outbound %s: an out-of-band scope needs out-of-band", id)
	}
	if (s.Disorder || s.OOB) && len(s.SplitPos) == 0 {
		return fmt.Errorf("outbound %s: disorder and out-of-band bytes need a split position", id)
	}
	return nil
}

// AmneziaWG parameter bounds, matching the upstream kernel module and
// amneziawg-go: Jc is 1-128 (0 disables junk), junk sizes stay below the
// 1280-byte minimal IPv6 MTU so packets do not fragment, S1/S2 keep
// 148+S1 != 92+S2 so init and response sizes cannot collide, and the four
// magic headers must be distinct so packet types stay distinguishable.
const (
	awgMaxJunkCount = 128
	awgMaxJunkSize  = 1280
	awgMaxS1        = 1132
	awgMaxS2        = 1188
	awgMaxS3        = 1216
	awgMaxS4        = 32
	awgMinMagic     = 5
	awgMaxMagic     = 2147483647
)

// validateAmneziaWG rejects obfuscation parameters an engine would silently
// misapply or drop: every engine derives from the same upstream device, so
// the checks stay engine-independent. I1-I5 are CPS tag scripts (engine and
// version specific) and are left to the renderer.
func validateAmneziaWG(id string, a *AmneziaWG) []error {
	var errs []error
	bad := func(format string, args ...any) {
		args = append([]any{id}, args...)
		errs = append(errs, fmt.Errorf("outbound %s: amneziawg "+format, args...))
	}
	if a.Jc < 0 || a.Jc > awgMaxJunkCount {
		bad("jc %d is outside 0-%d", a.Jc, awgMaxJunkCount)
	}
	if a.Jmin < 0 || a.Jmin > awgMaxJunkSize {
		bad("jmin %d is outside 0-%d", a.Jmin, awgMaxJunkSize)
	}
	if a.Jmax < 0 || a.Jmax > awgMaxJunkSize {
		bad("jmax %d is outside 0-%d", a.Jmax, awgMaxJunkSize)
	}
	if a.Jmin > a.Jmax {
		bad("jmin %d exceeds jmax %d", a.Jmin, a.Jmax)
	}
	pads := []struct {
		name string
		v    int
		max  int
	}{
		{"s1", a.S1, awgMaxS1}, {"s2", a.S2, awgMaxS2},
		{"s3", a.S3, awgMaxS3}, {"s4", a.S4, awgMaxS4},
	}
	for _, p := range pads {
		if p.v < 0 || p.v > p.max {
			bad("%s %d is outside 0-%d", p.name, p.v, p.max)
		}
	}
	if a.S1+56 == a.S2 && (a.S1 != 0 || a.S2 != 0) {
		bad("s1+56 must not equal s2, or padded init and response packets collide at %d bytes", a.S2+92)
	}
	type interval struct{ lo, hi int64 }
	headers := [4]interval{}
	names := []string{"h1", "h2", "h3", "h4"}
	values := []string{a.H1, a.H2, a.H3, a.H4}
	for i, raw := range values {
		if raw == "" {
			continue
		}
		lo, hi, err := parseAmneziaMagic(raw)
		if err != nil {
			bad("%s %q is not a header or header range: %v", names[i], raw, err)
			continue
		}
		if lo < awgMinMagic || hi > awgMaxMagic {
			bad("%s %q is outside %d-%d", names[i], raw, awgMinMagic, awgMaxMagic)
			continue
		}
		headers[i] = interval{lo, hi}
	}
	for i := 0; i < 4; i++ {
		if values[i] == "" {
			continue
		}
		for j := i + 1; j < 4; j++ {
			if values[j] == "" {
				continue
			}
			if headers[i].lo <= headers[j].hi && headers[j].lo <= headers[i].hi {
				bad("%s %q and %s %q overlap: packet types must stay distinguishable",
					names[i], values[i], names[j], values[j])
			}
		}
	}
	return errs
}

// parseAmneziaMagic parses a 2.0 magic header: a single number or an "x-y"
// range with x <= y.
func parseAmneziaMagic(raw string) (lo, hi int64, err error) {
	parts := strings.SplitN(raw, "-", 2)
	if len(parts) == 1 {
		n, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		if err != nil {
			return 0, 0, err
		}
		return n, n, nil
	}
	lo, err = strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil {
		return 0, 0, err
	}
	hi, err = strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil {
		return 0, 0, err
	}
	if lo > hi {
		return 0, 0, fmt.Errorf("range %q has its lower bound above the upper bound", raw)
	}
	return lo, hi, nil
}

// validateHysteria2Tuning checks the bandwidth caps and port-hopping spec of
// a Hysteria2 outbound. Engines pick BBR or Brutal congestion control and
// the hopping behavior from these fields, so malformed values must fail here
// instead of producing a config the engine silently misapplies.
func validateHysteria2Tuning(o Outbound) []error {
	var errs []error
	q := o.QUICOrZero()
	ob := o.ObfsOrZero()
	if q.UpMbps < 0 || q.DownMbps < 0 {
		errs = append(errs, fmt.Errorf("outbound %s: hysteria2 bandwidth caps must not be negative", o.ID))
	}
	if q.UpMbps > MaxHy2BandwidthMbps || q.DownMbps > MaxHy2BandwidthMbps {
		errs = append(errs, fmt.Errorf("outbound %s: hysteria2 bandwidth caps must not exceed %d Mbps", o.ID, MaxHy2BandwidthMbps))
	}
	// Obfs is a plan-level promise of wire obfuscation: the type must
	// be one the engines implement and its password (credential data,
	// carried in ObfsParam and masked via Secrets) must be present —
	// both hopping engines reject an obfs block without a password
	// at config load (verified on the pins, CENSOR-P3), so accepting
	// it here would defer a plan error to a dead engine start.
	if ob.Type != "" && !ValidHy2Obfs[ob.Type] {
		errs = append(errs, fmt.Errorf("outbound %s: hysteria2 obfs %q is not salamander or gecko", o.ID, ob.Type))
	}
	if ob.Type != "" && ob.Param == "" {
		errs = append(errs, fmt.Errorf("outbound %s: hysteria2 obfs %q needs its password", o.ID, ob.Type))
	}
	if ob.Type == "" && ob.Param != "" {
		errs = append(errs, fmt.Errorf("outbound %s: hysteria2 obfs password without an obfs type does nothing", o.ID))
	}
	if err := validateHopPorts(o.ID, q.HopPorts); err != nil {
		errs = append(errs, err)
	}
	switch {
	case q.HopInterval < 0:
		errs = append(errs, fmt.Errorf("outbound %s: hysteria2 hop interval must not be negative", o.ID))
	case q.HopInterval > 0 && q.HopInterval < MinHy2HopIntervalSeconds:
		// Hysteria2 requires at least 5s between hops.
		errs = append(errs, fmt.Errorf("outbound %s: hysteria2 hop interval must be at least %ds", o.ID, MinHy2HopIntervalSeconds))
	case q.HopInterval > 0 && q.HopPorts == "":
		errs = append(errs, fmt.Errorf("outbound %s: hysteria2 hop interval needs hop ports", o.ID))
	}
	switch {
	case q.HopIntervalMax < 0:
		errs = append(errs, fmt.Errorf("outbound %s: hysteria2 hop interval max must not be negative", o.ID))
	case q.HopIntervalMax > 0 && q.HopPorts == "":
		errs = append(errs, fmt.Errorf("outbound %s: hysteria2 hop interval max needs hop ports", o.ID))
	case q.HopIntervalMax > 0 && q.HopInterval > 0 && q.HopIntervalMax < q.HopInterval:
		// sing-box renders hop_interval..hop_interval_max as the
		// randomized hop range; an inverted range is a config bug.
		errs = append(errs, fmt.Errorf("outbound %s: hysteria2 hop interval max %ds is below the hop interval %ds", o.ID, q.HopIntervalMax, q.HopInterval))
	}
	if q.BBRProfile != "" && !validBBRProfiles[q.BBRProfile] {
		errs = append(errs, fmt.Errorf("outbound %s: hysteria2 bbr profile %q is not standard, conservative or aggressive", o.ID, q.BBRProfile))
	}
	return errs
}

// validBBRProfiles lists the BBR congestion profiles sing-box 1.14
// accepts for Hysteria2 outbounds (bbr_profile).
var validBBRProfiles = map[string]bool{"standard": true, "conservative": true, "aggressive": true}

// validateHopPorts checks a Hysteria2 port-hopping spec such as
// "20000-30000,40000": comma-separated single ports or ascending ranges.
// The parse itself lives in HopPortRanges (quic_defaults.go), the same
// parser the renderers translate from, so validation and rendering
// can never disagree about what a spec means.
func validateHopPorts(id, spec string) error {
	if _, err := HopPortRanges(spec); err != nil {
		return fmt.Errorf("outbound %s: %w", id, err)
	}
	return nil
}

// validateTUICTuning checks the congestion controller, UDP relay mode
// and heartbeat of a TUIC outbound against what the engines implement,
// so an unknown value fails validation instead of silently falling
// back to an engine default. The vocabularies live in
// quic_defaults.go (ValidTUICCongestion / ValidTUICUDPRelayMode);
// mihomo accepts unknown values silently at config load, so this
// gate is the only thing standing between a typo and a silent
// default there (verified on the pins, CENSOR-P3).
func validateTUICTuning(o Outbound) []error {
	var errs []error
	q := o.QUICOrZero()
	if q.CongestionControl != "" && !ValidTUICCongestion[q.CongestionControl] {
		errs = append(errs, fmt.Errorf("outbound %s: unknown tuic congestion control %q", o.ID, q.CongestionControl))
	}
	if q.UDPRelayMode != "" && !ValidTUICUDPRelayMode[q.UDPRelayMode] {
		errs = append(errs, fmt.Errorf("outbound %s: unknown tuic udp relay mode %q", o.ID, q.UDPRelayMode))
	}
	if q.TUICHeartbeat < 0 || (q.TUICHeartbeat > 0 && q.TUICHeartbeat < MinTUICHeartbeatSeconds) || q.TUICHeartbeat > MaxTUICHeartbeatSeconds {
		errs = append(errs, fmt.Errorf("outbound %s: tuic heartbeat %ds is outside %d-%ds (0 keeps the default)", o.ID, q.TUICHeartbeat, MinTUICHeartbeatSeconds, MaxTUICHeartbeatSeconds))
	}
	return errs
}
