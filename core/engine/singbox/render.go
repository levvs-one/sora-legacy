package singbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/supervise"
)

// Official SagerNet rule sets replace geoip and geosite databases removed in
// sing-box 1.12.
const (
	geoSiteRuleSetURL = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-%s.srs"
	geoIPRuleSetURL   = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-%s.srs"
)

// obj models configuration JSON. set omits zero values because some empty
// values are explicit settings upstream.
type obj map[string]any

func (o obj) set(key string, value any) obj {
	switch v := value.(type) {
	case string:
		if v == "" {
			return o
		}
	case int:
		if v == 0 {
			return o
		}
	case bool:
		if !v {
			return o
		}
	case []string:
		if len(v) == 0 {
			return o
		}
	case obj:
		if len(v) == 0 {
			return o
		}
	case nil:
		return o
	}
	o[key] = value
	return o
}

// Render produces credential-bearing JSON for engine stdin. The output must
// never enter diagnostic archives.
func Render(p *engine.Plan, rt supervise.Runtime) ([]byte, error) {
	if p == nil {
		return nil, errors.New("singbox: nil plan")
	}
	r := renderer{plan: p, tags: map[string]string{}, used: map[string]bool{"direct": true}}
	if err := r.assignTags(); err != nil {
		return nil, err
	}
	outbounds, endpoints, err := r.outbounds()
	if err != nil {
		return nil, err
	}
	route, err := r.route()
	if err != nil {
		return nil, err
	}
	dns, resolver, err := r.dns()
	if err != nil {
		return nil, err
	}
	route["default_domain_resolver"] = obj{"server": resolver}

	listen := "127.0.0.1"
	if p.Options.AllowLAN {
		listen = "0.0.0.0"
	}
	// Open only requested listeners because all local applications can
	// reach loopback.
	inbounds := []obj{}
	if lp := p.LocalProxy; lp.Enabled {
		mixed := obj{"type": "mixed", "tag": "mixed-in", "listen": listen, "listen_port": rt.LocalPort}
		if lp.Username != "" {
			mixed["users"] = []obj{{"username": lp.Username, "password": lp.Password}}
		}
		inbounds = append(inbounds, mixed)
	}
	if p.Tun.Enabled {
		inbounds = append(inbounds, tun(p.Tun))
	}

	cfg := obj{
		"log":       logConfig(p.Options.LogLevel),
		"dns":       dns,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     route,
		"experimental": obj{
			"clash_api": obj{"external_controller": rt.ControlAddr, "secret": rt.Secret},
			// Persist selector choices and fake-IP mappings because
			// new plans restart sing-box.
			"cache_file": obj{"enabled": true, "path": "cache.db", "store_fakeip": p.DNS.Mode == string(engine.DNSFakeIP)},
		},
	}
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	return json.Marshal(cfg)
}

type renderer struct {
	plan     *engine.Plan
	tags     map[string]string // plan id or group name -> sing-box tag
	used     map[string]bool
	final    string
	ruleSets []obj
}

// assignTags gives outbounds and groups unique tags. Unique display names are
// preferred because the Clash API shows tags to users.
func (r *renderer) assignTags() error {
	unique := func(name, fallback string) string {
		tag := strings.TrimSpace(name)
		if tag == "" || r.used[tag] {
			tag = fallback
		}
		for n := 2; r.used[tag]; n++ {
			tag = fallback + "-" + strconv.Itoa(n)
		}
		r.used[tag] = true
		return tag
	}
	for _, o := range r.plan.Outbounds {
		r.tags[o.ID] = unique(o.Name, o.ID)
	}
	for _, g := range r.plan.Groups {
		if _, clash := r.tags[g.Name]; clash {
			return fmt.Errorf("singbox: group %q has the id of an outbound", g.Name)
		}
		r.tags[g.Name] = unique(g.Name, "group")
	}
	return nil
}

func (r *renderer) target(id string) (string, error) {
	switch id {
	case "direct", "pass":
		// sing-box has no accept action; pass routes like direct.
		return "direct", nil
	}
	tag, ok := r.tags[id]
	if !ok {
		return "", fmt.Errorf("singbox: target %q is not an outbound or a group of this plan", id)
	}
	return tag, nil
}

func (r *renderer) outbounds() (outbounds, endpoints []obj, err error) {
	for _, o := range r.plan.Outbounds {
		out, err := r.outbound(o)
		if err != nil {
			return nil, nil, err
		}
		if o.Protocol == engine.ProtocolWireGuard {
			endpoints = append(endpoints, out)
		} else {
			outbounds = append(outbounds, out)
		}
	}
	for _, g := range r.plan.Groups {
		group, err := r.group(g)
		if err != nil {
			return nil, nil, err
		}
		outbounds = append(outbounds, group)
	}
	return append(outbounds, obj{"type": "direct", "tag": "direct"}), endpoints, nil
}

func (r *renderer) outbound(o engine.Outbound) (obj, error) {
	out := obj{"tag": r.tags[o.ID]}
	if o.Protocol != engine.ProtocolDirect && o.Protocol != engine.ProtocolWireGuard {
		out.set("server", o.Server).set("server_port", int(o.Port))
	}
	needsTLS := false
	switch o.Protocol {
	case engine.ProtocolDirect:
		out["type"] = "direct"
		return out, nil
	case engine.ProtocolVLESS:
		out.set("type", "vless").set("uuid", o.UUID).set("flow", o.Flow).set("packet_encoding", "xudp")
		if o.Encryption != "none" {
			out.set("encryption", o.Encryption)
		}
	case engine.ProtocolVMess:
		out.set("type", "vmess").set("uuid", o.UUID).set("security", orDefault(o.Cipher, "auto"))
	case engine.ProtocolTrojan:
		out.set("type", "trojan").set("password", o.Password)
		needsTLS = true
	case engine.ProtocolShadowsocks:
		// Fail closed on plugins the pinned build cannot resolve
		// (measured in sora, CENSOR-P4): an external plugin binary
		// that does not ship, or a name sing-box does not know, dies
		// here with the plan context instead of as a bare engine
		// FATAL at start. Selection refuses the same facts earlier
		// (catalog.go).
		if o.Plugin != "" && !engine.SupportsSSPlugin(engine.KindSingBox, o.Plugin) {
			return nil, fmt.Errorf("singbox: shadowsocks outbound %s uses plugin %q, which needs a plugin binary sora does not ship: refusing to render", o.ID, o.Plugin)
		}
		out.set("type", "shadowsocks").set("method", orDefault(o.Cipher, "aes-256-gcm")).set("password", o.Password)
		// An explicit SIP002 plugin wins over the legacy obfs-local
		// mapping; sing-box passes plugin/plugin_opts to the plugin
		// binary verbatim.
		switch {
		case o.Plugin != "":
			out.set("plugin", o.Plugin)
			if o.PluginOpts != "" {
				// Canonical schema order: the same option set
				// renders byte-identically however the import
				// link spelled it (SP3b).
				out.set("plugin_opts", engine.CanonicalSSPluginOpts(o.Plugin, o.PluginOpts))
			}
		case o.Obfs != "":
			opts := "obfs=" + o.Obfs
			if o.ObfsParam != "" {
				opts += ";obfs-host=" + o.ObfsParam
			}
			out.set("plugin", "obfs-local").set("plugin_opts", opts)
		}
	case engine.ProtocolHysteria2:
		out.set("type", "hysteria2").set("password", o.Password)
		// Bandwidth caps switch the engine from BBR to Hysteria (Brutal)
		// congestion control; zero means auto (BBR).
		if o.UpMbps > 0 {
			out["up_mbps"] = o.UpMbps
		}
		if o.DownMbps > 0 {
			out["down_mbps"] = o.DownMbps
		}
		// Port hopping: server_ports overrides server_port (sing-box
		// >= 1.11 ignores server_port when server_ports is set). The
		// plan spec is share-link spelling ("20000-30000,40000");
		// sing-box wants colon ranges with an explicit upper bound
		// ("20000:30000", "40000:40000") and rejects the plan
		// spelling at config load. SingBoxHopPorts is the single
		// translation.
		if o.HopPorts != "" {
			ports, err := engine.SingBoxHopPorts(o.HopPorts)
			if err != nil {
				return nil, fmt.Errorf("singbox: outbound %s: %w", o.ID, err)
			}
			out["server_ports"] = ports
		}
		if o.HopInterval > 0 {
			out["hop_interval"] = strconv.Itoa(o.HopInterval) + "s"
		}
		// Randomized hop interval (sing-box 1.14, Hysteria 2.8 server
		// side): hop_interval_max >= hop_interval is enforced by plan
		// validation; only a valid range reaches the render. The
		// field exists only since 1.14, above the catalog's 1.12.0
		// floor: builds the catalog honestly accepts refuse it at
		// load (`unknown field "hop_interval_max"` on 1.12.12 and
		// 1.13.21, probed — LEGACY-FULL gates). Selection therefore
		// gates such plans to sing-box builds >= 1.14
		// (FeatureHy2HopIntervalMax in BuildCapabilities); a bare
		// Render that bypasses selection still emits the field,
		// and a pre-1.14 build refuses it.
		if o.HopIntervalMax > 0 {
			out["hop_interval_max"] = strconv.Itoa(o.HopIntervalMax) + "s"
		}
		// BBR congestion profile (sing-box 1.14 bbr_profile, gated
		// exactly like hop_interval_max above —
		// FeatureHy2BBRProfile). Emitted only when BBR is actually
		// in charge: with bandwidth caps the client runs Brutal
		// instead and the profile would be dead text.
		if o.BBRProfile != "" && o.UpMbps == 0 && o.DownMbps == 0 {
			out["bbr_profile"] = o.BBRProfile
		}
		if o.Obfs != "" {
			// Hysteria2 obfs types: salamander (the Hysteria2
			// standard, spelled by every sing-box build in the
			// catalog) and gecko (sing-box 1.14 only — older
			// builds build the outbound and refuse the type,
			// `unknown obfs type: gecko`, probed). Gecko plans
			// are gated to >= 1.14 builds at selection
			// (FeatureHy2ObfsGecko); a bare Render still emits
			// the type, and a pre-1.14 build refuses it.
			out["obfs"] = obj{"type": o.Obfs, "password": o.ObfsParam}
		}
		needsTLS = true
	case engine.ProtocolTUIC:
		tuic := out.set("type", "tuic").set("uuid", o.UUID).set("password", o.Password)
		// The effective congestion controller always renders (the
		// plan value, or DefaultTUICCongestion from quic_defaults.go):
		// sing-box and mihomo then run the same controller for the
		// same plan instead of each falling back to its own default.
		tuic.set("congestion_control", o.EffectiveTUICCongestion())
		if o.UDPRelayMode != "" {
			tuic.set("udp_relay_mode", o.UDPRelayMode)
		}
		// Heartbeat (TUIC keepalive): sing-box spells it as a
		// duration string; the effective seconds come from the plan
		// or DefaultTUICHeartbeatSeconds (quic_defaults.go).
		tuic.set("heartbeat", strconv.Itoa(o.EffectiveTUICHeartbeatSeconds())+"s")
		needsTLS = true
	case engine.ProtocolAnyTLS:
		out.set("type", "anytls").set("password", o.Password)
		needsTLS = true
	case engine.ProtocolSOCKS5:
		out.set("type", "socks").set("version", "5").set("username", o.UserID).set("password", o.Password)
		return out, nil
	case engine.ProtocolHTTP:
		out.set("type", "http").set("username", o.UserID).set("password", o.Password)
	case engine.ProtocolWireGuard:
		return wireguard(out, o)
	default:
		return nil, fmt.Errorf("singbox: protocol %q is not supported", o.Protocol)
	}
	if o.TLS.Enabled || needsTLS {
		tlsObj, err := r.tls(o)
		if err != nil {
			return nil, err
		}
		out["tls"] = tlsObj
	}
	transport, err := transport(o.Transport)
	if err != nil {
		return nil, fmt.Errorf("singbox: outbound %s: %w", o.ID, err)
	}
	return out.set("transport", transport), nil
}

func (r *renderer) tls(o engine.Outbound) (obj, error) {
	t := obj{"enabled": true}
	t.set("server_name", o.TLS.ServerName).set("insecure", o.TLS.Insecure).set("alpn", o.TLS.ALPN)
	fingerprint := o.TLS.Fingerprint
	if o.TLS.Reality {
		// REALITY only works behind a uTLS fingerprint.
		fingerprint = orDefault(fingerprint, "chrome")
		reality := obj{"enabled": true, "public_key": o.TLS.RealityPublicKey}.set("short_id", o.TLS.RealityShortID)
		if o.TLS.KeyShare != "" {
			// tls.reality.key_share of the lx fork (PASS2 S3 in
			// sora), probed on the pinned lx.22 binary: "hybrid"/
			// "classical" are accepted, anything else is refused
			// at load, and a wire capture shows classical dropping
			// the X25519MLKEM768 group from the ClientHello
			// (CENSOR-FP; ported SP5-render from sora snapshot
			// 63faf1d3480d5429b6bcec3483c19c8e03defb85).
			reality["key_share"] = o.TLS.KeyShare
		}
		t["reality"] = reality
	}
	if fingerprint != "" {
		t["utls"] = obj{"enabled": true, "fingerprint": fingerprint}
	}
	if o.TLS.ECH.Enabled {
		// Without a pinned config the engine fetches the ECHConfigList
		// from the server's HTTPS DNS record. query_server_name exists
		// since sing-box 1.13, above the catalog's 1.12.0 floor: the
		// shipped payload build 1.12.12 refuses the rendered field at
		// load (`unknown field "query_server_name"`, probed —
		// LEGACY-PLAT-OBFS). Selection therefore gates such plans to
		// sing-box builds >= 1.13 (FeatureECHQueryServerName in
		// BuildCapabilities); a bare Render that bypasses selection
		// still emits the field, and a 1.12.x build refuses it.
		ech := obj{"enabled": true}
		if len(o.TLS.ECH.Config) > 0 {
			// The pinned list is canonicalized to the PEM label the
			// binary actually accepts — "ECH CONFIGS", probed on
			// lx.22: the historical "ECHCONFIG" label makes the
			// binary refuse the whole config at startup ("invalid
			// ECH configs pem", CENSOR-FP).
			pem, err := engine.ECHConfigPEM(o.TLS.ECH.Config)
			if err != nil {
				return nil, fmt.Errorf("singbox: outbound %s: %w", o.ID, err)
			}
			ech["config"] = pem
		}
		ech.set("query_server_name", o.TLS.ECH.QueryServerName)
		t["ech"] = ech
	}
	if r.plan.Options.Fragment.Enabled && o.Protocol != engine.ProtocolHysteria2 && o.Protocol != engine.ProtocolTUIC {
		// QUIC protocols have no TCP ClientHello to split.
		t["fragment"] = true
	}
	return t, nil
}

func transport(t engine.Transport) (obj, error) {
	host := func() obj {
		if t.Host == "" {
			return nil
		}
		return obj{"Host": t.Host}
	}
	switch t.Type {
	case "", "tcp":
		return nil, nil
	case "ws":
		return obj{"type": "ws"}.set("path", t.Path).set("headers", host()), nil
	case "grpc":
		return obj{"type": "grpc"}.set("service_name", t.Service), nil
	case "h2":
		out := obj{"type": "http"}.set("path", t.Path)
		if t.Host != "" {
			out["host"] = []string{t.Host}
		}
		return out, nil
	case "httpupgrade":
		return obj{"type": "httpupgrade"}.set("host", t.Host).set("path", t.Path), nil
	case "xhttp":
		out := obj{"type": "xhttp", "mode": orDefault(t.Mode, "auto")}.set("host", t.Host).set("path", t.Path)
		if len(t.Headers) > 0 {
			out["headers"] = t.Headers
		}
		// XHTTP padding and reuse tuning (S5-SP4, ported from sora):
		// the lx fork spells both (x_padding_bytes, xmux with
		// snake_case range fields, whose values accept the plan's
		// plain ints as single-value ranges), but this renderer
		// emitted neither and the values dropped at render time
		// while validation accepted them. The download split has no
		// sing-box spelling at all; FeatureXHTTPDownloadSplit keeps
		// such plans off this engine.
		out.set("x_padding_bytes", t.XPaddingBytes)
		if xmux := xhttpXmux(t); len(xmux) > 0 {
			out["xmux"] = xmux
		}
		return out, nil
	}
	return nil, fmt.Errorf("transport %q is not supported by sing-box", t.Type)
}

// xhttpXmux renders the plan's XHTTP reuse tuning in the lx fork's
// xmux spelling: snake_case fields whose values are ranges — a plain
// int is the single-value range. An untuned plan renders no block at
// all.
func xhttpXmux(t engine.Transport) obj {
	return obj{}.
		set("max_concurrency", t.XmuxMaxConcurrency).
		set("max_connections", t.XmuxMaxConnections).
		set("c_max_reuse_times", t.XmuxMaxReuseTimes).
		set("h_max_request_times", t.XmuxMaxRequestTimes)
}

// wireguard renders an endpoint: sing-box 1.13 removed the WireGuard outbound.
func wireguard(out obj, o engine.Outbound) (obj, error) {
	if len(o.Addresses) == 0 {
		return nil, fmt.Errorf("singbox: wireguard outbound %s has no interface address", o.ID)
	}
	out.set("type", "wireguard").set("address", o.Addresses).set("private_key", o.PrivateKey).set("mtu", 1420)
	if a := o.Amnezia; a != nil {
		if a.J1 != "" || a.J2 != "" || a.J3 != "" || a.Itime != 0 {
			return nil, fmt.Errorf("singbox: AmneziaWG J1/J2/J3/Itime require another engine")
		}
		out["mtu"] = 1280
		out.set("jc", a.Jc).set("jmin", a.Jmin).set("jmax", a.Jmax).
			set("s1", a.S1).set("s2", a.S2).set("s3", a.S3).set("s4", a.S4).
			set("h1", a.H1).set("h2", a.H2).set("h3", a.H3).set("h4", a.H4).
			set("i1", a.I1).set("i2", a.I2).set("i3", a.I3).set("i4", a.I4).set("i5", a.I5)
	}
	peers := make([]obj, 0, len(o.Peers))
	for _, peer := range o.Peers {
		host, portText, err := net.SplitHostPort(peer.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("singbox: wireguard outbound %s: peer endpoint: %w", o.ID, err)
		}
		port, _ := strconv.Atoi(portText)
		allowed := peer.AllowedIPs
		if len(allowed) == 0 {
			allowed = []string{"0.0.0.0/0", "::/0"}
		}
		peers = append(peers, obj{"address": host, "port": port, "public_key": peer.PublicKey, "allowed_ips": allowed}.
			set("pre_shared_key", peer.PreSharedKey).set("persistent_keepalive_interval", peer.PersistentKeepalive))
	}
	if len(peers) == 0 {
		return nil, fmt.Errorf("singbox: wireguard outbound %s has no peer", o.ID)
	}
	out["peers"] = peers
	return out, nil
}

func (r *renderer) group(g engine.Group) (obj, error) {
	members := make([]string, 0, len(g.Outbounds))
	for _, id := range g.Outbounds {
		tag, err := r.target(id)
		if err != nil {
			return nil, err
		}
		members = append(members, tag)
	}
	if len(members) == 0 {
		return nil, fmt.Errorf("singbox: group %q has no members", g.Name)
	}
	out := obj{"tag": r.tags[g.Name], "outbounds": members}
	switch g.Type {
	case engine.GroupSelect:
		out["type"] = "selector"
	case engine.GroupURLTest:
		out.set("type", "urltest").set("url", orDefault(g.URL, r.plan.Options.TestURL)).set("tolerance", g.Tolerance)
		if g.Interval > 0 {
			out["interval"] = strconv.Itoa(g.Interval) + "s"
		}
	default:
		return nil, fmt.Errorf("singbox: group type %q is not supported", g.Type)
	}
	return out, nil
}

// route orders sniffing and DNS hijacking before the unchanged plan rule order.
func (r *renderer) route() (obj, error) {
	rules := []obj{{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}}
	final := "direct"
	for _, rule := range r.plan.Rules {
		if rule.Type == engine.RuleMatchAll {
			switch rule.Target {
			case "reject", "block":
				rules = append(rules, obj{"action": "reject"})
			case "dns":
				rules = append(rules, obj{"action": "hijack-dns"})
			default:
				tag, err := r.target(rule.Target)
				if err != nil {
					return nil, err
				}
				final = tag
			}
			break
		}
		match, err := r.match(rule)
		if err != nil {
			return nil, err
		}
		switch rule.Target {
		case "reject", "block":
			match["action"] = "reject"
		case "dns":
			match["action"] = "hijack-dns"
		default:
			tag, err := r.target(rule.Target)
			if err != nil {
				return nil, err
			}
			match["action"], match["outbound"] = "route", tag
		}
		rules = append(rules, match)
	}
	r.final = final
	out := obj{"rules": rules, "final": final, "auto_detect_interface": !r.plan.Tun.Enabled || runtime.GOOS != "linux"}
	if len(r.ruleSets) > 0 {
		// Fetch rule sets through the default route to reach hosts
		// blocked on the local network.
		for _, rs := range r.ruleSets {
			rs["download_detour"] = final
		}
		out["rule_set"] = r.ruleSets
	}
	return out, nil
}

func (r *renderer) match(rule engine.Rule) (obj, error) {
	v := rule.Value
	switch rule.Type {
	case engine.RuleDomain:
		return obj{"domain": []string{v}}, nil
	case engine.RuleDomainSuffix:
		return obj{"domain_suffix": []string{v}}, nil
	case engine.RuleDomainKeyword:
		return obj{"domain_keyword": []string{v}}, nil
	case engine.RuleIPCIDR:
		return obj{"ip_cidr": []string{v}}, nil
	case engine.RulePort, engine.RuleSrcPort:
		port, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("singbox: rule %s: %q is not a port", rule.Type, v)
		}
		if rule.Type == engine.RuleSrcPort {
			return obj{"source_port": []int{port}}, nil
		}
		return obj{"port": []int{port}}, nil
	case engine.RuleProcess:
		return obj{"process_name": []string{v}}, nil
	case engine.RuleProtocol:
		return obj{"network": []string{strings.ToLower(v)}}, nil
	case engine.RuleGeoIP:
		if strings.EqualFold(v, "private") || strings.EqualFold(v, "lan") {
			return obj{"ip_is_private": true}, nil
		}
		return obj{"rule_set": []string{r.remoteRuleSet("geoip-"+strings.ToLower(v), fmt.Sprintf(geoIPRuleSetURL, strings.ToLower(v)))}}, nil
	case engine.RuleGeoSite:
		return obj{"rule_set": []string{r.remoteRuleSet("geosite-"+strings.ToLower(v), fmt.Sprintf(geoSiteRuleSetURL, strings.ToLower(v)))}}, nil
	case engine.RuleRuleSet:
		if !strings.HasPrefix(v, "https://") {
			return nil, fmt.Errorf("singbox: rule set %q must be an https URL", v)
		}
		return obj{"rule_set": []string{r.remoteRuleSet("rule-set-"+strconv.Itoa(len(r.ruleSets)+1), v)}}, nil
	}
	return nil, fmt.Errorf("singbox: rule type %q is not supported", rule.Type)
}

func (r *renderer) remoteRuleSet(tag, url string) string {
	for _, rs := range r.ruleSets {
		if rs["url"] == url {
			return rs["tag"].(string)
		}
	}
	format := "binary"
	if strings.HasSuffix(url, ".json") {
		format = "source"
	}
	r.ruleSets = append(r.ruleSets, obj{"type": "remote", "tag": tag, "format": format, "url": url})
	return tag
}

// dns uses the sing-box 1.12 server format and returns the proxy-hostname
// resolver tag. Bootstrap resolution must not pass through the proxy it
// resolves.
func (r *renderer) dns() (obj, string, error) {
	d := r.plan.DNS
	var servers, rules []obj
	direct, remote, bootstrap := "", "", ""
	byAddress := map[string]string{}
	var byHostname []obj
	for i, s := range d.Servers {
		tag := orDefault(s.Tag, "dns-"+strconv.Itoa(i+1))
		server := obj{"tag": tag}
		switch s.Transport {
		case engine.DNSSystem:
			server["type"] = "local"
		case engine.DNSFakeIP:
			continue
		case engine.DNSPlain, engine.DNSTCP, engine.DNSTLS, engine.DNSHTTPS, engine.DNSQUIC, "":
			server.set("type", orDefault(string(s.Transport), "udp")).set("server", s.Address).set("server_port", int(s.Port))
		default:
			return nil, "", fmt.Errorf("singbox: dns transport %q is not supported", s.Transport)
		}
		if s.ProxyOnly {
			// Proxy-only DNS uses the default route to keep queries
			// off the local network.
			server.set("detour", r.proxyFinal())
			if remote == "" {
				remote = tag
			}
		} else {
			if direct == "" {
				direct = tag
			}
			if bootstrap == "" && (s.Transport == engine.DNSSystem || net.ParseIP(s.Address) != nil) {
				bootstrap = tag
			}
		}
		if s.Transport != engine.DNSSystem && net.ParseIP(s.Address) == nil {
			byHostname = append(byHostname, server)
		}
		byAddress[s.Address] = tag
		servers = append(servers, server)
	}
	if bootstrap == "" {
		bootstrap = "local"
		servers = append(servers, obj{"type": "local", "tag": bootstrap})
	}
	if direct == "" {
		direct = bootstrap
	}
	// Resolver hostnames require an IP-addressed or system bootstrap
	// resolver.
	for _, server := range byHostname {
		server["domain_resolver"] = bootstrap
	}
	patterns := make([]string, 0, len(d.NameserverPolicy))
	for pattern := range d.NameserverPolicy {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	for _, pattern := range patterns {
		addresses := d.NameserverPolicy[pattern]
		if len(addresses) == 0 {
			continue
		}
		tag, ok := byAddress[addresses[0]]
		if !ok {
			return nil, "", fmt.Errorf("singbox: dns policy for %q names a server that is not in the plan", pattern)
		}
		suffix := strings.TrimPrefix(strings.TrimPrefix(pattern, "+."), "*.")
		rules = append(rules, obj{"domain_suffix": []string{suffix}, "server": tag})
	}
	if d.Mode == string(engine.DNSFakeIP) {
		servers = append(servers, obj{"type": "fakeip", "tag": "fakeip", "inet4_range": orDefault(d.FakeIPRange, "198.18.0.0/15")})
		rules = append(rules, obj{"query_type": []string{"A", "AAAA"}, "server": "fakeip"})
	}
	strategy := "ipv4_only"
	if r.plan.Options.IPv6 {
		strategy = "prefer_ipv4"
	}
	out := obj{"servers": servers, "final": orDefault(remote, direct), "strategy": strategy}.
		set("rules", rules).set("disable_cache", d.DisableCache)
	return out, bootstrap, nil
}

// proxyFinal is the default route when it leads through a proxy, or empty.
func (r *renderer) proxyFinal() string {
	if r.final == "direct" {
		return ""
	}
	return r.final
}

func tun(t engine.Tun) obj {
	return obj{
		"type": "tun", "tag": "tun-in",
		"address":      t.Addresses(),
		"auto_route":   runtime.GOOS != "linux",
		"strict_route": t.StrictRoute,
		"stack":        orDefault(t.Stack, "mixed"),
		"mtu":          orDefaultInt(t.MTU, 9000),
	}.set("interface_name", t.DeviceName).
		// Package filters apply only on Android; desktop application
		// routing uses process rules.
		set("include_package", t.IncludeApps).set("exclude_package", t.ExcludeApps)
}

func logConfig(level string) obj {
	switch level {
	case "silent":
		return obj{"disabled": true}
	case "warning":
		level = "warn"
	case "":
		level = "warn"
	}
	return obj{"level": level, "timestamp": false}
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func orDefaultInt(v, fallback int) int {
	if v == 0 {
		return fallback
	}
	return v
}
