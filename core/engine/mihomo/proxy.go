package mihomo

import (
	"fmt"
	"maps"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"

	"github.com/levvs-one/sora-client/core/engine"
)

// buildProxy converts an outbound to a mihomo proxy. The caller sets its name
// to ensure plan-wide uniqueness.
func buildProxy(o engine.Outbound) (proxy, error) {
	udp := o.Protocol != engine.ProtocolHTTP && (o.Protocol != engine.ProtocolSOCKS5 || o.SOCKSUDP)
	px := proxy{Type: "ss", Tag: o.ID, UDP: &udp, IPVer: "dual"}
	q := o.QUICOrZero()
	ob := o.ObfsOrZero()
	wg := o.WireGuardOrZero()
	// WireGuard uses its peer's server address.
	if o.Server == "" && o.Protocol != engine.ProtocolWireGuard {
		return proxy{}, fmt.Errorf("mihomo: outbound %s has no server", o.ID)
	}
	px.Server = o.Server
	px.Port = int(o.Port)

	switch o.Protocol {
	case engine.ProtocolShadowsocks:
		px.Type = "ss"
		px.Cipher = orDefault(o.Cipher, "aes-256-gcm")
		px.Password = o.Password
		if ob.Plugin != "" {
			// An explicit SIP002 plugin goes through mihomo's plugin
			// path; the legacy Obfs mapping below stays for the native
			// simple-obfs fields. The plugin NAME must be translated:
			// mihomo's adapter matches its own spellings ("obfs", not
			// the SIP002 binary name "obfs-local"; "restls", not
			// "restls-plugin") and silently ignores any other name —
			// the outbound would run unobfuscated (SP3b, read from the
			// pinned adapter/outbound/shadowsocks.go).
			spec := engine.SSPluginByName(ob.Plugin)
			if spec == nil || !engine.SupportsSSPlugin(engine.KindMihomo, ob.Plugin) {
				return proxy{}, fmt.Errorf("mihomo: shadowsocks outbound %s uses plugin %q, which mihomo does not implement", o.ID, ob.Plugin)
			}
			px.SSPlugin = spec.MihomoName
			if px.SSPlugin == "" {
				px.SSPlugin = spec.Name
			}
			if opts := ssPluginOpts(ob.Plugin, ob.PluginOpts); len(opts) > 0 {
				px.SSPluginOpts = opts
			}
		} else if ob.Type != "" {
			px.Obfs = ob.Type
			px.ObfsParam = ob.Param
		}
	case engine.ProtocolVMess:
		px.Type = "vmess"
		px.UUID = o.UUID
		px.AlterID = new(int)
		px.Cipher = orDefault(o.Cipher, "auto")
	case engine.ProtocolVLESS:
		px.Type = "vless"
		px.UUID = o.UUID
		px.Flow = o.Flow
		px.Encryption = o.Encryption
	case engine.ProtocolTrojan:
		px.Type = "trojan"
		px.Password = o.Password
	case engine.ProtocolHysteria2:
		px.Type = "hysteria2"
		px.Password = o.Password
		if ob.Type != "" {
			px.Obfs = ob.Type
			px.ObfsPassword = ob.Param
		}
		// Bandwidth caps switch the engine from BBR to Brutal congestion
		// control; zero means auto.
		if q.UpMbps > 0 {
			px.Up = strconv.Itoa(q.UpMbps) + " Mbps"
		}
		if q.DownMbps > 0 {
			px.Down = strconv.Itoa(q.DownMbps) + " Mbps"
		}
		if q.HopPorts != "" {
			px.Ports = q.HopPorts
		}
		if q.HopInterval > 0 {
			px.HopInterval = q.HopInterval
		}
	case engine.ProtocolTUIC:
		px.Type = "tuic"
		px.UUID = o.UUID
		px.Password = o.Password
		// v4 servers authenticate with a token instead of uuid+password.
		if q.Token != "" {
			px.Token = q.Token
		}
		// The effective congestion controller always renders (the
		// plan value, or DefaultTUICCongestion): mihomo silently
		// accepts an omitted or unknown controller and falls back
		// to its own default, so spelling the effective value is
		// what keeps a plan's controller identical across engines.
		px.CongestionController = o.EffectiveTUICCongestion()
		if q.UDPRelayMode != "" {
			px.UDPRelayMode = q.UDPRelayMode
		}
		// TUIC heartbeat in mihomo's spelling: milliseconds.
		px.HeartbeatInterval = o.EffectiveTUICHeartbeatSeconds() * 1000
	case engine.ProtocolAnyTLS:
		// AnyTLS mandates TLS on the wire; the plan carries the SNI and
		// the uTLS client fingerprint in TLS. Stream transports do not
		// apply to it.
		px.Type = "anytls"
		px.Password = o.Password
		if err := applyTLS(&px, o); err != nil {
			return proxy{}, err
		}
		tls := true
		px.TLS = &tls
		return px, nil
	case engine.ProtocolWireGuard:
		px.Type = "wireguard"
		px.PrivateKey = wg.PrivateKey
		px.MTU = 1420
		for _, address := range wg.Addresses {
			prefix, err := netip.ParsePrefix(address)
			if err != nil {
				return proxy{}, fmt.Errorf("mihomo: wireguard outbound %s: address %q: %w", o.ID, address, err)
			}
			if prefix.Addr().Is4() && px.IP == "" {
				px.IP = prefix.Addr().String()
			} else if prefix.Addr().Is6() && px.IPv6 == "" {
				px.IPv6 = prefix.Addr().String()
			}
		}
		if px.IP == "" && px.IPv6 == "" {
			return proxy{}, fmt.Errorf("mihomo: wireguard outbound %s has no interface address", o.ID)
		}
		if o.Amnezia != nil {
			px.Amnezia = amneziaOptions(o.Amnezia)
		}
		peers, err := wireguardPeers(o)
		if err != nil {
			return proxy{}, err
		}
		// mihomo stores a single peer on the proxy and multiple peers
		// in the peers list.
		if len(peers) == 1 {
			p := peers[0]
			px.Server, px.Port = p.Server, p.Port
			px.PublicKey, px.PreSharedKey, px.AllowedIPs = p.PublicKey, p.PreSharedKey, p.AllowedIPs
			px.PersistentKeepalive = p.PersistentKeepalive
		} else {
			px.Peers = peers
		}

	case engine.ProtocolSOCKS5, engine.ProtocolHTTP:
		px.Type = "socks5"
		if o.Protocol == engine.ProtocolHTTP {
			px.Type = "http"
		}
		px.Username = o.UserID
		px.Password = o.Password
		// HTTPS proxies require TLS to avoid sending credentials in
		// cleartext.
		if err := applyTLS(&px, o); err != nil {
			return proxy{}, err
		}
		return px, nil
	default:
		return proxy{}, fmt.Errorf("mihomo: protocol %q is not supported", o.Protocol)
	}

	if err := applyTransport(&px, o.Transport); err != nil {
		return proxy{}, err
	}
	if err := applyTLS(&px, o); err != nil {
		return proxy{}, err
	}
	return px, nil
}

// applyTransport writes the nested options of the stream transport.
func applyTransport(px *proxy, t engine.Transport) error {
	x := t.XHTTPOrZero()
	headers := maps.Clone(t.Headers)
	if t.Host != "" && t.Type != "h2" && t.Type != "xhttp" {
		if headers == nil {
			headers = map[string]string{}
		}
		headers["Host"] = t.Host
	}
	switch t.Type {
	case "", "tcp", "raw":
		px.Network = "tcp"
	case "ws":
		px.Network = "ws"
		px.WSOpts = &wsOpts{Path: t.Path, Headers: headers}
	case "httpupgrade":
		// mihomo carries HTTPUpgrade as a flavour of its websocket
		// transport.
		px.Network = "ws"
		px.WSOpts = &wsOpts{Path: t.Path, Headers: headers, V2RayHTTPUpgrade: true}
	case "grpc":
		px.Network = "grpc"
		px.GRPCOpts = &grpcOpts{ServiceName: t.Service}
	case "h2":
		px.Network = "h2"
		px.H2Opts = &h2Opts{Path: t.Path}
		if t.Host != "" {
			px.H2Opts.Host = []string{t.Host}
		}
	case "xhttp":
		px.Network = "xhttp"
		// Mode passes through verbatim: the pinned docs list "auto"
		// among the available mode values, so a plan's explicit auto
		// is legal here, not a leak (S5-SP4, ported from sora).
		opts := &xhttpOpts{Path: t.Path, Host: t.Host, Mode: x.Mode, Headers: maps.Clone(t.Headers),
			XPaddingBytes: x.XPaddingBytes, ReuseSettings: xhttpReuseSettings(t)}
		if x.DownloadAddress != "" {
			opts.DownloadSettings = &xhttpDownload{
				Server: x.DownloadAddress, Port: int(x.DownloadPort),
				ReuseSettings: xhttpReuseSettings(t),
			}
		}
		px.XHTTPOpts = opts
	default:
		return fmt.Errorf("mihomo: transport %q is not supported", t.Type)
	}
	return nil
}

// xhttpReuseSettings renders reuse-settings (XMUX) from the plan's
// xmux tuning. Unlike the original Xray implementation, mihomo's
// reuse-settings has NO default value: omitting the block disables
// connection reuse entirely — every request opens a new underlying
// connection (pinned docs, transport configuration). The block is
// therefore always emitted: the plan's tuning when the plan carries
// it, otherwise the docs' example default (max-concurrency "16-32")
// so the mihomo path reuses connections like the other engines
// instead of paying a fresh TCP+TLS handshake per request. The
// default is only used when the plan tunes nothing: max-concurrency
// conflicts with max-connections, so a tuned plan must never grow a
// default concurrency on top of its connections (S5-SP4, ported
// from sora).
func xhttpReuseSettings(t engine.Transport) *xhttpReuse {
	x := t.XHTTPOrZero()
	r := &xhttpReuse{}
	if x.XmuxMaxConcurrency > 0 {
		r.MaxConcurrency = strconv.Itoa(x.XmuxMaxConcurrency)
	}
	if x.XmuxMaxConnections > 0 {
		r.MaxConnections = strconv.Itoa(x.XmuxMaxConnections)
	}
	if x.XmuxMaxReuseTimes > 0 {
		r.CMaxReuseTimes = strconv.Itoa(x.XmuxMaxReuseTimes)
	}
	if x.XmuxMaxRequestTimes > 0 {
		r.HMaxRequestTimes = strconv.Itoa(x.XmuxMaxRequestTimes)
	}
	if r.MaxConcurrency == "" && r.MaxConnections == "" && r.CMaxReuseTimes == "" && r.HMaxRequestTimes == "" {
		r.MaxConcurrency = "16-32"
	}
	return r
}

func wireguardPeers(o engine.Outbound) ([]wireguardPeer, error) {
	wg := o.WireGuardOrZero()
	if len(wg.Peers) == 0 {
		return nil, fmt.Errorf("mihomo: wireguard outbound %s has no peer", o.ID)
	}
	out := make([]wireguardPeer, 0, len(wg.Peers))
	for _, peer := range wg.Peers {
		host, portText, err := net.SplitHostPort(peer.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("mihomo: wireguard outbound %s: peer endpoint: %w", o.ID, err)
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return nil, fmt.Errorf("mihomo: wireguard outbound %s: peer port %q", o.ID, portText)
		}
		out = append(out, wireguardPeer{
			Server: host, Port: port, PublicKey: peer.PublicKey, PreSharedKey: peer.PreSharedKey,
			AllowedIPs: peer.AllowedIPs, PersistentKeepalive: peer.PersistentKeepalive,
		})
	}
	return out, nil
}

// amneziaOptions renders amnezia-wg-option keys. Numeric headers stay numbers
// for 1.x; 2.0 also accepts ranges.
func amneziaOptions(a *engine.AmneziaWG) map[string]any {
	out := map[string]any{}
	ints := map[string]int{"jc": a.Jc, "jmin": a.Jmin, "jmax": a.Jmax, "s1": a.S1, "s2": a.S2, "s3": a.S3, "s4": a.S4, "itime": a.Itime}
	for key, v := range ints {
		if v != 0 {
			out[key] = v
		}
	}
	strs := map[string]string{"h1": a.H1, "h2": a.H2, "h3": a.H3, "h4": a.H4,
		"i1": a.I1, "i2": a.I2, "i3": a.I3, "i4": a.I4, "i5": a.I5, "j1": a.J1, "j2": a.J2, "j3": a.J3}
	for key, v := range strs {
		if v == "" {
			continue
		}
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && strings.HasPrefix(key, "h") {
			out[key] = n
			continue
		}
		out[key] = v
	}
	return out
}

// applyTLS writes TLS, SNI, ALPN, uTLS fingerprint and Reality parameters.
func applyTLS(px *proxy, o engine.Outbound) error {
	rs := o.TLS.RealityOrZero()
	ech := o.TLS.ECHOrZero()
	if o.Protocol == engine.ProtocolWireGuard {
		return nil
	}
	enabled := o.TLS.Enabled
	switch o.Protocol {
	case engine.ProtocolTrojan, engine.ProtocolHysteria2, engine.ProtocolTUIC:
		enabled = true
	}
	px.TLS = &enabled
	if o.TLS.ServerName != "" {
		px.SNI = o.TLS.ServerName
	}
	if len(o.TLS.ALPN) > 0 {
		px.ALPN = o.TLS.ALPN
	}
	if ech.Enabled {
		cfg, err := mihomoECHConfig(ech.Config)
		if err != nil {
			return err
		}
		px.ECH = &echOpts{Enable: true, Config: cfg, QueryServerName: ech.QueryServerName}
	}
	if o.TLS.Insecure {
		skip := true
		px.SkipCertVerify = &skip
	}
	if o.TLS.Reality != nil {
		if rs.PublicKey == "" {
			return fmt.Errorf("mihomo: outbound %s uses reality without a public key", o.ID)
		}
		// REALITY only works behind a uTLS fingerprint; default to chrome
		// like the sing-box and Xray renderers do.
		px.Fingerprint = orDefault(o.TLS.Fingerprint, "chrome")
		px.Reality = &reality{PublicKey: rs.PublicKey, ShortID: rs.ShortID}
		// PASS3 deep S2 in sora: the plan's REALITY key-share knob,
		// third leg of PASS2 S3. hybrid -> support-x25519mlkem768:
		// true, classical -> false explicitly; unset leaves the key
		// out. The unset default is MEASURED in the reference, not
		// just undocumented: a wire capture against the pinned
		// 1.19.32 binary shows the default ClientHello carrying NO
		// X25519MLKEM768 group (a ~590-byte hello vs ~1780 with the
		// hybrid), so "" honestly means "mihomo's default, which
		// offers no hybrid" (CENSOR-FP; ported SP5-render from sora
		// snapshot 63faf1d3480d5429b6bcec3483c19c8e03defb85).
		switch rs.KeyShare {
		case "hybrid":
			v := true
			px.Reality.SupportMLKEM768 = &v
		case "classical":
			v := false
			px.Reality.SupportMLKEM768 = &v
		}
	} else if o.TLS.Fingerprint != "" {
		px.Fingerprint = o.TLS.Fingerprint
	}
	return nil
}

// mihomoECHConfig converts the plan's pinned ECHConfigList to the
// ech-opts.config spelling: one base64 string. The conversion itself
// is the shared engine helper (echconfig.go): strip any armor, verify
// the body is one base64 ECHConfigList, re-encode canonically. More
// than one PEM block cannot be merged into mihomo's single config
// value — each block is a complete ECHConfigList — so that shape
// fails closed here with the mihomo context attached.
func mihomoECHConfig(lines []string) (string, error) {
	if len(lines) == 0 {
		return "", nil
	}
	out, err := engine.ECHConfigListBase64(lines)
	if err != nil {
		return "", fmt.Errorf("mihomo: %w", err)
	}
	return out, nil
}

// ssPluginOpts translates a SIP002 plugin option string ("k=v;k;flag")
// into mihomo's plugin-opts map. obfs-local and v2ray-plugin get their
// native key names; anything else passes through generically and mihomo
// validates it (fail-closed on unknown plugins — buildProxy refuses a
// plugin the catalog does not carry on mihomo before this is called).
func ssPluginOpts(plugin, opts string) map[string]any {
	raw := map[string]string{}
	for _, part := range strings.Split(opts, ";") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		raw[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	switch plugin {
	case "obfs-local":
		// simple-obfs: "obfs=tls;obfs-host=example.com".
		out := map[string]any{}
		if m, ok := raw["obfs"]; ok {
			out["mode"] = m
		}
		if h, ok := raw["obfs-host"]; ok {
			out["host"] = h
		}
		return out
	case "v2ray-plugin", "gost-plugin":
		// gost-plugin's mihomo option shape mirrors v2ray-plugin's
		// (its adapter decodes the same fields and likewise requires
		// mode "websocket"); without the shared case it fell into the
		// generic passthrough and never got the mandatory mode.
		out := map[string]any{"mode": "websocket"}
		for k, v := range raw {
			switch k {
			case "tls", "mux":
				// Bare flags mean enabled; explicit values parse as bool.
				out[k] = v == "" || v == "1" || strings.EqualFold(v, "true")
			default:
				out[k] = v
			}
		}
		return out
	default:
		out := map[string]any{}
		for k, v := range raw {
			out[k] = v
		}
		return out
	}
}

// sanitizeName removes unsafe display-name characters. Commas, slashes, and
// controls can alter mihomo rules or break name-based URLs.
func sanitizeName(name, fallback string) string {
	src := name
	if src == "" {
		src = fallback
	}
	var b strings.Builder
	for _, r := range src {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('_')
		}
		if b.Len() > 96 {
			break
		}
	}
	out := strings.Trim(b.String(), "-_.")
	if out == "" {
		out = "server"
	}
	return out
}

// uniqueName appends a counter until the name is free.
func uniqueName(name string, used map[string]struct{}) string {
	candidate := name
	for i := 2; ; i++ {
		if _, taken := used[candidate]; !taken {
			used[candidate] = struct{}{}
			return candidate
		}
		candidate = fmt.Sprintf("%s-%d", name, i)
	}
}

func orDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func orDefaultInt(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}
