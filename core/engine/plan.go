package engine

import (
	"encoding/json"
	"net/netip"
)

// Limits mirror the sora.core.v1 contract. A plan that exceeds them is
// rejected before any engine sees it.
const (
	MaxOutbounds      = 5000
	MaxGroups         = 500
	MaxRules          = 10000
	MaxIDLen          = 128
	MaxNameBytes      = 256
	MaxHeaderCount    = 32
	MaxDNSServers     = 32
	TestURLProduction = "https://www.gstatic.com/generate_204"
)

// Protocol is an outbound protocol name as used in plans.
type Protocol string

// Outbound protocols a plan may hold, named as the control plane names them.
const (
	ProtocolVLESS       Protocol = "vless"
	ProtocolVMess       Protocol = "vmess"
	ProtocolTrojan      Protocol = "trojan"
	ProtocolShadowsocks Protocol = "shadowsocks"
	ProtocolHysteria2   Protocol = "hysteria2"
	ProtocolTUIC        Protocol = "tuic"
	ProtocolWireGuard   Protocol = "wireguard"
	ProtocolSOCKS5      Protocol = "socks5"
	ProtocolHTTP        Protocol = "http"
	ProtocolAnyTLS      Protocol = "anytls"
	// ProtocolBypass reshapes direct TLS and HTTP handshakes with zapret to
	// evade DPI. It requires no server.
	ProtocolBypass Protocol = "bypass"
	// ProtocolXrayProfile runs a provider's full Xray configuration within
	// the session, preserving outbounds, balancers, and routing. Only Xray
	// supports it.
	ProtocolXrayProfile Protocol = "xray-profile"
	ProtocolDirect      Protocol = "direct"
)

// GroupType is how the engine chooses between the members of a group.
type GroupType string

// Strategies the engine uses to pick a member of a group.
const (
	GroupSelect      GroupType = "select"
	GroupURLTest     GroupType = "url-test"
	GroupFallback    GroupType = "fallback"
	GroupLoadBalance GroupType = "load-balance"
)

// ECHConfig holds Encrypted Client Hello (RFC 9849) parameters of an
// outbound. The zero value disables ECH.
type ECHConfig struct {
	// Enabled turns ECH on. Without a pinned Config the engine fetches
	// the ECHConfigList from the server's HTTPS DNS record, so a working
	// (ideally encrypted) DNS path is required for the bootstrap.
	Enabled bool
	// Config pins PEM-encoded ECHConfigList lines, skipping the DNS
	// lookup. Useful where encrypted DNS itself is blocked.
	Config []string
	// QueryServerName overrides the domain used for the ECH DNS query.
	// Rendered by sing-box (ech.query_server_name, available since
	// 1.13 — above the shipped payload build 1.12.12, which refuses
	// the field at load; selection gates it via
	// FeatureECHQueryServerName) and by mihomo
	// (ech-opts.query-server-name). The Xray renderer spells ECH
	// itself but has no query-name spelling and refuses the override
	// at render; see FeatureECH. (SP5-render, from sora snapshot
	// 63faf1d — whose own comment here is stale and still says the
	// Xray renderer does not emit ECH at all.)
	QueryServerName string
}

// RealitySettings holds the REALITY parameters of an outbound's TLS.
// Boxed behind a pointer on TLS: most outbounds run plain TLS, so the
// four strings cost nothing in a plan until REALITY is configured.
type RealitySettings struct {
	// PublicKey and the other REALITY parameters are public but masked
	// because they identify a server.
	PublicKey string
	ShortID   string
	SpiderX   string
	// KeyShare selects the key share the REALITY ClientHello offers:
	// "" leaves the engine default, "classical" offers X25519 only,
	// "hybrid" offers the X25519MLKEM768 hybrid. REALITY servers on
	// Xray >= 26.9.8 accept only the hybrid share, so against them
	// "classical" (or a default that omits the hybrid) fails the
	// handshake with an opaque verification error. Rendered by
	// mihomo (support-x25519mlkem768) and by the sing-box lx fork
	// (tls.reality.key_share); RequiredFeatures demands
	// FeatureRealityKeyShare, which upstream sing-box and Xray do
	// not claim, so on those builds a plan setting it fails engine
	// selection instead of silently losing the choice (S5-SP5,
	// SP5-render).
	KeyShare string
}

// TLS holds transport security parameters of an outbound.
type TLS struct {
	Enabled     bool
	ServerName  string
	ALPN        []string
	Fingerprint string
	// ECH enables Encrypted Client Hello. Opt-in only: some censors drop
	// ClientHellos carrying the ECH extension, so it must never default on.
	// Boxed: a nil ECH is a disabled ECH.
	ECH      *ECHConfig
	Insecure bool
	// Reality holds the REALITY parameters; nil is plain TLS.
	Reality *RealitySettings
}

// ECHOrZero returns the ECH configuration, or its zero (disabled)
// value when none is boxed.
func (t TLS) ECHOrZero() ECHConfig {
	if t.ECH == nil {
		return ECHConfig{}
	}
	return *t.ECH
}

// ECHBox returns the boxed ECH configuration, allocating it first
// when the outbound carries none.
func (t *TLS) ECHBox() *ECHConfig {
	if t.ECH == nil {
		t.ECH = &ECHConfig{}
	}
	return t.ECH
}

// RealityOrZero returns the REALITY parameters, or their zero value
// when the outbound runs plain TLS.
func (t TLS) RealityOrZero() RealitySettings {
	if t.Reality == nil {
		return RealitySettings{}
	}
	return *t.Reality
}

// RealityBox returns the boxed REALITY parameters, allocating them
// first when the outbound carries none.
func (t *TLS) RealityBox() *RealitySettings {
	if t.Reality == nil {
		t.Reality = &RealitySettings{}
	}
	return t.Reality
}

// XHTTPSettings holds the XHTTP-only stream tuning of an outbound:
// the stream mode, the split download leg, connection reuse (xmux)
// and the padding range. Boxed behind a pointer on Transport: the
// fields are rejected on every other transport, so a plain TCP or
// WebSocket outbound pays nothing for them in a plan.
type XHTTPSettings struct {
	// Mode is the XHTTP mode: auto, packet-up, stream-up or stream-one.
	Mode string
	// DownloadAddress and DownloadPort split the XHTTP downlink onto a
	// separate server, so uplink and downlink can ride different domains.
	// Both must be set together; the fields are ignored by other
	// transports and rejected there by the engines.
	DownloadAddress string
	DownloadPort    uint16
	// Xmux tunes XHTTP connection reuse. MaxConcurrency (streams per
	// connection) and MaxConnections are mutually exclusive. Zero keeps
	// the engine default. Every renderer emits the tuning: mihomo as
	// reuse-settings, Xray as xmux, sing-box-lx as xmux — gated by
	// FeatureXHTTPXmux so a plan carrying it never routes to an engine
	// that would drop it silently (S5-SP4, ported from sora).
	XmuxMaxConcurrency  int
	XmuxMaxConnections  int
	XmuxMaxReuseTimes   int
	XmuxMaxRequestTimes int
	// XPaddingBytes is the random XHTTP padding range, "min-max" or a
	// single number, e.g. "100-1000". Every renderer emits it —
	// mihomo as x-padding-bytes, Xray as xPaddingBytes, sing-box-lx as
	// x_padding_bytes — under its own capability (FeatureXHTTPPadding),
	// split from the xmux gate: padding and reuse tuning are
	// independent plan data (S5-SP4, ported from sora).
	XPaddingBytes string
}

// Transport holds the stream transport of an outbound.
type Transport struct {
	// Type is tcp, ws, grpc, h2, httpupgrade or xhttp.
	Type    string
	Path    string
	Host    string
	Service string
	Headers map[string]string
	// XHTTP holds the XHTTP-only tuning; nil on other transports.
	XHTTP *XHTTPSettings
}

// XHTTPOrZero returns the XHTTP tuning, or its zero value when the
// transport carries none.
func (t Transport) XHTTPOrZero() XHTTPSettings {
	if t.XHTTP == nil {
		return XHTTPSettings{}
	}
	return *t.XHTTP
}

// XHTTPBox returns the boxed XHTTP tuning, allocating it first when
// the transport carries none.
func (t *Transport) XHTTPBox() *XHTTPSettings {
	if t.XHTTP == nil {
		t.XHTTP = &XHTTPSettings{}
	}
	return t.XHTTP
}

// WireGuardPeer is one WireGuard peer of an outbound.
type WireGuardPeer struct {
	PublicKey           string
	PreSharedKey        string
	Endpoint            string
	AllowedIPs          []string
	PersistentKeepalive int
}

// Outbound is one server the plan can route traffic through.
type Outbound struct {
	ID   string
	Name string

	Protocol  Protocol
	Transport Transport
	TLS       TLS
	// SOCKSUDP enables UDP on a SOCKS5 peer known to support associations.
	SOCKSUDP bool

	Server string
	Port   uint16

	// UUID and the following credential fields must be masked in logs and
	// events.
	UUID     string
	Password string
	Cipher   string
	UserID   string
	Flow     string
	// Obfs holds the wire-obfuscation settings; nil is a plain
	// connection (see ObfsSettings).
	Obfs      *ObfsSettings
	PublicKey string
	ShortID   string
	// Encryption configures VLESS. Empty or "none" disables it; other
	// values use Xray's post-quantum VLESS Encryption.
	Encryption string
	// QUIC holds the Hysteria2/TUIC tuning; nil for every other
	// protocol (see QUICSettings).
	QUIC *QUICSettings

	// WireGuard holds the WireGuard interface material; nil for
	// every other protocol (see WireGuardSettings).
	WireGuard *WireGuardSettings
	// Amnezia turns a WireGuard outbound into AmneziaWG. Nil is plain
	// WireGuard.
	Amnezia *AmneziaWG
	// Bypass is the strategy of a bypass outbound.
	Bypass *BypassStrategy
	// Profile contains a provider's Xray configuration and credentials, so
	// the entire value is secret. Boxed: only xray-profile outbounds
	// carry one, and a profile document is large.
	Profile *json.RawMessage
}

// QUICSettings holds the Hysteria2 and TUIC tuning of an outbound.
// Both protocols ride QUIC and share the congestion vocabulary; the
// group is boxed behind a pointer on Outbound because TCP-based
// protocols — the bulk of every plan — never fill a single field.
type QUICSettings struct {
	// UpMbps and DownMbps are the client's Hysteria2 bandwidth caps in
	// Mbps (from upmbps/downmbps in the import link). Positive values
	// switch sing-box and mihomo from BBR to Hysteria (Brutal) congestion
	// control; zero means auto (BBR).
	UpMbps   int
	DownMbps int
	// HopPorts is the Hysteria2 port-hopping spec, e.g.
	// "20000-30000,40000" (from mport/ports in the import link). Empty
	// keeps the single Port.
	HopPorts string
	// HopInterval is the Hysteria2 port hop interval in seconds. Zero
	// keeps the engine default (30s); the protocol requires at least 5s.
	HopInterval int
	// HopIntervalMax is the randomized upper bound of the port hop
	// interval in seconds (sing-box 1.14 hop_interval_max; Hysteria
	// 2.8's randomized hop interval). Zero keeps a fixed HopInterval.
	// Only sing-box >= 1.14 spells the field — above the catalog's
	// 1.12.0 floor — so RequiredFeatures demands
	// FeatureHy2HopIntervalMax and selection refuses the plan by
	// name on older builds and on engines with no spelling, instead
	// of the build refusing the rendered config at load.
	HopIntervalMax int
	// BBRProfile selects the sing-box 1.14 Hysteria2 BBR congestion
	// profile: "standard", "conservative" or "aggressive". Empty keeps
	// the engine default. It applies only while BBR is in charge (no
	// bandwidth caps — caps switch the client to Brutal). Like
	// HopIntervalMax it exists only since sing-box 1.14, so
	// RequiredFeatures demands FeatureHy2BBRProfile (same gate).
	BBRProfile string
	// CongestionControl selects the TUIC QUIC congestion controller:
	// "bbr" (default), "cubic" or "new_reno". Unknown values are rejected.
	CongestionControl string
	// UDPRelayMode selects the TUIC UDP relay mode: "native" (default)
	// or "quic".
	UDPRelayMode string
	// TUICHeartbeat is the TUIC heartbeat (keepalive) interval in
	// seconds. Zero keeps DefaultTUICHeartbeatSeconds (see
	// quic_defaults.go); renderers emit the effective value on both
	// TUIC engines (sing-box heartbeat duration, mihomo
	// heartbeat-interval in milliseconds) so a session's keepalive
	// never depends on which engine carries it.
	TUICHeartbeat int
	// Token is the TUIC v4 pre-shared token; v5 authenticates with
	// UUID+Password. Like the other credential fields, it must be masked
	// in logs and events.
	Token string
}

// WireGuardSettings holds the WireGuard interface material of an
// outbound: the interface key, addresses and peers. Boxed behind a
// pointer on Outbound: only wireguard outbounds carry any of it.
type WireGuardSettings struct {
	// PrivateKey is the interface private key. Like the other
	// credential fields, it must be masked in logs and events.
	PrivateKey string
	Peers      []WireGuardPeer
	// Addresses lists WireGuard interface CIDRs, required for the tunnel to
	// carry traffic.
	Addresses []string
}

// QUICOrZero returns the QUIC tuning, or its zero value when the
// outbound carries none.
func (o Outbound) QUICOrZero() QUICSettings {
	if o.QUIC == nil {
		return QUICSettings{}
	}
	return *o.QUIC
}

// QUICBox returns the boxed QUIC tuning, allocating it first when
// the outbound carries none.
func (o *Outbound) QUICBox() *QUICSettings {
	if o.QUIC == nil {
		o.QUIC = &QUICSettings{}
	}
	return o.QUIC
}

// WireGuardOrZero returns the WireGuard material, or its zero value
// when the outbound carries none.
func (o Outbound) WireGuardOrZero() WireGuardSettings {
	if o.WireGuard == nil {
		return WireGuardSettings{}
	}
	return *o.WireGuard
}

// WireGuardBox returns the boxed WireGuard material, allocating it
// first when the outbound carries none.
func (o *Outbound) WireGuardBox() *WireGuardSettings {
	if o.WireGuard == nil {
		o.WireGuard = &WireGuardSettings{}
	}
	return o.WireGuard
}

// ObfsSettings holds the wire obfuscation of an outbound: the
// simple-obfs mode of Shadowsocks and the obfs of Hysteria2 (the
// Type/Param pair), and the Shadowsocks SIP002 plugin selection.
// Boxed behind a pointer on Outbound: most protocols run plain and
// never fill a field, so the four strings cost nothing in a plan
// until obfuscation is configured.
type ObfsSettings struct {
	// Type is the obfuscation type: a simple-obfs mode ("http" or
	// "tls") for Shadowsocks, or a Hysteria2 obfs ("salamander" or
	// "gecko").
	Type string
	// Param is the obfuscation parameter: the simple-obfs host, or
	// the Hysteria2 obfs password. Like the other credential fields,
	// it must be masked in logs and events.
	Param string
	// Plugin and PluginOpts carry a Shadowsocks SIP002 obfuscation
	// plugin (e.g. v2ray-plugin) and its raw option string, verbatim
	// from the import link. When set, Plugin wins over the legacy
	// Type/Param obfs-local mapping. Like the other credential
	// fields, PluginOpts must be masked in logs and events.
	Plugin     string
	PluginOpts string
}

// ObfsOrZero returns the obfuscation settings, or their zero value
// when the outbound runs plain.
func (o Outbound) ObfsOrZero() ObfsSettings {
	if o.Obfs == nil {
		return ObfsSettings{}
	}
	return *o.Obfs
}

// ObfsBox returns the boxed obfuscation settings, allocating them
// first when the outbound carries none.
func (o *Outbound) ObfsBox() *ObfsSettings {
	if o.Obfs == nil {
		o.Obfs = &ObfsSettings{}
	}
	return o.Obfs
}

// ProfileBytes returns the Xray profile document, or nil when the
// outbound carries none.
func (o Outbound) ProfileBytes() json.RawMessage {
	if o.Profile == nil {
		return nil
	}
	return *o.Profile
}

// Group is a user-selectable set of outbounds.
type Group struct {
	Name      string
	Type      GroupType
	Outbounds []string
	URL       string
	Interval  int
	Tolerance int
	Lazy      bool
	Hidden    bool
	Icon      string
	Provider  string
}

// RuleType is a rule matcher as named in the sora.core.v1 contract.
type RuleType string

// Rule matchers a plan may carry.
const (
	RuleDomain        RuleType = "domain"
	RuleDomainSuffix  RuleType = "domain-suffix"
	RuleDomainKeyword RuleType = "domain-keyword"
	RuleIPCIDR        RuleType = "ip-cidr"
	RuleIPSuffix      RuleType = "ip-suffix"
	RuleGeoIP         RuleType = "geoip"
	RuleGeoSite       RuleType = "geosite"
	RuleRuleSet       RuleType = "rule-set"
	RulePort          RuleType = "port"
	RuleSrcPort       RuleType = "src-port"
	RuleProcess       RuleType = "process"
	RuleProtocol      RuleType = "protocol"
	RuleMatchAll      RuleType = "all"
)

// Rule routes a matching destination to an outbound or a group.
type Rule struct {
	Type      RuleType
	Value     string
	Target    string
	NoResolve bool
}

// DNSTransport is how a DNS server is reached.
type DNSTransport string

// Transports a DNS server of the plan can be reached by.
const (
	DNSPlain  DNSTransport = "udp"
	DNSTCP    DNSTransport = "tcp"
	DNSTLS    DNSTransport = "tls"
	DNSHTTPS  DNSTransport = "https"
	DNSQUIC   DNSTransport = "quic"
	DNSSystem DNSTransport = "system"
	DNSFakeIP DNSTransport = "fakeip"
)

// DNSServer is one resolver of the plan.
type DNSServer struct {
	Tag       string
	Transport DNSTransport
	Address   string
	Port      uint16
	// Dialer names the outbound used to reach this resolver ("direct" or an
	// outbound ID). The mihomo renderer honors it (dialer-proxy, rendered
	// as a "#<name>" suffix on the resolver address). It is set in the
	// tree: the xraytun bridge rewrites every non-"direct" dialer of the
	// tunneled plan to its bridge outbound (xraytun/bridge.go), and
	// renderers/tests set it directly.
	Dialer    string
	ProxyOnly bool
}

// DNS is the resolver setup of the plan.
type DNS struct {
	Enabled          bool
	Mode             string // rule, fakeip, redir-host
	FakeIPRange      string
	Servers          []DNSServer
	NameserverPolicy map[string][]string
	DisableCache     bool
	Sniff            bool
	HijackTun        []string
}

// TunDevice names Sora's adapter to avoid collisions and allow startup checks.
const TunDevice = "sora0"

// Tun is the virtual network interface setup of the plan.
type Tun struct {
	IPv4             netip.Prefix
	IPv6             netip.Prefix
	Enabled          bool
	Stack            string // system, gvisor, mixed, mips (mihomo or Xray bridge)
	DeviceName       string
	MTU              int
	StrictRoute      bool
	AutoRoute        bool
	RouteAddressSets []string
	IncludeApps      []string
	ExcludeApps      []string
}

// AmneziaWG holds configuration-file obfuscation parameters that must match the
// server. Zero values are omitted to retain engine defaults.
type AmneziaWG struct {
	Jc, Jmin, Jmax int
	S1, S2, S3, S4 int
	// H1..H4 are message type headers: a number, or a range in AmneziaWG
	// 2.0.
	H1, H2, H3, H4 string
	// I1..I5 are the signature packets of AmneziaWG 1.5 and 2.0.
	I1, I2, I3, I4, I5 string
	J1, J2, J3         string
	Itime              int
}

// BypassStrategy defines zapret handshake shaping. Positions are byte offsets,
// negative from the end, or markers (method, host, endhost, sld, midsld,
// endsld, sniext) with optional +N or -N.
type BypassStrategy struct {
	SplitPos []string
	// Disorder sends the second part of a split first.
	Disorder bool
	// DisorderScope limits disorder to one protocol: "" (both), "http" or
	// "tls". Needs Disorder.
	DisorderScope string
	// OOB sends an out-of-band byte with the split.
	OOB bool
	// OOBScope limits the out-of-band byte to one protocol: "" (both),
	// "http" or "tls". Needs OOB.
	OOBScope string
	// TLSRecord splits the ClientHello into two TLS records at a position.
	TLSRecord string
	// HostCase reshapes HTTP header casing; DomainCase and MethodEOL also
	// reshape plain HTTP requests.
	HostCase   bool
	DomainCase bool
	MethodEOL  bool
	// HostDot adds "." after the Host: name; HostTab and HostNoSpace
	// reshape the space after Host:; MethodSpace adds an extra space
	// after the HTTP method; UnixEOL replaces CRLF with LF in plain
	// HTTP requests.
	HostDot     bool
	HostTab     bool
	HostNoSpace bool
	MethodSpace bool
	UnixEOL     bool
	// SplitAnyProtocol splits every protocol, not only HTTP and TLS.
	SplitAnyProtocol bool
}

// Fragment splits proxy TLS ClientHello messages across TCP segments to evade
// SNI matching on a single segment.
type Fragment struct {
	Enabled bool
	// Packets selects Xray segments ("tlshello" or "1-3"); Length sets
	// bytes ("100-200") and Interval sets milliseconds ("10-20"). Engines
	// with only a switch use Enabled.
	Packets  string
	Length   string
	Interval string
}

// Options configures engine-wide plan settings.
type Options struct {
	LogLevel    string
	Mode        string // rule, global, direct
	FindProcess bool
	GeoData     bool
	AllowLAN    bool
	IPv6        bool
	TestURL     string
	GeoSiteURL  string
	GeoIPURL    string
	Fragment    Fragment
}

// LocalProxy opens a loopback HTTP/SOCKS5 listener only for system proxy mode
// or explicit requests. Other local applications can use it and discover the
// upstream server address.
type LocalProxy struct {
	Enabled bool
	// Username and Password restrict the listener to authenticated
	// applications. System proxies cannot supply a login.
	Username string
	Password string
}

// Plan is a complete, engine-independent description of one session.
type Plan struct {
	SessionID string
	// Engines is the engine preference of this session, best first. Empty
	// uses the core default; a single entry pins that engine.
	Engines []Kind
	// PrivateControl requires Unix sockets, named pipes, or no controller,
	// preventing discovery through listening network ports.
	PrivateControl bool
	LocalProxy     LocalProxy

	Outbounds []Outbound
	Groups    []Group
	Rules     []Rule
	DNS       DNS
	Tun       Tun
	Options   Options
}
