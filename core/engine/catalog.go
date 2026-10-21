package engine

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
)

// Availability describes an engine build found on this machine.
type Availability struct {
	Kind      Kind
	Path      string
	Version   Version
	Usable    bool
	Reason    string
	BuildTags []string
}

// Catalog holds upstream engine capabilities, separate from installed
// Availability. Entries were validated with mihomo v1.19.32 (-t), sing-box
// v1.14.3 (check), and Xray v26.3.27 (run -test).
var Catalog = map[Kind]Capabilities{
	KindMihomo: {
		Kind:       KindMihomo,
		MinVersion: "1.19.0",
		Protocols: map[Protocol]bool{
			ProtocolVLESS: true, ProtocolVMess: true, ProtocolTrojan: true,
			ProtocolShadowsocks: true, ProtocolHysteria2: true, ProtocolTUIC: true,
			ProtocolWireGuard: true, ProtocolSOCKS5: true, ProtocolHTTP: true,
			ProtocolAnyTLS: true, ProtocolDirect: true,
		},
		Features: map[Feature]bool{
			FeatureTun: true, FeatureFakeIP: true, FeatureRuleSets: true,
			FeatureProxyProviders: true, FeatureURLTest: true, FeatureLatencyTest: true,
			FeatureHotApply: true, FeatureGeoData: true, FeatureFallbackGroup: true,
			FeatureLoadBalance: true, FeatureXHTTP: true, FeatureVLESSEncrypt: true,
			FeatureXHTTPDownloadSplit: true, FeatureXHTTPXmux: true, FeatureXHTTPPadding: true, FeatureRealityKeyShare: true,
			FeatureAmneziaWG: true, FeaturePrivateControl: true, FeatureECH: true,
			FeatureECHQueryServerName: true,
			FeatureHy2PortHop:         true, FeatureHy2Obfs: true,
		},
	},
	KindSingBox: {
		Kind: KindSingBox,
		// The renderer requires DNS and rule-action formats added in
		// 1.12; 1.14 removes the legacy formats.
		MinVersion: "1.12.0",
		Protocols: map[Protocol]bool{
			ProtocolVLESS: true, ProtocolVMess: true, ProtocolTrojan: true,
			ProtocolShadowsocks: true, ProtocolHysteria2: true, ProtocolTUIC: true,
			ProtocolWireGuard: true, ProtocolSOCKS5: true, ProtocolHTTP: true,
			ProtocolAnyTLS: true, ProtocolDirect: true,
		},
		Features: map[Feature]bool{
			FeatureTun: true, FeatureFakeIP: true, FeatureRuleSets: true,
			FeatureURLTest: true, FeatureLatencyTest: true, FeatureGeoData: true,
			FeaturePerAppRouting: true, FeatureTLSFragment: true, FeatureECH: true,
			// Deliberately no static FeatureECHQueryServerName:
			// ech.query_server_name exists only since sing-box
			// 1.13, above this entry's 1.12.0 floor — the shipped
			// payload build 1.12.12 refuses the rendered field at
			// load (probed, LEGACY-PLAT-OBFS). The claim is
			// version-gated in BuildCapabilities.
			FeatureHy2PortHop: true, FeatureHy2Obfs: true,
			// Deliberately no static FeatureRealityKeyShare: the
			// key_share spelling is the lx fork's (probed on lx.22
			// in sora, whose shipped pin IS the fork); legacy ships
			// upstream 1.14.3, which has no such field and refuses
			// unknown keys at load. The claim rides the lx build in
			// BuildCapabilities, exactly like FeatureXHTTP
			// (SP5-render; a deliberate divergence from the
			// reference's static claim, driven by the shipped pin).
			// Deliberately no FeatureXHTTPDownloadSplit: the lx
			// fork's xhttp transport has no download_settings field
			// at all. Its xmux and x_padding_bytes claims ride the
			// lx build in BuildCapabilities, exactly like
			// FeatureXHTTP itself — upstream sing-box spells
			// neither, so the static entry claims neither (S5-SP4).
		},
	},
	KindXray: {
		Kind: KindXray,
		// The minimum version is the shipped build verified for
		// Hysteria2, XHTTP, and VLESS Encryption.
		MinVersion: "26.3.27",
		Protocols: map[Protocol]bool{
			ProtocolVLESS: true, ProtocolVMess: true, ProtocolTrojan: true,
			ProtocolShadowsocks: true, ProtocolHysteria2: true, ProtocolWireGuard: true,
			ProtocolSOCKS5: true, ProtocolHTTP: true, ProtocolDirect: true, ProtocolXrayProfile: true,
		},
		Features: map[Feature]bool{
			// Xray TUN does not install routes; engine/tunroute
			// supplies them on supported platforms (see
			// catalog_*.go).
			FeatureURLTest: true, FeatureLoadBalance: true, FeatureLatencyTest: true,
			FeatureGeoData: true, FeatureTLSFragment: true,
			FeatureXHTTP: true, FeatureVLESSEncrypt: true, FeaturePrivateControl: true,
			FeatureXHTTPDownloadSplit: true, FeatureXHTTPXmux: true, FeatureXHTTPPadding: true,
			// FeatureECH is claimed as of the SP5-render port (from
			// sora snapshot 63faf1d, where the CENSOR-FP wire probe
			// on 26.10.17 showed the outer SNI becoming the pinned
			// list's public_name): the renderer emits echConfigList
			// and echForceQuery. Legacy's shipped pin is 26.3.27 —
			// the same floor the reference claims from — but the
			// wire probe was not re-run on 26.3.27 here.
			FeatureECH: true,
			// Deliberately no FeatureHy2PortHop: Xray's hysteria2
			// outbound cannot hop ports (see FeatureHy2PortHop).
			// Deliberately no FeatureHy2Obfs: Xray's hysteria
			// transport exposes no obfs option (see FeatureHy2Obfs).
			// Deliberately no FeatureRealityKeyShare: Xray has no
			// key-share knob — the chosen parrot decides whether the
			// hybrid group is offered — so a plan pinning the choice
			// reports it missing here instead of losing it silently,
			// and the renderer refuses it as a backstop (29d9cc4).
		},
	},
}

// BuildCapabilities keeps upstream and downstream builds distinct. A version
// suffix alone cannot prove that an optional transport was compiled in.
func BuildCapabilities(kind Kind, version Version, tags []string) Capabilities {
	caps := Catalog[kind]
	if kind == KindSingBox && !version.Less(Version{Major: 1, Minor: 13}) {
		// ech.query_server_name was added in sing-box 1.13; the
		// static entry's floor (1.12.0, the shipped payload build
		// 1.12.12) refuses the field at load, so the claim exists
		// only here, on a build new enough to spell it.
		caps.Features = maps.Clone(caps.Features)
		caps.Features[FeatureECHQueryServerName] = true
	}
	if kind == KindSingBox && strings.HasPrefix(version.PreRelease, "lx.") &&
		!version.Less(Version{Major: 1, Minor: 14, Patch: 3}) {
		caps.Features = maps.Clone(caps.Features)
		caps.Features[FeatureXHTTP] = slices.Contains(tags, "with_xhttp")
		// The lx XHTTP transport also spells xmux and
		// x_padding_bytes; they exist exactly when the with_xhttp
		// build does, so they share its claim. There is no
		// download_settings spelling on any sing-box build, so
		// FeatureXHTTPDownloadSplit is never claimed here (S5-SP4).
		caps.Features[FeatureXHTTPXmux] = caps.Features[FeatureXHTTP]
		caps.Features[FeatureXHTTPPadding] = caps.Features[FeatureXHTTP]
		// The lx fork's REALITY spells key_share (probed on the
		// pinned lx.22 binary in sora); upstream sing-box — legacy's
		// shipped pin — has no such field, so the claim exists only
		// here, on the fork build, not in the static entry
		// (SP5-render).
		caps.Features[FeatureRealityKeyShare] = true
		caps.Features[FeatureVLESSEncrypt] = true
		caps.Features[FeatureAmneziaWG] = slices.Contains(tags, "with_awg")
	}
	return caps
}

// DefaultPreference tries sing-box for low memory use, cross-platform TUN, and
// native Android support, then Xray for XHTTP and VLESS Encryption, then mihomo
// for fallback groups, providers, and routing.
var DefaultPreference = []Kind{KindSingBox, KindXray, KindMihomo}

// PrivatePreference prioritizes controllers inaccessible to other programs.
// mihomo retains counters and connection tracking over a private socket; Xray
// runs without a controller.
var PrivatePreference = []Kind{KindSingBox, KindMihomo, KindXray}

// ErrNoEngine reports that no available engine carries an outbound or a plan.
var ErrNoEngine = errors.New("engine: no available engine carries this")

// Selection is the engine chosen for a plan.
type Selection struct {
	Kind   Kind
	Reason string
	// Rejected lists skipped engines in preference order so clients can
	// explain selection failures.
	Rejected []string
}

// SelectEngine chooses the first available engine supporting the whole plan. It
// returns rejection reasons and missing capabilities for clients.
func SelectEngine(p *Plan, available []Availability, preference []Kind) (Selection, error) {
	if p == nil {
		return Selection{}, fmt.Errorf("engine: nil plan")
	}
	if len(p.Outbounds) == 0 {
		return Selection{}, fmt.Errorf("engine: plan has no outbounds")
	}
	byKind := make(map[Kind]Availability, len(available))
	for _, a := range available {
		byKind[a.Kind] = a
	}
	var rejected []string
	for _, kind := range preference {
		avail, ok := byKind[kind]
		if !ok || !avail.Usable {
			why := "not installed"
			if ok && avail.Reason != "" {
				why = avail.Reason
			}
			rejected = append(rejected, string(kind)+": "+why)
			continue
		}
		caps, ok := Catalog[kind]
		if !ok {
			rejected = append(rejected, string(kind)+": no capability matrix")
			continue
		}
		caps = BuildCapabilities(kind, avail.Version, avail.BuildTags)
		if lowest, err := ParseVersion(caps.MinVersion); err == nil && avail.Version.Less(lowest) {
			rejected = append(rejected, fmt.Sprintf("%s: version %s is older than %s", kind, avail.Version, caps.MinVersion))
			continue
		}
		missing := caps.Missing(p)
		if len(missing) > 0 {
			rejected = append(rejected, fmt.Sprintf("%s: cannot carry %s", kind, strings.Join(missing, ", ")))
			continue
		}
		return Selection{
			Kind:     kind,
			Reason:   fmt.Sprintf("%s carries %d outbounds and %d groups", kind, len(p.Outbounds), len(p.Groups)),
			Rejected: rejected,
		}, nil
	}
	return Selection{Rejected: rejected}, fmt.Errorf("engine: no engine can carry this plan (%s)", strings.Join(rejected, "; "))
}

// Missing returns sorted protocols and features the engine cannot support.
// Empty means the whole plan is supported.
func (c Capabilities) Missing(p *Plan) []string {
	var missing []string
	if p.Tun.Enabled && p.Tun.Stack != "" {
		if (c.Kind == KindXray && p.Tun.Stack != "gvisor") || (c.Kind == KindSingBox && p.Tun.Stack == "mips") {
			missing = append(missing, "TUN stack "+p.Tun.Stack)
		}
	}
	if c.Kind == KindXray {
		for _, o := range p.Outbounds {
			if o.TLS.Insecure && !o.TLS.Reality && (o.TLS.Enabled || o.Protocol == ProtocolTrojan || o.Protocol == ProtocolHysteria2) {
				missing = append(missing, "TLS verification disabled (removed by Xray)")
				break
			}
		}
	}
	if c.Kind == KindSingBox {
		for _, o := range p.Outbounds {
			if a := o.Amnezia; a != nil && (a.J1 != "" || a.J2 != "" || a.J3 != "" || a.Itime != 0) {
				missing = append(missing, "AmneziaWG J1/J2/J3/Itime parameters")
				break
			}
		}
	}
	if c.Kind == KindSingBox || c.Kind == KindMihomo {
		// Only Xray implements REALITY spider_x; the other engines have
		// no such option and would silently drop it.
		for _, o := range p.Outbounds {
			if o.TLS.SpiderX != "" {
				missing = append(missing, "REALITY spider_x")
				break
			}
		}
	}
	// Shadowsocks plugin support is per-engine measured data
	// (ss_plugin.go), not a protocol-level claim: a plan whose plugin
	// this engine's pinned build does not carry must not be routed
	// here — the engine would refuse the config at load or, worse,
	// silently run without the plugin (SP3b).
	for _, o := range p.Outbounds {
		if o.Protocol != ProtocolShadowsocks {
			continue
		}
		if o.Plugin != "" && !SupportsSSPlugin(c.Kind, o.Plugin) {
			missing = append(missing, "shadowsocks plugin "+o.Plugin)
			break
		}
		if o.Plugin == "" && o.Obfs != "" && !SupportsSSPlugin(c.Kind, "") {
			missing = append(missing, "shadowsocks obfs (simple-obfs)")
			break
		}
	}
	for proto := range p.Protocols() {
		if !c.SupportsProtocol(proto) {
			missing = append(missing, "protocol "+string(proto))
		}
	}
	for f := range p.RequiredFeatures() {
		if !c.Supports(f) {
			missing = append(missing, "feature "+string(f))
		}
	}
	sort.Strings(missing)
	return missing
}
