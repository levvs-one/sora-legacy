// Package engine defines the plan-based boundary for mihomo, sing-box, and
// Xray. Callers avoid engine-specific configuration and select engines by
// advertised protocols and features.
package engine

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Kind identifies a forwarding engine implementation.
type Kind string

// The engines Sora can run.
const (
	KindMihomo  Kind = "mihomo"
	KindSingBox Kind = "sing-box"
	KindXray    Kind = "xray"
)

// Feature is a capability the control plane may require from an engine.
type Feature string

// Features are provided according to the capability matrix in catalog.go.
const (
	FeatureTun            Feature = "tun"
	FeatureFakeIP         Feature = "fake-ip"
	FeatureRuleSets       Feature = "rule-sets"
	FeatureProxyProviders Feature = "proxy-providers"
	FeatureURLTest        Feature = "url-test"
	FeatureLatencyTest    Feature = "latency-test"
	FeatureHotApply       Feature = "hot-apply"
	FeatureGeoData        Feature = "geodata"
	FeaturePerAppRouting  Feature = "per-app-routing"
	FeatureFallbackGroup  Feature = "fallback-group"
	FeatureLoadBalance    Feature = "load-balance"
	FeatureTLSFragment    Feature = "tls-fragment"
	FeatureXHTTP          Feature = "xhttp"
	// FeatureXHTTPDownloadSplit marks engines that can split the XHTTP
	// downlink onto a separate server. Xray (downloadSettings) and
	// mihomo (download-settings) claim it; sing-box (including the lx
	// fork) has no such option: routing a split plan to it would
	// silently send downloads over the uplink server (S5-SP4, ported
	// from sora).
	FeatureXHTTPDownloadSplit Feature = "xhttp-download-split"
	// FeatureXHTTPXmux marks engines that honour XHTTP connection-reuse
	// tuning. All three engines claim it: mihomo renders
	// reuse-settings, Xray renders xmux, sing-box-lx renders xmux. A
	// claim belongs in a catalog entry only together with a renderer
	// that emits the tuning (S5-SP4, ported from sora).
	FeatureXHTTPXmux Feature = "xhttp-xmux"
	// FeatureXHTTPPadding marks engines that honour the XHTTP padding
	// range (Transport.XPaddingBytes). It is a separate feature from
	// FeatureXHTTPXmux because the fields are independent plan data: a
	// padding-only plan must not demand xmux support, and an xmux-only
	// plan must not demand padding (S5-SP4, ported from sora).
	FeatureXHTTPPadding Feature = "xhttp-padding"
	// FeatureECH marks engines whose renderer actually emits Encrypted
	// Client Hello for an outbound that enables it: sing-box (ech
	// block with canonical PEM config and query_server_name), mihomo
	// (ech-opts with pinned config and query-server-name) and Xray
	// (echConfigList + echForceQuery; a query_server_name override
	// has no Xray spelling and is refused at render). All three claim
	// it since the SP5-render port (from sora snapshot 63faf1d,
	// CENSOR-FP); before that no legacy engine claimed it and an ECH
	// plan failed selection instead of sending the SNI in the clear
	// while promising it hidden (S5-SP5).
	FeatureECH Feature = "ech"
	// FeatureECHQueryServerName marks engines whose ECH spelling
	// carries a query_server_name override (ECHConfig.QueryServerName):
	// sing-box since 1.13 (tls.ech.query_server_name — probed absent
	// on the shipped payload sing-box 1.12.12: the rendered config
	// fails its check with `unknown field "query_server_name"`,
	// LEGACY-PLAT-OBFS) and mihomo (ech-opts.query-server-name).
	// The sing-box claim is version-gated in BuildCapabilities, not
	// static: the static floor is 1.12.0, which loads no such field.
	// Xray claims it nowhere: it has no query-name spelling, so a
	// plan setting one fails selection there instead of reaching the
	// renderer, whose refusal stays as a backstop.
	FeatureECHQueryServerName Feature = "ech-query-server-name"
	// FeatureRealityKeyShare marks engines whose renderer can spell
	// the plan's REALITY key-share choice (RealitySettings.KeyShare): mihomo
	// (support-x25519mlkem768) and the sing-box lx fork
	// (tls.reality.key_share, claimed in BuildCapabilities — legacy
	// ships upstream sing-box, which has no such field). Xray claims
	// it nowhere: it has no key-share knob, so a plan setting
	// KeyShare fails selection there instead of silently losing the
	// choice, and its renderer refuses the pin as a backstop
	// (S5-SP5, SP5-render).
	FeatureRealityKeyShare Feature = "reality-key-share"
	FeatureVLESSEncrypt    Feature = "vless-encryption"
	// FeatureHy2PortHop marks engines whose Hysteria2 outbound supports
	// port hopping (sing-box server_ports, mihomo ports). Xray's hysteria2
	// outbound has no port-hopping support, so a hopping plan must never
	// be routed to it: hopping rendered nowhere would silently pin the
	// client to one port.
	FeatureHy2PortHop Feature = "hy2-port-hop"
	// FeatureHy2Obfs marks engines whose Hysteria2 outbound implements
	// obfuscation (salamander/gecko): sing-box and mihomo do, Xray's
	// hysteria transport exposes no obfs option and its renderer
	// refuses the field. Without the gate an obfuscated plan routed
	// to Xray failed only at render time, after selection had promised
	// it could run.
	FeatureHy2Obfs Feature = "hy2-obfs"
	// FeatureHy2HopIntervalMax marks engines whose Hysteria2 spelling
	// carries a randomized hop interval upper bound
	// (QUICSettings.HopIntervalMax): sing-box renders hop_interval_max
	// only since 1.14 — the option structs of 1.12.25 and 1.13.21 have
	// no such field, and their binaries refuse the rendered config at
	// load (`unknown field "hop_interval_max"`), while 1.14.3 accepts
	// it (all probed with `sing-box check` on the release binaries,
	// LEGACY-FULL gates). The sing-box claim is version-gated in
	// BuildCapabilities, not static: the static floor is 1.12.0.
	// Mihomo and Xray claim it nowhere: neither renderer emits the
	// bound, so a plan pinning one fails selection there instead of
	// silently collapsing to a fixed hop interval.
	FeatureHy2HopIntervalMax Feature = "hy2-hop-interval-max"
	// FeatureHy2BBRProfile marks engines whose Hysteria2 spelling
	// carries a BBR congestion profile (QUICSettings.BBRProfile):
	// sing-box renders bbr_profile only since 1.14 — absent from the
	// 1.12.25/1.13.21 option structs, refused by their binaries at
	// load (`unknown field "bbr_profile"`), accepted by 1.14.3
	// (probed as above). The sing-box claim is version-gated in
	// BuildCapabilities; mihomo and Xray have no profile spelling
	// and claim it nowhere, so a plan pinning a profile fails
	// selection there instead of silently running the engine
	// default.
	FeatureHy2BBRProfile Feature = "hy2-bbr-profile"
	// FeatureHy2ObfsGecko marks engines whose Hysteria2 obfs
	// implements the gecko type (ObfsSettings.Type == "gecko"), the
	// Hysteria 2.9.2 obfuscation sing-box spells only since 1.14:
	// older sing-box builds accept the obfs block at decode (the
	// type is a free string there) and then refuse it when the
	// outbound is built (`unknown obfs type: gecko` at load, probed
	// on 1.12.12 and 1.13.21; 1.14.3 accepts). The sing-box claim is
	// version-gated in BuildCapabilities. Mihomo claims it
	// statically: its renderer passes the obfs type through and the
	// shipped pin 1.19.32 accepts gecko while rejecting an unknown
	// type (`mihomo -t`, probed with a bogus-type control). Xray
	// claims it nowhere: it implements no Hysteria2 obfs at all
	// (see FeatureHy2Obfs).
	FeatureHy2ObfsGecko   Feature = "hy2-obfs-gecko"
	FeatureAmneziaWG      Feature = "amneziawg"
	FeaturePrivateControl Feature = "private-control"
)

// Capabilities describes the protocols and features supported by an engine
// build.
type Capabilities struct {
	Kind       Kind
	MinVersion string
	Protocols  map[Protocol]bool
	Features   map[Feature]bool
}

// SupportsProtocol reports whether the engine can build an outbound for p.
func (c Capabilities) SupportsProtocol(p Protocol) bool { return c.Protocols[p] }

// Supports reports whether the engine provides f.
func (c Capabilities) Supports(f Feature) bool { return c.Features[f] }

// State describes a managed engine instance.
type State string

// Stopped and Failed are terminal until the engine is started again.
const (
	StateIdle       State = "idle"
	StateStarting   State = "starting"
	StateRunning    State = "running"
	StateApplying   State = "applying"
	StateRecovering State = "recovering"
	StateStopping   State = "stopping"
	StateStopped    State = "stopped"
	StateFailed     State = "failed"
)

// Version is a parsed engine version.
type Version struct {
	Raw        string
	Major      int
	Minor      int
	Patch      int
	PreRelease string
}

// Less reports whether v sorts before other.
func (v Version) Less(other Version) bool {
	if v.Major != other.Major {
		return v.Major < other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor < other.Minor
	}
	return v.Patch < other.Patch
}

func (v Version) String() string { return v.Raw }

// ParseVersion accepts "1.19.32", "v1.19.32" and "v1.19.32-beta.3".
func ParseVersion(raw string) (Version, error) {
	s := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "v"))
	if s == "" {
		return Version{}, fmt.Errorf("engine: empty version")
	}
	pre := ""
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		pre, s = s[i+1:], s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("engine: malformed version %q", raw)
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return Version{}, fmt.Errorf("engine: malformed version %q", raw)
		}
		nums[i] = n
	}
	return Version{
		Raw: strings.TrimSpace(raw), Major: nums[0], Minor: nums[1], Patch: nums[2], PreRelease: pre,
	}, nil
}

// Engine manages a forwarding process. Apply is idempotent and converges to the
// requested plan while minimizing traffic interruptions.
type Engine interface {
	Kind() Kind
	Capabilities() Capabilities
	State() State
	Version() Version

	// Validate reports every problem that would stop this plan from
	// running.
	Validate(ctx context.Context, p *Plan) error
	// Apply starts the engine or moves a running engine to the given plan.
	Apply(ctx context.Context, p *Plan) error
	// Stop shuts the engine down and removes it from the system.
	Stop(ctx context.Context) error
	// Close releases all resources. Close is safe to call after Stop.
	Close() error

	// Groups returns the selectable groups with their live state.
	Groups(ctx context.Context) ([]GroupStatus, error)
	// Select pins target inside a selectable group.
	Select(ctx context.Context, group, target string) error
	// Delay measures one proxy through the engine.
	Delay(ctx context.Context, name, url string, timeout time.Duration) (time.Duration, error)
	// Counters returns traffic counters of the running session.
	Counters(ctx context.Context) (Counters, error)

	// Events returns the engine event bus.
	Events() *EventBus
}
