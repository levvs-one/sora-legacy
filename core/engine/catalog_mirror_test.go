package engine_test

// Catalog <-> renderer mirror pin (final pass 3).
//
// engine.Catalog is the claim every selection decision reads: a
// protocol or feature listed there routes plans to that engine. The
// renderers are the fact: if a claimed protocol does not render, the
// claim is decorative and a plan can be selected onto an engine that
// then fails — the exact failure the catalog exists to prevent.
// Until now the two were joined only by per-feature tests written
// when a feature landed; nothing swept the whole claim surface.
//
// This test sweeps it: for every engine kind, every protocol the
// static catalog claims must render through that engine's renderer
// from the canonical enginetest plan, every protocol another engine
// claims but this one does not must be refused by selection
// (Catalog.Missing via SelectEngine), and every engine claiming
// FeatureECH must actually emit its ECH spelling for an ECH plan.
//
// Version-gated claims (BuildCapabilities: the sing-box lx fork,
// 1.13/1.14 spellings) are deliberately not swept here: they are not
// static-catalog claims, and their gates carry their own binary-probe
// tests (catalog_ech_qsn_test.go, catalog_hy2_114_test.go).

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/enginetest"
	"github.com/levvs-one/sora-client/core/engine/mihomo"
	"github.com/levvs-one/sora-client/core/engine/singbox"
	"github.com/levvs-one/sora-client/core/engine/supervise"
	"github.com/levvs-one/sora-client/core/engine/xray"
)

var mirrorRuntime = supervise.Runtime{
	LocalPort:   7890,
	ControlAddr: "127.0.0.1:9090",
	ProbeURL:    engine.TestURLProduction,
}

func mirrorRender(kind engine.Kind, p *engine.Plan) (string, error) {
	switch kind {
	case engine.KindSingBox:
		raw, err := singbox.Render(p, mirrorRuntime)
		return string(raw), err
	case engine.KindXray:
		raw, err := xray.Render(p, mirrorRuntime, nil)
		return string(raw), err
	case engine.KindMihomo:
		return mihomo.Render(p, mihomo.Runtime{
			ControllerAddr: "127.0.0.1:9090",
			Secret:         "mirror",
			MixedPort:      7890,
			TestURL:        engine.TestURLProduction,
		})
	}
	return "", errors.New("unknown engine kind")
}

// mirrorPlan builds the canonical one-outbound plan for a protocol,
// reduced to the protocol itself: the enginetest outbound bundles
// optional extras that are separate catalog Features (the Hysteria2
// outbound carries salamander obfs), and a protocol claim must not
// fail because an unclaimed feature rides along — feature claims
// have their own gates, and the reduction below only ever strips a
// field whose feature this engine does not claim. Xray profiles run
// alone by plan law, so they get the minimal profile plan shape the
// xray package's own tests use.
func mirrorPlan(t *testing.T, kind engine.Kind, proto engine.Protocol) *engine.Plan {
	t.Helper()
	if proto == engine.ProtocolXrayProfile {
		profile := `{"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"192.0.2.10","port":443,"users":[{"id":"123e4567-e89b-12d3-a456-426614174000","encryption":"none"}]}]}},{"tag":"direct","protocol":"freedom"}]}`
		rawProfile := json.RawMessage(profile)
		return &engine.Plan{
			SessionID:  "catalog-mirror",
			Outbounds:  []engine.Outbound{{ID: "p", Name: "profile", Protocol: engine.ProtocolXrayProfile, Server: "192.0.2.10", Port: 443, Profile: &rawProfile}},
			LocalProxy: engine.LocalProxy{Enabled: true},
			Options:    engine.Options{LogLevel: "warning", TestURL: engine.TestURLProduction},
		}
	}
	p := enginetest.Plan(proto)
	if caps := engine.Catalog[kind]; !caps.Features[engine.FeatureHy2Obfs] {
		for i := range p.Outbounds {
			p.Outbounds[i].ObfsBox().Type, p.Outbounds[i].ObfsBox().Param = "", ""
		}
	}
	return p
}

func claimedProtocols() map[engine.Kind]map[engine.Protocol]bool {
	out := map[engine.Kind]map[engine.Protocol]bool{}
	for kind, caps := range engine.Catalog {
		set := map[engine.Protocol]bool{}
		for p := range caps.Protocols {
			set[p] = true
		}
		out[kind] = set
	}
	return out
}

func TestCatalogMirrorClaimedProtocolsRender(t *testing.T) {
	for kind, claimed := range claimedProtocols() {
		for proto := range claimed {
			t.Run(string(kind)+"/"+string(proto), func(t *testing.T) {
				out, err := mirrorRender(kind, mirrorPlan(t, kind, proto))
				if err != nil {
					t.Fatalf("catalog claims %s for %s, but its renderer refuses the canonical plan: %v", proto, kind, err)
				}
				if len(out) == 0 {
					t.Fatalf("catalog claims %s for %s, but the renderer produced nothing", proto, kind)
				}
			})
		}
	}
}

func TestCatalogMirrorUnclaimedProtocolsAreRefusedBySelection(t *testing.T) {
	claims := claimedProtocols()
	union := map[engine.Protocol]bool{}
	for _, set := range claims {
		for p := range set {
			union[p] = true
		}
	}
	for kind, claimed := range claims {
		caps := engine.Catalog[kind]
		version, err := engine.ParseVersion(caps.MinVersion)
		if err != nil {
			t.Fatalf("%s: catalog MinVersion %q does not parse: %v", kind, caps.MinVersion, err)
		}
		avail := []engine.Availability{{Kind: kind, Path: "/nonexistent", Version: version, Usable: true}}
		for proto := range union {
			if claimed[proto] {
				continue
			}
			t.Run(string(kind)+"/not-"+string(proto), func(t *testing.T) {
				if _, err := engine.SelectEngine(mirrorPlan(t, kind, proto), avail, []engine.Kind{kind}); err == nil {
					t.Fatalf("catalog does not claim %s for %s, but selection routed the plan there", proto, kind)
				}
			})
		}
		// And the claimed direction of selection: every claimed
		// protocol must also pass selection (not only rendering).
		for proto := range claimed {
			t.Run(string(kind)+"/selects-"+string(proto), func(t *testing.T) {
				if _, err := engine.SelectEngine(mirrorPlan(t, kind, proto), avail, []engine.Kind{kind}); err != nil {
					t.Fatalf("catalog claims %s for %s, but selection refuses the canonical plan: %v", proto, kind, err)
				}
			})
		}
	}
}

func TestCatalogMirrorECHClaimRenders(t *testing.T) {
	markers := map[engine.Kind]string{
		engine.KindSingBox: `"ech"`,
		engine.KindXray:    `echConfigList`,
		engine.KindMihomo:  `ech-opts:`,
	}
	for kind, caps := range engine.Catalog {
		if !caps.Features[engine.FeatureECH] {
			continue
		}
		t.Run(string(kind), func(t *testing.T) {
			p := enginetest.Plan(engine.ProtocolTrojan)
			p.Outbounds[0].TLS.ECH = &engine.ECHConfig{
				Enabled: true,
				Config:  []string{"AE7+DQA8NwAgACBwaW5uZWQtZWNoLXRlc3QtY29uZmln"},
			}
			out, err := mirrorRender(kind, p)
			if err != nil {
				t.Fatalf("catalog claims FeatureECH for %s, but its renderer refuses an ECH plan: %v", kind, err)
			}
			if !strings.Contains(out, markers[kind]) {
				t.Fatalf("catalog claims FeatureECH for %s, but the render carries no %s spelling:\n%s", kind, markers[kind], out)
			}
		})
	}
}
