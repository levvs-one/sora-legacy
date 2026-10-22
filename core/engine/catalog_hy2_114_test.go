package engine

import (
	"slices"
	"strings"
	"testing"
)

// TestHy2SingBox114Gates is the catalog side of the LEGACY-FULL
// gates fix: the sing-box renderer emits three Hysteria2 spellings
// that exist only since sing-box 1.14 — hop_interval_max,
// bbr_profile and the gecko obfs type — while the static sing-box
// floor is 1.12.0. Builds the catalog honestly accepts refuse such
// renders at load (1.12.12 and 1.13.21 probed with `sing-box check`:
// `unknown field "hop_interval_max"`, `unknown field
// "bbr_profile"`, `unknown obfs type: gecko`; 1.14.3 accepts all
// three; the binary side is pinned in the singbox package). A plan
// pinning any of the three must therefore require its own feature
// and be carried exactly by the builds that spell it: sing-box
// >= 1.14 (BuildCapabilities claims), mihomo only for gecko (its
// renderer passes the obfs type through and the shipped pin
// 1.19.32 accepts it, probed with `mihomo -t`), Xray for none.
func TestHy2SingBox114Gates(t *testing.T) {
	cases := []struct {
		name    string
		feature Feature
		mut     func(*Outbound)
	}{
		{"hop_interval_max", FeatureHy2HopIntervalMax, func(o *Outbound) {
			o.QUICBox().HopPorts, o.QUICBox().HopInterval, o.QUICBox().HopIntervalMax = "20000-30000", 30, 90
		}},
		{"bbr_profile", FeatureHy2BBRProfile, func(o *Outbound) {
			o.QUICBox().BBRProfile = "conservative"
		}},
		{"gecko obfs", FeatureHy2ObfsGecko, func(o *Outbound) {
			o.ObfsBox().Type, o.ObfsBox().Param = "gecko", "gecko-secret"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			missingName := "feature " + string(c.feature)

			plain := &Plan{SessionID: "s1", Outbounds: []Outbound{hy2Outbound()}}
			if plain.RequiredFeatures()[c.feature] {
				t.Fatalf("a plain hysteria2 plan must not require %s", c.feature)
			}

			p := &Plan{SessionID: "s1", Outbounds: []Outbound{hy2Outbound()}}
			c.mut(&p.Outbounds[0])
			if !p.RequiredFeatures()[c.feature] {
				t.Fatalf("a plan pinning %s must require feature %s", c.name, c.feature)
			}

			if missing := Catalog[KindSingBox].Missing(p); !slices.Contains(missing, missingName) {
				t.Errorf("static sing-box entry (floor 1.12.0) must not carry the plan, got missing %v", missing)
			}
			for _, version := range []string{"1.12.0", "1.12.12", "1.13.0", "1.13.21"} {
				caps := BuildCapabilities(KindSingBox, mustVersion(t, version), nil)
				if missing := caps.Missing(p); !slices.Contains(missing, missingName) {
					t.Errorf("sing-box %s refuses %s at load and must not carry the plan, got missing %v", version, c.name, missing)
				}
			}
			for _, version := range []string{"1.14.0", "1.14.3", "1.14.3-lx.22"} {
				caps := BuildCapabilities(KindSingBox, mustVersion(t, version), nil)
				if missing := caps.Missing(p); slices.Contains(missing, missingName) {
					t.Errorf("sing-box %s spells %s and must carry the plan, got missing %v", version, c.name, missing)
				}
			}
			if missing := Catalog[KindXray].Missing(p); !slices.Contains(missing, missingName) {
				t.Errorf("xray spells no %s and must not carry the plan, got missing %v", c.name, missing)
			}
			mihomoCarries := c.feature == FeatureHy2ObfsGecko
			missing := Catalog[KindMihomo].Missing(p)
			if mihomoCarries && slices.Contains(missing, missingName) {
				t.Errorf("mihomo 1.19.32 accepts gecko and must carry the plan, got missing %v", missing)
			}
			if !mihomoCarries && !slices.Contains(missing, missingName) {
				t.Errorf("mihomo renders no %s and must not carry the plan, got missing %v", c.name, missing)
			}
		})
	}
}

// TestHy2SingBox114GateIsNarrow pins the other direction of the
// gates: a Hysteria2 plan using only the pre-1.14 spellings
// (salamander obfs, fixed hop interval) keeps routing to every
// build at the static floor — the 1.14 claims must not widen into
// a general Hysteria2 refusal.
func TestHy2SingBox114GateIsNarrow(t *testing.T) {
	o := hy2Outbound()
	o.ObfsBox().Type, o.ObfsBox().Param = "salamander", "obfs-secret"
	o.QUICBox().HopPorts, o.QUICBox().HopInterval = "20000-30000,40000", 30
	p := &Plan{SessionID: "s1", Outbounds: []Outbound{o}}
	for _, version := range []string{"1.12.0", "1.12.12", "1.13.21", "1.14.3"} {
		caps := BuildCapabilities(KindSingBox, mustVersion(t, version), nil)
		if missing := caps.Missing(p); len(missing) > 0 {
			t.Errorf("sing-box %s must carry a pre-1.14 hysteria2 plan, got missing %v", version, missing)
		}
	}
	if missing := Catalog[KindMihomo].Missing(p); len(missing) > 0 {
		t.Errorf("mihomo must carry a pre-1.14 hysteria2 plan, got missing %v", missing)
	}
}

// TestHy2SingBox114SelectEngine checks the gate end to end through
// SelectEngine: a combined 1.14 plan (all three spellings at once)
// is refused by name on a 1.13.21 build and selected on a 1.14.3
// build, so the refusal reaches the client before any render.
func TestHy2SingBox114SelectEngine(t *testing.T) {
	o := hy2Outbound()
	o.QUICBox().HopPorts, o.QUICBox().HopInterval, o.QUICBox().HopIntervalMax = "20000-30000", 30, 90
	o.QUICBox().BBRProfile = "conservative"
	o.ObfsBox().Type, o.ObfsBox().Param = "gecko", "gecko-secret"
	p := &Plan{SessionID: "s1", Outbounds: []Outbound{o}}

	old := []Availability{{Kind: KindSingBox, Usable: true, Version: mustVersion(t, "1.13.21")}}
	if _, err := SelectEngine(p, old, []Kind{KindSingBox}); err == nil ||
		!strings.Contains(err.Error(), string(FeatureHy2HopIntervalMax)) ||
		!strings.Contains(err.Error(), string(FeatureHy2BBRProfile)) ||
		!strings.Contains(err.Error(), string(FeatureHy2ObfsGecko)) {
		t.Fatalf("SelectEngine(1.13.21) = %v, want a refusal naming all three 1.14 features", err)
	}
	fresh := []Availability{{Kind: KindSingBox, Usable: true, Version: mustVersion(t, "1.14.3")}}
	sel, err := SelectEngine(p, fresh, []Kind{KindSingBox})
	if err != nil {
		t.Fatalf("SelectEngine(1.14.3) = %v, want the plan selected", err)
	}
	if sel.Kind != KindSingBox {
		t.Fatalf("SelectEngine(1.14.3) picked %s, want sing-box", sel.Kind)
	}
}
