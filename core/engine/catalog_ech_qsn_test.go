package engine

import (
	"slices"
	"testing"
)

// TestECHQueryServerNameGate is the catalog side of the
// LEGACY-PLAT-OBFS probe: the shipped payload sing-box 1.12.12
// refuses a rendered ech.query_server_name at load (`unknown field
// "query_server_name"` — the field exists only since sing-box
// 1.13), while the static sing-box floor is 1.12.0. A plan pinning
// an override must therefore require FeatureECHQueryServerName and
// be carried exactly by the builds that spell it: mihomo (static
// claim), sing-box >= 1.13 (BuildCapabilities claim), never Xray
// (no spelling; its renderer refuses as a backstop).
func TestECHQueryServerNameGate(t *testing.T) {
	qsnMissing := "feature " + string(FeatureECHQueryServerName)

	plain := &Plan{SessionID: "s1", Outbounds: []Outbound{echOutbound()}}
	if plain.RequiredFeatures()[FeatureECHQueryServerName] {
		t.Fatal("an ECH plan without an override must not require ech-query-server-name")
	}

	p := &Plan{SessionID: "s1", Outbounds: []Outbound{echOutbound()}}
	p.Outbounds[0].TLS.ECH.QueryServerName = "ech-query.example.com"
	if !p.RequiredFeatures()[FeatureECHQueryServerName] {
		t.Fatal("a plan pinning an ECH query_server_name must require feature ech-query-server-name")
	}

	if missing := Catalog[KindMihomo].Missing(p); slices.Contains(missing, qsnMissing) {
		t.Errorf("mihomo renders ech-opts.query-server-name and must carry the plan, got missing %v", missing)
	}
	if missing := Catalog[KindXray].Missing(p); !slices.Contains(missing, qsnMissing) {
		t.Errorf("xray has no query_server_name spelling and must not carry the plan, got missing %v", missing)
	}
	if missing := Catalog[KindSingBox].Missing(p); !slices.Contains(missing, qsnMissing) {
		t.Errorf("static sing-box entry (floor 1.12.0) must not carry the plan, got missing %v", missing)
	}
	for _, version := range []string{"1.12.0", "1.12.12"} {
		caps := BuildCapabilities(KindSingBox, mustVersion(t, version), nil)
		if missing := caps.Missing(p); !slices.Contains(missing, qsnMissing) {
			t.Errorf("sing-box %s refuses query_server_name at load and must not carry the plan, got missing %v", version, missing)
		}
	}
	for _, version := range []string{"1.13.0", "1.14.3", "1.14.3-lx.22"} {
		caps := BuildCapabilities(KindSingBox, mustVersion(t, version), nil)
		if missing := caps.Missing(p); slices.Contains(missing, qsnMissing) {
			t.Errorf("sing-box %s spells query_server_name and must carry the plan, got missing %v", version, missing)
		}
	}
}
