package engine

import (
	"strings"
	"testing"
)

// TestReleaseA1SelectEngineVersionGates is the §8.6 release pin:
// every version-gated spelling — ECH query_server_name (sing-box
// 1.13+), Hysteria2 hop_interval_max and bbr_profile and the gecko
// obfs type (sing-box 1.14+) — must be refused BY NAME through
// SelectEngine on every engine/build that cannot spell it, and
// carried by the builds that can. A build below a field's floor
// must never receive the plan and fail only at engine load.
// The Missing-level pins live in catalog_ech_qsn_test.go and
// catalog_hy2_114_test.go; this test closes the end-to-end level
// for query_server_name (which previously had no SelectEngine
// coverage) and re-checks each 1.14 field individually through
// selection on all three engines.
func TestReleaseA1SelectEngineVersionGates(t *testing.T) {
	singBox := func(v string) []Availability {
		return []Availability{{Kind: KindSingBox, Usable: true, Version: mustVersion(t, v)}}
	}
	one := func(kind Kind, v string) []Availability {
		return []Availability{{Kind: kind, Usable: true, Version: mustVersion(t, v)}}
	}
	wantRefusal := func(t *testing.T, p *Plan, avail []Availability, kind Kind, feature Feature) {
		t.Helper()
		_, err := SelectEngine(p, avail, []Kind{kind})
		if err == nil || !strings.Contains(err.Error(), string(feature)) {
			t.Fatalf("SelectEngine(%s) = %v, want a refusal naming %s", kind, err, feature)
		}
	}
	wantCarried := func(t *testing.T, p *Plan, avail []Availability, kind Kind) {
		t.Helper()
		sel, err := SelectEngine(p, avail, []Kind{kind})
		if err != nil {
			t.Fatalf("SelectEngine(%s) = %v, want the plan carried", kind, err)
		}
		if sel.Kind != kind {
			t.Fatalf("SelectEngine picked %s, want %s", sel.Kind, kind)
		}
	}

	// query_server_name: sing-box floor is 1.13 for this field.
	qsn := &Plan{SessionID: "s1", Outbounds: []Outbound{echOutbound()}}
	qsn.Outbounds[0].TLS.ECHBox().QueryServerName = "ech-query.example.com"
	for _, v := range []string{"1.12.0", "1.12.12"} {
		wantRefusal(t, qsn, singBox(v), KindSingBox, FeatureECHQueryServerName)
	}
	for _, v := range []string{"1.13.0", "1.13.21", "1.14.3"} {
		wantCarried(t, qsn, singBox(v), KindSingBox)
	}
	wantCarried(t, qsn, one(KindMihomo, "1.19.32"), KindMihomo)
	wantRefusal(t, qsn, one(KindXray, "26.3.27"), KindXray, FeatureECHQueryServerName)

	// Each 1.14 Hysteria2 field individually, on all engines.
	fields := []struct {
		name    string
		feature Feature
		mut     func(*Outbound)
		mihomo  bool // whether mihomo carries the field
	}{
		{"hop_interval_max", FeatureHy2HopIntervalMax, func(o *Outbound) {
			o.QUICBox().HopPorts, o.QUICBox().HopInterval, o.QUICBox().HopIntervalMax = "20000-30000", 30, 90
		}, false},
		{"bbr_profile", FeatureHy2BBRProfile, func(o *Outbound) {
			o.QUICBox().BBRProfile = "conservative"
		}, false},
		{"gecko obfs", FeatureHy2ObfsGecko, func(o *Outbound) {
			o.ObfsBox().Type, o.ObfsBox().Param = "gecko", "gecko-secret"
		}, true},
	}
	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			p := &Plan{SessionID: "s1", Outbounds: []Outbound{hy2Outbound()}}
			f.mut(&p.Outbounds[0])
			for _, v := range []string{"1.12.0", "1.12.12", "1.13.21"} {
				wantRefusal(t, p, singBox(v), KindSingBox, f.feature)
			}
			wantCarried(t, p, singBox("1.14.3"), KindSingBox)
			if f.mihomo {
				wantCarried(t, p, one(KindMihomo, "1.19.32"), KindMihomo)
			} else {
				wantRefusal(t, p, one(KindMihomo, "1.19.32"), KindMihomo, f.feature)
			}
			wantRefusal(t, p, one(KindXray, "26.3.27"), KindXray, f.feature)
		})
	}
}
