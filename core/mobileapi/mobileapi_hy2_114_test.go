package mobileapi

import (
	"strings"
	"testing"
)

// TestRenderRefusesSingBox114Hy2Fields pins the mobile path of the
// LEGACY-FULL gates: RenderSingBoxConfig gates on the static
// sing-box catalog, which claims none of the three sing-box 1.14
// Hysteria2 spellings (hop_interval_max, bbr_profile, gecko obfs —
// version-gated claims in engine.BuildCapabilities, which this
// facade does not assume). A document carrying any of them must be
// refused here by name, before rendering, instead of producing a
// configuration a pre-1.14 sing-box build would refuse at load; the
// pre-1.14 baseline (salamander obfs, fixed hop interval) renders.
func TestRenderRefusesSingBox114Hy2Fields(t *testing.T) {
	cases := map[string]string{
		"hop_interval_max": "hysteria2://secret@example.com:443?ports=20000-30000&hopinterval=30&hopintervalmax=90&sni=example.com#H",
		"bbr_profile":      "hysteria2://secret@example.com:443?bbr_profile=conservative&sni=example.com#H",
		"gecko obfs":       "hysteria2://secret@example.com:443?obfs=gecko&obfs-password=gecko-secret&sni=example.com#H",
	}
	features := map[string]string{
		"hop_interval_max": "hy2-hop-interval-max",
		"bbr_profile":      "hy2-bbr-profile",
		"gecko obfs":       "hy2-obfs-gecko",
	}
	for name, link := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := ImportLinks(link)
			if err != nil {
				t.Fatalf("ImportLinks: %v", err)
			}
			if _, err := BuildPlan(raw); err != nil {
				t.Fatalf("BuildPlan: %v", err)
			}
			if _, err := RenderSingBoxConfig(raw); err == nil || !strings.Contains(err.Error(), features[name]) {
				t.Fatalf("RenderSingBoxConfig(%s) = %v, want a refusal naming %s", name, err, features[name])
			}
		})
	}
	raw, err := ImportLinks("hysteria2://secret@example.com:443?obfs=salamander&obfs-password=pw&ports=20000-30000&hopinterval=30&sni=example.com#H")
	if err != nil {
		t.Fatalf("ImportLinks(baseline): %v", err)
	}
	if _, err := RenderSingBoxConfig(raw); err != nil {
		t.Fatalf("RenderSingBoxConfig(pre-1.14 baseline) = %v, want the config rendered", err)
	}
}
