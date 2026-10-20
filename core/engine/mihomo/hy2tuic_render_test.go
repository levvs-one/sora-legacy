package mihomo

import (
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/enginetest"
)

// W1 (ported from sora snapshot 142397c5): mihomo renders the same
// Hysteria2/TUIC tuning the plan carries.

func TestRenderHysteria2BandwidthAndHopping(t *testing.T) {
	p := testPlan()
	p.Outbounds[1].UpMbps, p.Outbounds[1].DownMbps = 20, 100
	p.Outbounds[1].HopPorts = "20000-30000"
	p.Outbounds[1].HopInterval = 30
	out, err := Render(p, testRuntime(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"up: 20 Mbps", "down: 100 Mbps", "ports: 20000-30000", "hop-interval: 30"} {
		if !strings.Contains(out, want) {
			t.Fatalf("rendered mihomo config is missing %q:\n%s", want, out)
		}
	}
}

func TestRenderTUICTuning(t *testing.T) {
	p := testPlan()
	p.Outbounds = append(p.Outbounds, engine.Outbound{
		ID: "srv-3", Name: "TUIC", Protocol: engine.ProtocolTUIC,
		Server: "tu.example.com", Port: 443,
		UUID: "11111111-2222-3333-4444-555555555555", Password: "tuic-test-password",
		CongestionControl: "cubic", UDPRelayMode: "quic", Token: "v4-token", TUICHeartbeat: 25,
		TLS: engine.TLS{Enabled: true, ServerName: "tu.example.com"},
	})
	out, err := Render(p, testRuntime(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"type: tuic", "congestion-controller: cubic", "udp-relay-mode: quic", "token: v4-token", "heartbeat-interval: 25000"} {
		if !strings.Contains(out, want) {
			t.Fatalf("rendered mihomo config is missing %q:\n%s", want, out)
		}
	}
}

// TestRenderTUICDefaults: an untuned TUIC outbound renders the
// effective defaults from quic_defaults.go explicitly — mihomo
// silently falls back to its own defaults for omitted fields, and
// the two TUIC engines must agree on a plan.
func TestRenderTUICDefaults(t *testing.T) {
	p := testPlan()
	p.Outbounds = append(p.Outbounds, engine.Outbound{
		ID: "srv-3", Name: "TUIC", Protocol: engine.ProtocolTUIC,
		Server: "tu.example.com", Port: 443,
		UUID: "11111111-2222-3333-4444-555555555555", Password: "tuic-test-password",
		TLS: engine.TLS{Enabled: true, ServerName: "tu.example.com"},
	})
	out, err := Render(p, testRuntime(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"congestion-controller: bbr", "heartbeat-interval: 10000"} {
		if !strings.Contains(out, want) {
			t.Fatalf("rendered mihomo config is missing %q:\n%s", want, out)
		}
	}
}

// TestRenderHy2TUICDeterministic: the same hy2/tuic plan rendered
// twice is byte-identical.
func TestRenderHy2TUICDeterministic(t *testing.T) {
	for _, proto := range []engine.Protocol{engine.ProtocolHysteria2, engine.ProtocolTUIC} {
		p := enginetest.Plan(proto)
		o := &p.Outbounds[0]
		o.HopPorts, o.HopInterval = "20000-30000,40000", 30
		o.UpMbps, o.DownMbps = 20, 100
		o.CongestionControl, o.UDPRelayMode, o.TUICHeartbeat = "cubic", "quic", 25
		first, err := Render(p, testRuntime(t))
		if err != nil {
			t.Fatal(err)
		}
		again, err := Render(p, testRuntime(t))
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatalf("%s renders differ:\n%s\n---\n%s", proto, again, first)
		}
	}
}
