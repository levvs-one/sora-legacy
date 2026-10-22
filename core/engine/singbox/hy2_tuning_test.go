package singbox

import (
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/enginetest"
)

// W1 (ported from sora snapshot 142397c5): sing-box Hysteria2/TUIC
// tuning fields must reach the render — bandwidth caps, port hopping
// in sing-box spelling, hop intervals, bbr_profile — and the TUIC
// congestion/relay/heartbeat fields likewise.

func findOutbound(cfg map[string]any, typ string) map[string]any {
	for _, o := range cfg["outbounds"].([]any) {
		m := o.(map[string]any)
		if m["type"] == typ {
			return m
		}
	}
	return nil
}

func TestRenderHysteria2BandwidthAndHopping(t *testing.T) {
	p := enginetest.Plan(engine.ProtocolHysteria2)
	o := &p.Outbounds[0]
	o.QUICBox().UpMbps, o.QUICBox().DownMbps = 20, 100
	o.QUICBox().HopPorts = "20000-30000,40000"
	o.QUICBox().HopInterval = 30
	cfg := render(t, p)
	hy2 := findOutbound(cfg, "hysteria2")
	if hy2 == nil {
		t.Fatal("no hysteria2 outbound rendered")
	}
	// up/down switch the engine from BBR to Brutal congestion control.
	if hy2["up_mbps"] != float64(20) || hy2["down_mbps"] != float64(100) {
		t.Fatalf("bandwidth caps not rendered: %v", hy2)
	}
	// server_ports uses sing-box spelling: colon ranges with an
	// explicit upper bound (the binary rejects the plan's dash
	// spelling and bare single ports at config load).
	ports, ok := hy2["server_ports"].([]any)
	if !ok || len(ports) != 2 || ports[0] != "20000:30000" || ports[1] != "40000:40000" {
		t.Fatalf("hop ports not rendered in sing-box spelling: %v", hy2["server_ports"])
	}
	if hy2["hop_interval"] != "30s" {
		t.Fatalf("hop interval not rendered: %v", hy2["hop_interval"])
	}
	// Salamander obfuscation still renders alongside the tuning fields.
	if obfs, ok := hy2["obfs"].(map[string]any); !ok || obfs["type"] != "salamander" {
		t.Fatalf("obfs not rendered: %v", hy2["obfs"])
	}
}

func TestRenderHysteria2TuningFields(t *testing.T) {
	p := enginetest.Plan(engine.ProtocolHysteria2)
	o := &p.Outbounds[0]
	o.QUICBox().HopPorts = "20000-30000"
	o.QUICBox().HopInterval = 30
	o.QUICBox().HopIntervalMax = 90
	o.QUICBox().BBRProfile = "conservative"
	cfg := render(t, p)
	hy2 := findOutbound(cfg, "hysteria2")
	if hy2 == nil {
		t.Fatal("no hysteria2 outbound rendered")
	}
	if hy2["hop_interval"] != "30s" || hy2["hop_interval_max"] != "90s" {
		t.Errorf("hop fields = %v/%v, want 30s/90s", hy2["hop_interval"], hy2["hop_interval_max"])
	}
	if hy2["bbr_profile"] != "conservative" {
		t.Errorf("bbr_profile = %v, want conservative", hy2["bbr_profile"])
	}
}

func TestRenderHysteria2BBRProfileSuppressedUnderBrutal(t *testing.T) {
	// With bandwidth caps the client runs Brutal, not BBR: emitting
	// bbr_profile would be dead config text.
	p := enginetest.Plan(engine.ProtocolHysteria2)
	o := &p.Outbounds[0]
	o.QUICBox().UpMbps, o.QUICBox().DownMbps = 50, 200
	o.QUICBox().BBRProfile = "aggressive"
	cfg := render(t, p)
	hy2 := findOutbound(cfg, "hysteria2")
	if _, ok := hy2["bbr_profile"]; ok {
		t.Errorf("bbr_profile emitted while brutal caps are set: %v", hy2)
	}
}

func TestRenderHysteria2GeckoObfs(t *testing.T) {
	p := enginetest.Plan(engine.ProtocolHysteria2)
	o := &p.Outbounds[0]
	o.ObfsBox().Type, o.ObfsBox().Param = "gecko", "gecko-secret"
	cfg := render(t, p)
	hy2 := findOutbound(cfg, "hysteria2")
	obfs, _ := hy2["obfs"].(map[string]any)
	if obfs["type"] != "gecko" || obfs["password"] != "gecko-secret" {
		t.Errorf("obfs = %v, want gecko with its password", hy2["obfs"])
	}
}

func TestRenderTUICTuning(t *testing.T) {
	p := enginetest.Plan(engine.ProtocolTUIC)
	p.Outbounds[0].QUICBox().CongestionControl = "cubic"
	p.Outbounds[0].QUICBox().UDPRelayMode = "quic"
	p.Outbounds[0].QUICBox().TUICHeartbeat = 25
	cfg := render(t, p)
	tuic := findOutbound(cfg, "tuic")
	if tuic == nil {
		t.Fatal("no tuic outbound rendered")
	}
	if tuic["congestion_control"] != "cubic" || tuic["udp_relay_mode"] != "quic" {
		t.Fatalf("tuic tuning not rendered: %v", tuic)
	}
	if tuic["heartbeat"] != "25s" {
		t.Fatalf("tuic heartbeat not rendered: %v", tuic)
	}
	// Defaults come from quic_defaults.go: BBR and the default
	// heartbeat, rendered explicitly so both TUIC engines agree.
	cfg = render(t, enginetest.Plan(engine.ProtocolTUIC))
	tuic = findOutbound(cfg, "tuic")
	if tuic["congestion_control"] != engine.DefaultTUICCongestion {
		t.Fatal("tuic default congestion control must stay bbr")
	}
	if want := "10s"; tuic["heartbeat"] != want {
		t.Fatalf("tuic default heartbeat = %v, want %s (DefaultTUICHeartbeatSeconds)", tuic["heartbeat"], want)
	}
}

// TestRenderHy2TUICDeterministic: the same hy2/tuic plan rendered
// twice is byte-identical — config churn between identical plans
// would churn engine restarts and defeat config diffing in
// diagnostics.
func TestRenderHy2TUICDeterministic(t *testing.T) {
	for _, proto := range []engine.Protocol{engine.ProtocolHysteria2, engine.ProtocolTUIC} {
		p := enginetest.Plan(proto)
		o := &p.Outbounds[0]
		o.QUICBox().HopPorts, o.QUICBox().HopInterval, o.QUICBox().HopIntervalMax = "20000-30000,40000", 30, 90
		o.QUICBox().UpMbps, o.QUICBox().DownMbps = 20, 100
		o.QUICBox().CongestionControl, o.QUICBox().UDPRelayMode, o.QUICBox().TUICHeartbeat = "cubic", "quic", 25
		first, err := Render(p, testRuntime)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			again, err := Render(p, testRuntime)
			if err != nil {
				t.Fatal(err)
			}
			if string(again) != string(first) {
				t.Fatalf("%s render %d differs from the first:\n%s\n---\n%s", proto, i, again, first)
			}
		}
	}
}
