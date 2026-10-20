package control

import (
	"testing"

	"github.com/levvs-one/sora-client/core/parser"
)

// W1: Hysteria2/TUIC tuning from an import link must survive the whole
// chain — parser Options, the credential document in the vault, and
// planFromProto — into the engine plan, exactly as in sora (snapshot
// 142397c5). Before the port the credential document dropped every
// tuning key, so the plan silently ran untuned defaults.
func TestImportedHy2TUICTuningSurvivesTheVault(t *testing.T) {
	hy2, err := parser.LinkParser{}.Parse([]byte(
		"hysteria2://pw@hy.example.com:443?upmbps=100&downmbps=200&mport=20000-30000,40000&hop-interval=45&hop-interval-max=90&bbr-profile=aggressive&obfs=salamander&obfs-password=obfspw&sni=hy.example.com#hy2"))
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := importedPlan(t, hy2)
	o := plan.Outbounds[0]
	if o.UpMbps != 100 || o.DownMbps != 200 {
		t.Errorf("bandwidth caps = %d/%d, want 100/200", o.UpMbps, o.DownMbps)
	}
	if o.HopPorts != "20000-30000,40000" || o.HopInterval != 45 || o.HopIntervalMax != 90 {
		t.Errorf("hopping = %q/%d/%d, want 20000-30000,40000/45/90", o.HopPorts, o.HopInterval, o.HopIntervalMax)
	}
	if o.BBRProfile != "aggressive" {
		t.Errorf("bbr profile = %q, want aggressive", o.BBRProfile)
	}
	if o.Obfs != "salamander" || o.ObfsParam != "obfspw" {
		t.Errorf("obfs = %q/%q, want salamander/obfspw", o.Obfs, o.ObfsParam)
	}

	tuic, err := parser.LinkParser{}.Parse([]byte(
		"tuic://11111111-2222-4333-8444-555555555555:pw@tu.example.com:443?congestion_control=cubic&udp_relay_mode=quic&heartbeat=15&token=tok123&sni=tu.example.com#tuic"))
	if err != nil {
		t.Fatal(err)
	}
	plan, _ = importedPlan(t, tuic)
	o = plan.Outbounds[0]
	if o.CongestionControl != "cubic" || o.UDPRelayMode != "quic" || o.TUICHeartbeat != 15 {
		t.Errorf("tuic tuning = %q/%q/%d, want cubic/quic/15", o.CongestionControl, o.UDPRelayMode, o.TUICHeartbeat)
	}
	if o.Token != "tok123" {
		t.Errorf("tuic token = %q, want tok123", o.Token)
	}
}

// TestImportedHy2MihomoPortsSpelling: the mihomo-style ports= key and
// the underscore bbr_profile spelling land in the same plan fields.
func TestImportedHy2MihomoPortsSpelling(t *testing.T) {
	res, err := parser.LinkParser{}.Parse([]byte(
		"hysteria2://pw@hy.example.com:443?ports=20000-30000&hopinterval=30&bbr_profile=standard&sni=hy.example.com#hy2"))
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := importedPlan(t, res)
	o := plan.Outbounds[0]
	if o.HopPorts != "20000-30000" || o.HopInterval != 30 || o.BBRProfile != "standard" {
		t.Errorf("hopping = %q/%d profile=%q, want 20000-30000/30/standard", o.HopPorts, o.HopInterval, o.BBRProfile)
	}
}
