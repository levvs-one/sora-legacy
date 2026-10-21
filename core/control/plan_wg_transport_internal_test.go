package control

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/singbox"
	"github.com/levvs-one/sora-client/core/engine/supervise"
	"github.com/levvs-one/sora-client/core/engine/xray"
	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
	"github.com/levvs-one/sora-client/core/parser"
)

// TestWireGuardImportBuildsPlanAndRenders is the end-to-end pin for
// the WireGuard transport vocabulary fix: the parser spells a
// WireGuard spec's transport "udp" (exactly as sora's parser does),
// which is not a plan transport, so before the normalization in
// outboundFromProto no imported WireGuard server — link or .conf —
// could ever build a plan. The whole desktop pipeline is exercised:
// parse → credential document → outboundToProto → BuildEnginePlan
// (planFromProto, which validates) → Validate → both renderers whose
// catalogs carry WireGuard.
func TestWireGuardImportBuildsPlanAndRenders(t *testing.T) {
	for name, source := range map[string]string{
		"link": "wireguard://cKE7LmCF61IhqqABGhvJ44jWXp8fKymcMAEVAzLDYVk%3D@198.51.100.7:51820" +
			"?publickey=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw%3D&address=10.7.0.2%2C2001%3Adb8%3A%3A2#WG",
		"conf": "[Interface]\nPrivateKey = cKE7LmCF61IhqqABGhvJ44jWXp8fKymcMAEVAzLDYVk=\nAddress = 10.7.0.2, fd00::2/128\n\n" +
			"[Peer]\nPublicKey = Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw=\nEndpoint = 198.51.100.7:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n",
	} {
		t.Run(name, func(t *testing.T) {
			result, err := parser.LinkParser{}.Parse([]byte(source))
			if err != nil || len(result.Servers) != 1 {
				t.Fatalf("Parse = %+v, %v", result, err)
			}
			spec := result.Servers[0]
			if spec.Transport != "udp" {
				t.Fatalf("parser transport = %q, want the producer spelling %q (parity with sora's parser)", spec.Transport, "udp")
			}
			reference, err := referenceOf(spec)
			if err != nil {
				t.Fatal(err)
			}
			document, err := credentialDocument(spec)
			if err != nil {
				t.Fatal(err)
			}
			wire := outboundToProto(spec, reference)
			if wire.GetTransport() != "udp" {
				t.Fatalf("wire transport = %q, want %q: the client carries the producer spelling, the plan layer must absorb it", wire.GetTransport(), "udp")
			}
			plan, err := BuildEnginePlan(&corev1.SessionPlan{
				TunnelMode: corev1.TunnelMode_TUNNEL_MODE_APPLICATION,
				Outbounds:  []*corev1.OutboundSpec{wire},
			}, "sess-wg-transport", map[string][]byte{reference: document})
			if err != nil {
				t.Fatalf("BuildEnginePlan: %v", err)
			}
			if err := plan.Validate(); err != nil {
				t.Fatalf("plan.Validate: %v", err)
			}
			o := plan.Outbounds[0]
			if o.Protocol != engine.ProtocolWireGuard || o.Transport.Type != "" {
				t.Fatalf("outbound = protocol %q transport %q, want wireguard with no stream transport", o.Protocol, o.Transport.Type)
			}
			if o.PrivateKey == "" || len(o.Peers) != 1 || len(o.Addresses) == 0 {
				t.Fatalf("wireguard material lost on the way to the plan: key %q peers %d addresses %v", o.PrivateKey, len(o.Peers), o.Addresses)
			}

			rt := supervise.Runtime{LocalPort: 7890, ControlAddr: "127.0.0.1:9090", ProbeURL: engine.TestURLProduction}
			raw, err := singbox.Render(plan, rt)
			if err != nil {
				t.Fatalf("singbox.Render: %v", err)
			}
			var sbCfg struct {
				Endpoints []struct {
					Type string `json:"type"`
				} `json:"endpoints"`
			}
			if err := json.Unmarshal(raw, &sbCfg); err != nil {
				t.Fatalf("sing-box config is not JSON: %v", err)
			}
			if len(sbCfg.Endpoints) != 1 || sbCfg.Endpoints[0].Type != "wireguard" {
				t.Fatalf("sing-box endpoints = %+v, want one wireguard endpoint", sbCfg.Endpoints)
			}

			raw, err = xray.Render(plan, rt, nil)
			if err != nil {
				t.Fatalf("xray.Render: %v", err)
			}
			var xCfg struct {
				Outbounds []struct {
					Protocol string `json:"protocol"`
				} `json:"outbounds"`
			}
			if err := json.Unmarshal(raw, &xCfg); err != nil {
				t.Fatalf("xray config is not JSON: %v", err)
			}
			found := false
			for _, ob := range xCfg.Outbounds {
				found = found || ob.Protocol == "wireguard"
			}
			if !found {
				t.Fatalf("xray outbounds = %+v, want a wireguard outbound", xCfg.Outbounds)
			}
		})
	}
}

// TestWireGuardTransportNormalizationIsStrict pins the other half of
// the fix (ported from sora's B1 review probe): only the spellings
// real producers emit — the parser's "udp", a custom spec's ""
// (which the converter's default turns into "tcp") and "tcp" itself
// — are normalized to the plan's empty transport. Anything else is
// not a WireGuard transport at all and must fail plan building
// honestly, including "ws"/"grpc", which the plan whitelist accepts
// for other protocols and therefore cannot catch downstream.
func TestWireGuardTransportNormalizationIsStrict(t *testing.T) {
	build := func(transport string) (*engine.Plan, error) {
		spec := &corev1.OutboundSpec{
			Id: "wg1", DisplayName: "WG", Protocol: "wireguard",
			Transport: transport, Security: "none",
			Endpoint: &corev1.Endpoint{Host: "198.51.100.7", Port: 51820},
		}
		return planFromProto(&corev1.SessionPlan{
			TunnelMode: corev1.TunnelMode_TUNNEL_MODE_APPLICATION,
			Outbounds:  []*corev1.OutboundSpec{spec},
		}, "sess-wg-strict", nil)
	}
	for _, transport := range []string{"bogus", "ws", "grpc", "xhttp", "quic"} {
		if _, err := build(transport); err == nil {
			t.Errorf("wireguard/%q: plan built, want an honest validation failure", transport)
		} else if !strings.Contains(err.Error(), "wireguard has no stream transport") {
			t.Errorf("wireguard/%q: error = %v, want the wireguard transport refusal", transport, err)
		}
	}
	for _, transport := range []string{"udp", "", "tcp"} {
		plan, err := build(transport)
		if err != nil {
			t.Errorf("wireguard/%q: plan failed: %v, want it to build with no transport", transport, err)
			continue
		}
		if got := plan.Outbounds[0].Transport.Type; got != "" {
			t.Errorf("wireguard/%q: built plan carries transport %q, want %q (WireGuard has none)", transport, got, "")
		}
	}
}
