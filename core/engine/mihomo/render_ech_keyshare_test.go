package mihomo

import (
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
)

// ECH and REALITY key-share render tests, ported from sora snapshot
// 63faf1d3480d5429b6bcec3483c19c8e03defb85 (SP5-render): the ECH and
// key-share tests from mihomo/render_test.go.

func TestRenderECHProxyToggle(t *testing.T) {
	p := testPlan()
	p.Outbounds[0].TLS.ECH = &engine.ECHConfig{Enabled: true}
	out, err := Render(p, testRuntime(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ech-opts:") || !strings.Contains(out, "enable: true") {
		t.Fatalf("rendered mihomo config must enable ech via ech-opts, got:\n%s", out)
	}
	if strings.Contains(out, "\n    ech: true") {
		t.Fatalf("the legacy flat ech toggle must not be emitted anymore:\n%s", out)
	}
}

func TestRenderECHPinnedConfigAndQueryServerName(t *testing.T) {
	// PASS3 deep S4: the pinned config and the query name used to be
	// dropped (only `ech: true` was rendered). The plan stores PEM
	// lines; ech-opts.config is one base64 string.
	p := testPlan()
	p.Outbounds[0].TLS.ECH = &engine.ECHConfig{
		Enabled: true,
		Config: []string{
			"-----BEGIN ECHCONFIG-----",
			"AE7+DQA8NwAgACBwaW5uZWQtZWNoLXRlc3QtY29uZmln",
			"-----END ECHCONFIG-----",
		},
		QueryServerName: "ech-query.example.com",
	}
	out, err := Render(p, testRuntime(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"config: AE7+DQA8NwAgACBwaW5uZWQtZWNoLXRlc3QtY29uZmln",
		"query-server-name: ech-query.example.com",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("rendered mihomo config is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "BEGIN ECHCONFIG") {
		t.Fatalf("PEM armor must not reach ech-opts.config:\n%s", out)
	}
}

func TestRenderECHRejectsUnmergeablePinnedConfigs(t *testing.T) {
	p := testPlan()
	p.Outbounds[0].TLS.ECH = &engine.ECHConfig{
		Enabled: true,
		Config: []string{
			"-----BEGIN ECHCONFIG-----", "QUJD", "-----END ECHCONFIG-----",
			"-----BEGIN ECHCONFIG-----", "REVG", "-----END ECHCONFIG-----",
		},
	}
	if _, err := Render(p, testRuntime(t)); err == nil {
		t.Fatal("two pinned ECHConfigLists cannot merge into mihomo's single config value and must be refused")
	}
	p.Outbounds[0].TLS.ECHBox().Config = []string{"not base64!!!"}
	if _, err := Render(p, testRuntime(t)); err == nil {
		t.Fatal("a non-base64 pinned ECH config must be refused, not rendered")
	}
}

func TestRenderOmitsECHByDefault(t *testing.T) {
	out, err := Render(testPlan(), testRuntime(t))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "ech-opts") {
		t.Fatalf("rendered mihomo config must not mention ech unless enabled, got:\n%s", out)
	}
}

// TestRenderRealityKeyShare pins PASS3 deep S2: the plan's KeyShare
// knob renders as reality-opts.support-x25519mlkem768 on mihomo —
// hybrid as explicit true, classical as explicit false, unset as
// absent (mihomo's own default is not confirmed from the pinned
// docs, so the renderer must not invent one).
func TestRenderRealityKeyShare(t *testing.T) {
	render := func(ks string) string {
		p := testPlan()
		p.Outbounds[0] = engine.Outbound{
			ID: "srv-1", Name: "Reality 01", Protocol: engine.ProtocolVLESS,
			Server: "re.example.com", Port: 443, UUID: "11111111-2222-3333-4444-555555555555",
			TLS: engine.TLS{Enabled: true, ServerName: "www.example.com",
				Reality: &engine.RealitySettings{PublicKey: "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw", KeyShare: ks}},
		}
		p.Groups = []engine.Group{{Name: "sel", Type: engine.GroupSelect, Outbounds: []string{"srv-1"}}}
		p.Rules = []engine.Rule{{Type: engine.RuleMatchAll, Target: "srv-1"}}
		out, err := Render(p, testRuntime(t))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if out := render("hybrid"); !strings.Contains(out, "support-x25519mlkem768: true") {
		t.Fatalf("hybrid must render support-x25519mlkem768: true:\n%s", out)
	}
	if out := render("classical"); !strings.Contains(out, "support-x25519mlkem768: false") {
		t.Fatalf("classical must render support-x25519mlkem768: false explicitly:\n%s", out)
	}
	if out := render(""); strings.Contains(out, "support-x25519mlkem768") {
		t.Fatalf("an unset KeyShare must omit the key entirely:\n%s", out)
	}
}
