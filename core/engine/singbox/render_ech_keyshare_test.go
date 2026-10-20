package singbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/enginetest"
)

// ECH and REALITY key-share render tests, ported from sora snapshot
// 63faf1d3480d5429b6bcec3483c19c8e03defb85 (SP5-render): the ECH tests
// from singbox/render_test.go, the key-share tests from
// singbox/censor_p1_reality_test.go.

func trojanOutbound(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	for _, ob := range cfg["outbounds"].([]any) {
		m := ob.(map[string]any)
		if m["type"] == "trojan" {
			return m
		}
	}
	t.Fatal("no trojan outbound rendered")
	return nil
}

func TestRenderECHOutboundTLS(t *testing.T) {
	p := enginetest.Plan(engine.ProtocolTrojan)
	p.Outbounds[0].TLS.ECH = engine.ECHConfig{
		Enabled: true,
		Config:  []string{"AE7+DQA8NwAgACBwaW5uZWQtZWNoLXRlc3QtY29uZmln"},
	}
	tls, ok := trojanOutbound(t, render(t, p))["tls"].(map[string]any)
	if !ok {
		t.Fatal("trojan outbound must carry a tls block")
	}
	ech, ok := tls["ech"].(map[string]any)
	if !ok {
		t.Fatal("tls block must carry ech when ECH is enabled")
	}
	if ech["enabled"] != true {
		t.Fatalf("ech.enabled = %v, want true", ech["enabled"])
	}
	// The pinned list renders canonicalized to the PEM armor the
	// binary accepts — label "ECH CONFIGS", probed on lx.22 (the
	// verbatim passthrough of a bare base64 line or an "ECHCONFIG"
	// label fails the engine's startup, CENSOR-FP) — carrying the
	// same ECHConfigList bytes.
	got, _ := ech["config"].([]any)
	var lines []string
	for _, v := range got {
		lines = append(lines, v.(string))
	}
	raw, err := engine.ECHConfigListBytes(lines)
	if err != nil {
		t.Fatalf("ech.config = %v, want a decodable pinned ECHConfigList: %v", ech["config"], err)
	}
	want, _ := engine.ECHConfigListBytes([]string{"AE7+DQA8NwAgACBwaW5uZWQtZWNoLXRlc3QtY29uZmln"})
	if string(raw) != string(want) {
		t.Fatalf("ech.config decodes to %x, want the pinned list %x", raw, want)
	}
	if len(lines) == 0 || lines[0] != "-----BEGIN ECH CONFIGS-----" {
		t.Fatalf("ech.config = %v, want canonical ECH CONFIGS armor", ech["config"])
	}
}

func TestRenderOmitsECHByDefault(t *testing.T) {
	tls, ok := trojanOutbound(t, render(t, enginetest.Plan(engine.ProtocolTrojan)))["tls"].(map[string]any)
	if !ok {
		t.Fatal("trojan outbound must carry a tls block")
	}
	if _, has := tls["ech"]; has {
		t.Fatal("ech must not be rendered unless explicitly enabled")
	}
}

// TestRenderECHQueryServerName locks the 1.13+ ECH field: a configured
// override must reach the engine, an empty one must stay unset.
func TestRenderECHQueryServerName(t *testing.T) {
	p := enginetest.Plan(engine.ProtocolTrojan)
	p.Outbounds[0].TLS.ECH = engine.ECHConfig{Enabled: true, QueryServerName: "ech-query.example.com"}
	ech, ok := trojanOutbound(t, render(t, p))["tls"].(map[string]any)["ech"].(map[string]any)
	if !ok {
		t.Fatal("tls block must carry ech when ECH is enabled")
	}
	if ech["query_server_name"] != "ech-query.example.com" {
		t.Fatalf("ech.query_server_name = %v, want the configured override", ech["query_server_name"])
	}

	p.Outbounds[0].TLS.ECH = engine.ECHConfig{Enabled: true}
	ech, ok = trojanOutbound(t, render(t, p))["tls"].(map[string]any)["ech"].(map[string]any)
	if !ok {
		t.Fatal("tls block must carry ech when ECH is enabled")
	}
	if _, has := ech["query_server_name"]; has {
		t.Fatal("ech.query_server_name must stay unset when empty")
	}
}

// TestRenderECHRejectsBadPin: a bare Render (bypassing plan
// validation, which already decodes the pin) must fail on a pin the
// shared helper cannot decode — the reference's tls() returns the
// ECHConfigPEM error wrapped with the outbound id instead of
// emitting an undecodable config.
func TestRenderECHRejectsBadPin(t *testing.T) {
	p := enginetest.Plan(engine.ProtocolTrojan)
	p.Outbounds[0].TLS.ECH = engine.ECHConfig{
		Enabled: true,
		Config:  []string{"!!! not a config !!!"},
	}
	if _, err := Render(p, testRuntime); err == nil || !strings.Contains(err.Error(), "ech:") {
		t.Fatalf("Render = %v, want the pinned-list decode error", err)
	}
}

// TestCensorP1RenderKeyShare pins the sing-box leg of the plan's
// REALITY key-share knob: tls.reality.key_share carries the plan
// value verbatim, and an unset knob renders nothing (the engine
// default must stay the engine's, not a sora invention).
func TestCensorP1RenderKeyShare(t *testing.T) {
	for _, ks := range []string{"hybrid", "classical"} {
		p := enginetest.Plan(engine.ProtocolVLESS)
		p.Outbounds[0].TLS.KeyShare = ks
		raw, err := Render(p, testRuntime)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `"key_share":"`+ks+`"`) {
			t.Fatalf("KeyShare %q must render as tls.reality.key_share:\n%s", ks, raw)
		}
	}
	p := enginetest.Plan(engine.ProtocolVLESS)
	raw, err := Render(p, testRuntime)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "key_share") {
		t.Fatalf("an unset KeyShare must render no key_share key:\n%s", raw)
	}
}

// TestCensorP1BinaryAcceptsKeyShareRender is the `sing-box check`
// verification behind the sing-box KeyShare claim (CENSOR-P1): the
// pinned lx binary must accept the rendered key_share shape as-is.
// Its wire-level effect (classical drops the hybrid group) is pinned
// by the fingerprint-policy captures, not here.
func TestCensorP1BinaryAcceptsKeyShareRender(t *testing.T) {
	bin := os.Getenv("SORA_SINGBOX_BIN")
	if bin == "" {
		dir := os.Getenv("SORA_ENGINES_DIR")
		if dir == "" {
			t.Skip("set SORA_ENGINES_DIR or SORA_SINGBOX_BIN to check the render with sing-box")
		}
		bin = filepath.Join(dir, "sing-box")
	}
	p := enginetest.Plan(engine.ProtocolVLESS)
	p.Outbounds[0].TLS.KeyShare = "hybrid"
	raw, err := Render(p, testRuntime)
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfg, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(t.Context(), bin, "check", "-c", cfg).CombinedOutput(); err != nil {
		t.Fatalf("sing-box refused the key_share render: %v\n%s", err, out)
	}
}
