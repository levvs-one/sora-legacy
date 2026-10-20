package xray

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/enginetest"
)

// TestRenderECH is ported from sora snapshot
// 63faf1d3480d5429b6bcec3483c19c8e03defb85 (SP5-render; the
// reference's xray/render_test.go).
func TestRenderECH(t *testing.T) {
	// CENSOR-FP: the PASS3 refusal is superseded by a wire probe on
	// the pinned 26.10.17 binary — with echConfigList set, the outer
	// SNI of the captured ClientHello becomes the list's public_name
	// (real ECH, not GREASE). The renderer now emits the pinned list
	// as one base64 string, or echForceQuery "full" when unpinned,
	// and still refuses the one shape Xray cannot spell: a distinct
	// query_server_name override.
	mk := func(ech engine.ECHConfig) *engine.Plan {
		p := enginetest.Plan(engine.ProtocolVLESS)
		o := &p.Outbounds[0]
		o.Flow, o.TLS.Reality = "", false
		o.TLS = engine.TLS{Enabled: true, ServerName: "cdn.example.com", ECH: ech}
		return p
	}
	tlsSettings := func(t *testing.T, raw []byte) map[string]any {
		t.Helper()
		var cfg struct {
			Outbounds []struct {
				StreamSettings struct {
					TLSSettings map[string]any `json:"tlsSettings"`
				} `json:"streamSettings"`
			} `json:"outbounds"`
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatal(err)
		}
		return cfg.Outbounds[0].StreamSettings.TLSSettings
	}
	// Pinned: the canonical base64 of the plan's list.
	pinned := []string{"-----BEGIN ECHCONFIG-----", "QUJD", "-----END ECHCONFIG-----"}
	raw, err := Render(mk(engine.ECHConfig{Enabled: true, Config: pinned}), testRuntime, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := tlsSettings(t, raw)["echConfigList"]; got != "QUJD" {
		t.Errorf("echConfigList = %v, want the canonical base64 QUJD", got)
	}
	// Unpinned: Xray fetches the list itself.
	raw, err = Render(mk(engine.ECHConfig{Enabled: true}), testRuntime, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := tlsSettings(t, raw)["echForceQuery"]; got != "full" {
		t.Errorf("echForceQuery = %v, want full", got)
	}
	// QueryServerName has no Xray spelling: named refusal.
	if _, err := Render(mk(engine.ECHConfig{Enabled: true, QueryServerName: "ech.example.com"}), testRuntime, nil); err == nil || !strings.Contains(err.Error(), "query_server_name") {
		t.Fatalf("ECH query_server_name on the Xray path must be refused with a named error, got %v", err)
	}
	// A pinned list the shared helper cannot decode fails the render
	// closed (the reference wraps the helper error with the outbound
	// id) instead of emitting an echConfigList the engine would
	// silently misread.
	if _, err := Render(mk(engine.ECHConfig{Enabled: true, Config: []string{"not base64!!!"}}), testRuntime, nil); err == nil || !strings.Contains(err.Error(), "ech:") {
		t.Fatalf("an undecodable pinned list must be refused, got %v", err)
	}
}
