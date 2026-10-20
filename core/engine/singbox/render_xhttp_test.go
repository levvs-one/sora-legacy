package singbox

import (
	"bytes"
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/enginetest"
)

// The tests in this file are ported from sora's censor_p1_xhttp_test.go
// (S5-SP4), minus the binary-acceptance case (it needs the pinned
// sing-box-lx binary). Legacy spells the unset-mode default as the
// literal "auto" — it has no engine.DefaultXHTTPMode constant.

func xhttpPlan() *engine.Plan {
	p := enginetest.Plan(engine.ProtocolVLESS)
	p.Outbounds[0].Flow = "" // XHTTP cannot carry Vision; REALITY stays
	p.Outbounds[0].Transport = engine.Transport{
		Type: "xhttp", Mode: "stream-up", Path: "/xh",
		XmuxMaxConcurrency: 16, XmuxMaxReuseTimes: 10,
		XPaddingBytes: "100-1000",
	}
	return p
}

// TestRenderXHTTPTuning pins the sing-box leg of the XHTTP parity fix:
// the lx spellings (xmux snake_case, x_padding_bytes) carry the plan's
// exact values, and an untuned plan renders neither key.
func TestRenderXHTTPTuning(t *testing.T) {
	raw, err := Render(xhttpPlan(), testRuntime)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"xmux":{"c_max_reuse_times":10,"max_concurrency":16}`,
		`"x_padding_bytes":"100-1000"`,
		`"mode":"stream-up"`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("render lacks %s:\n%s", want, raw)
		}
	}
	p := enginetest.Plan(engine.ProtocolVLESS)
	p.Outbounds[0].Flow = "" // XHTTP cannot carry Vision; REALITY stays
	p.Outbounds[0].Transport = engine.Transport{Type: "xhttp", Path: "/xh"}
	raw, err = Render(p, testRuntime)
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"xmux", "x_padding_bytes"} {
		if strings.Contains(string(raw), absent) {
			t.Errorf("an untuned plan must render no %s:\n%s", absent, raw)
		}
	}
	if !strings.Contains(string(raw), `"mode":"auto"`) {
		t.Errorf("unset mode must render the default:\n%s", raw)
	}
}

// TestRenderXHTTPDeterministic pins field-order determinism for the
// XHTTP+REALITY surface (мелочи): two renders of one plan are
// byte-identical.
func TestRenderXHTTPDeterministic(t *testing.T) {
	p := xhttpPlan()
	a, err := Render(p, testRuntime)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Render(p, testRuntime)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("two renders of one plan differ")
	}
}
