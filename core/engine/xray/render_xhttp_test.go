package xray

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/enginetest"
)

// The tests in this file are ported from sora (S5-SP4): the tuning and
// determinism cases from its censor_p1_xhttp_test.go (minus the
// binary-acceptance case, which needs the pinned binary this repo's
// test rig locates differently) and the downloadSettings cases from
// its render_test.go. Legacy spells the unset-mode default as the
// literal "auto" — it has no engine.DefaultXHTTPMode constant.

func xhttpTuningPlan(t *testing.T) *engine.Plan {
	t.Helper()
	p := enginetest.Plan(engine.ProtocolVLESS)
	o := &p.Outbounds[0]
	o.Flow = "" // XHTTP cannot carry Vision; REALITY stays
	o.Transport = engine.Transport{
		Type: "xhttp", Path: "/xh",
		XHTTP: &engine.XHTTPSettings{Mode: "stream-up",
			XmuxMaxConcurrency: 16, XmuxMaxReuseTimes: 10,
			XPaddingBytes: "100-1000"},
	}
	return p
}

// TestRenderXHTTPTuning pins the Xray leg of the XHTTP parity fix:
// xmux and xPaddingBytes reach xhttpSettings with the plan's exact
// values, and an untuned plan renders neither key.
func TestRenderXHTTPTuning(t *testing.T) {
	raw, err := Render(xhttpTuningPlan(t), testRuntime, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"xmux":{"cMaxReuseTimes":10,"maxConcurrency":16}`,
		`"xPaddingBytes":"100-1000"`,
		`"mode":"stream-up"`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("render lacks %s:\n%s", want, raw)
		}
	}
	p := enginetest.Plan(engine.ProtocolVLESS)
	p.Outbounds[0].Flow = "" // XHTTP cannot carry Vision; REALITY stays
	p.Outbounds[0].Transport = engine.Transport{Type: "xhttp", XHTTP: &engine.XHTTPSettings{Mode: "stream-up"}, Path: "/xh"}
	raw, err = Render(p, testRuntime, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"xmux", "xPaddingBytes"} {
		if strings.Contains(string(raw), absent) {
			t.Errorf("an untuned plan must render no %s:\n%s", absent, raw)
		}
	}
	if !strings.Contains(string(raw), `"mode":"stream-up"`) {
		t.Errorf("explicit mode must pass through:\n%s", raw)
	}
	p.Outbounds[0].Transport.XHTTPBox().Mode = ""
	raw, err = Render(p, testRuntime, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"mode":"auto"`) {
		t.Errorf("unset mode must render the default:\n%s", raw)
	}
}

// TestRenderXHTTPDeterministic pins field-order determinism for the
// XHTTP+REALITY surface (мелочи): two renders of one plan are
// byte-identical.
func TestRenderXHTTPDeterministic(t *testing.T) {
	p := xhttpTuningPlan(t)
	a, err := Render(p, testRuntime, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Render(p, testRuntime, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("two renders of one plan differ")
	}
}

func xhttpVLESS() *engine.Plan {
	p := enginetest.Plan(engine.ProtocolVLESS)
	o := &p.Outbounds[0]
	o.Flow = "" // XTLS Vision is TCP-only; it would (correctly) refuse xhttp.
	o.Transport = engine.Transport{
		Type: "xhttp", Path: "/up",
		XHTTP: &engine.XHTTPSettings{Mode: "stream-up", DownloadAddress: "down.example.com", DownloadPort: 8443},
	}
	return p
}

func TestRenderPassesXHTTPDownloadSettings(t *testing.T) {
	raw, err := Render(xhttpVLESS(), testRuntime, nil)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Outbounds []struct {
			StreamSettings struct {
				XHTTP struct {
					Download struct {
						Address       string `json:"address"`
						Port          int    `json:"port"`
						Network       string `json:"network"`
						Security      string `json:"security"`
						XHTTPSettings struct {
							Path string `json:"path"`
						} `json:"xhttpSettings"`
						RealitySettings struct {
							ServerName string `json:"serverName"`
						} `json:"realitySettings"`
					} `json:"downloadSettings"`
				} `json:"xhttpSettings"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	d := cfg.Outbounds[0].StreamSettings.XHTTP.Download
	if d.Address != "down.example.com" || d.Port != 8443 {
		t.Errorf("downloadSettings = %+v, want down.example.com:8443", d)
	}
	if d.Network != "xhttp" || d.Security != "reality" {
		t.Errorf("downloadSettings = %+v, want an xhttp stream mirroring the main security", d)
	}
	if d.XHTTPSettings.Path != "/up" {
		t.Errorf("downlink path = %q, want the uplink path", d.XHTTPSettings.Path)
	}
	// The downlink SNI must name the downlink host, not the uplink one.
	if d.RealitySettings.ServerName != "down.example.com" {
		t.Errorf("downlink SNI = %q, want down.example.com", d.RealitySettings.ServerName)
	}
}

func TestRenderRefusesBrokenXHTTPDownloadSettings(t *testing.T) {
	cases := map[string]func(*engine.Transport){
		"address without port": func(tr *engine.Transport) { tr.XHTTPBox().DownloadPort = 0 },
		"port without address": func(tr *engine.Transport) { tr.XHTTPBox().DownloadAddress = "" },
		"stream-one mode":      func(tr *engine.Transport) { tr.XHTTPBox().Mode = "stream-one" },
	}
	for name, mutate := range cases {
		p := xhttpVLESS()
		mutate(&p.Outbounds[0].Transport)
		if _, err := Render(p, testRuntime, nil); err == nil {
			t.Errorf("%s: must be refused, not rendered", name)
		}
	}
	// Download fields on a non-XHTTP transport must not be silently dropped.
	p := xhttpVLESS()
	tr := p.Outbounds[0].Transport
	tr.Type = "ws"
	p.Outbounds[0].Transport = tr
	if _, err := Render(p, testRuntime, nil); err == nil {
		t.Error("downloadSettings on websocket: must be refused, not silently dropped")
	}
	// A split plan without an explicit fingerprint must be refused:
	// the downlink would otherwise parrot a different ClientHello
	// than the uplink.
	p = xhttpVLESS()
	p.Outbounds[0].TLS.Fingerprint = ""
	if _, err := Render(p, testRuntime, nil); err == nil {
		t.Error("downloadSettings without a fingerprint: must be refused, not silently defaulted")
	}
}
