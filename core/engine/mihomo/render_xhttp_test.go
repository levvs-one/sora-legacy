package mihomo

import (
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/enginetest"
)

// The tests in this file are ported from sora's mihomo render_test.go
// (S5-SP4): the reuse-settings and download-settings legs of its XHTTP
// parity work.

// TestRenderXHTTPReuseSettings pins the reuse-settings rule: without
// the block mihomo disables connection reuse entirely (no default
// value upstream — every request opens a new connection), so the
// block is always rendered: the docs' example default when the plan
// tunes nothing, the plan's tuning when it does.
func TestRenderXHTTPReuseSettings(t *testing.T) {
	xhttpPlan := func(mut func(*engine.Transport)) *engine.Plan {
		p := enginetest.Plan(engine.ProtocolVLESS)
		p.Outbounds[0].Flow = ""
		tr := engine.Transport{Type: "xhttp", Path: "/x", Host: "cdn.example.com"}
		if mut != nil {
			mut(&tr)
		}
		p.Outbounds[0].Transport = tr
		return p
	}
	render := func(p *engine.Plan) string {
		out, err := Render(p, testRuntime(t))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	out := render(xhttpPlan(nil))
	if !strings.Contains(out, "reuse-settings:") || !strings.Contains(out, "16-32") {
		t.Fatalf("an untuned xhttp plan must still render reuse-settings with the docs default:\n%s", out)
	}

	out = render(xhttpPlan(func(tr *engine.Transport) {
		tr.XHTTPBox().XmuxMaxConnections = 4
		tr.XHTTPBox().XmuxMaxReuseTimes = 10
		tr.XHTTPBox().XmuxMaxRequestTimes = 600
		tr.XHTTPBox().XPaddingBytes = "100-1000"
	}))
	for _, want := range []string{"max-connections:", "c-max-reuse-times:", "h-max-request-times:", "x-padding-bytes: 100-1000"} {
		if !strings.Contains(out, want) {
			t.Fatalf("tuned xhttp render is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "max-concurrency") {
		t.Fatalf("a tuned plan must not grow the default max-concurrency (it conflicts with max-connections):\n%s", out)
	}

	// mode: auto is a documented mihomo mode value and must pass
	// through verbatim.
	out = render(xhttpPlan(func(tr *engine.Transport) { tr.XHTTPBox().Mode = "auto" }))
	if !strings.Contains(out, "mode: auto") {
		t.Fatalf("mode auto must render verbatim:\n%s", out)
	}
}

// TestRenderXHTTPDownloadSettings pins the download-settings leg: a
// split plan renders the separate downlink server with its own
// reuse-settings; unset items inherit the uplink.
func TestRenderXHTTPDownloadSettings(t *testing.T) {
	p := enginetest.Plan(engine.ProtocolVLESS)
	p.Outbounds[0].Flow = ""
	p.Outbounds[0].Transport = engine.Transport{
		Type: "xhttp", Path: "/x", Host: "cdn.example.com",
		XHTTP: &engine.XHTTPSettings{Mode: "stream-up", DownloadAddress: "dl.example.com", DownloadPort: 8443},
	}
	out, err := Render(p, testRuntime(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"download-settings:", "server: dl.example.com", "port: 8443"} {
		if !strings.Contains(out, want) {
			t.Fatalf("split xhttp render is missing %q:\n%s", want, out)
		}
	}
}
