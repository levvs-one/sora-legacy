package engine_test

import (
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/enginetest"
)

// LEGACY-FULL WS2: the Xray catalog floor and the shipped Windows
// payload pin are the same build (26.3.27, Xray-win7-32). The floor
// exists because the payload it replaced (25.9.11) provably cannot
// carry one claimed protocol: Xray gained its Hysteria outbound and
// transport with upstream PR 5508 (first tagged in v26.1.13), and
// the 25.9.11
// binary refuses the renderer's Hy2 render with "unknown transport
// protocol: hysteria" (binary corpus in LEGACY-FULL-2-XRAY.md).
// These tests pin the resolution in both directions so the pin and
// the floor cannot silently drift apart again: the old payload is
// rejected before rendering for ANY plan, and the floor build is
// accepted for the plain and the Hysteria2 plans alike.
func TestXrayFloorRejectsOldPayloadAndAcceptsShippedPin(t *testing.T) {
	if got := engine.Catalog[engine.KindXray].MinVersion; got != "26.3.27" {
		t.Fatalf("Xray MinVersion = %q, want 26.3.27 (the shipped payload pin, LEGACY-FULL WS2)", got)
	}
	old, err := engine.ParseVersion("25.9.11")
	if err != nil {
		t.Fatal(err)
	}
	shipped, err := engine.ParseVersion("26.3.27")
	if err != nil {
		t.Fatal(err)
	}
	hy2 := enginetest.Plan(engine.ProtocolHysteria2)
	hy2.Outbounds[0].Obfs, hy2.Outbounds[0].ObfsParam = "", ""
	for name, plan := range map[string]*engine.Plan{
		"plain vless": enginetest.Plan(engine.ProtocolVLESS),
		"hysteria2":   hy2,
	} {
		availOld := []engine.Availability{{Kind: engine.KindXray, Usable: true, Version: old}}
		if _, err := engine.SelectEngine(plan, availOld, []engine.Kind{engine.KindXray}); err == nil ||
			!strings.Contains(err.Error(), "version 25.9.11 is older than 26.3.27") {
			t.Errorf("%s: SelectEngine(25.9.11) = %v, want the floor rejection", name, err)
		}
		availNew := []engine.Availability{{Kind: engine.KindXray, Usable: true, Version: shipped}}
		sel, err := engine.SelectEngine(plan, availNew, []engine.Kind{engine.KindXray})
		if err != nil {
			t.Errorf("%s: SelectEngine(26.3.27) = %v, want the shipped pin to carry the plan", name, err)
		} else if sel.Kind != engine.KindXray {
			t.Errorf("%s: SelectEngine(26.3.27) picked %s, want xray", name, sel.Kind)
		}
	}
	// The one capability that forces the floor: the old payload's
	// catalog entry must not be reachable, but the floor build's
	// static claims include Hysteria2 (binary-proved on 26.3.27).
	caps := engine.BuildCapabilities(engine.KindXray, shipped, nil)
	if !caps.SupportsProtocol(engine.ProtocolHysteria2) {
		t.Error("floor build must claim protocol hysteria2 (binary-proved, LEGACY-FULL WS2)")
	}
}
