package xray

import (
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/enginetest"
)

// REVIEW-SP45 §3.3 / SP6b commit C: the production path is fail-closed
// (no legacy engine claims FeatureRealityKeyShare, so Supervisor.admit
// refuses a KeyShare plan), but a bare Render in bypass of admit used
// to drop the pin silently. The reference's xray renderer refuses it;
// this backstop is ported verbatim, error text included. Sing-box and
// mihomo in the reference RENDER key_share rather than refusing it,
// so no symmetric refusal is ported there — and legacy's bare-Render
// ECH drop likewise has no reference refusal to port (the reference
// renders ECH on all three engines; that is a feature port, not a
// backstop). Both stay gated at admit, as before.
func TestRenderRefusesRealityKeyShare(t *testing.T) {
	for _, ks := range []string{"hybrid", "classical"} {
		p := enginetest.Plan(engine.ProtocolVLESS)
		p.Outbounds[0].TLS.KeyShare = ks
		_, err := Render(p, testRuntime, nil)
		if err == nil {
			t.Fatalf("KeyShare %q: a bare Render must refuse the pin instead of dropping it", ks)
		}
		want := "pins a REALITY key_share, which Xray does not expose"
		if !strings.Contains(err.Error(), want) {
			t.Errorf("KeyShare %q: error = %v, want it to name %q", ks, err, want)
		}
	}
	// Control: the same plan without the pin renders.
	p := enginetest.Plan(engine.ProtocolVLESS)
	if _, err := Render(p, testRuntime, nil); err != nil {
		t.Fatalf("the unpinned plan must render: %v", err)
	}
}
