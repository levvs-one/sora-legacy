package engine

import (
	"slices"
	"strings"
	"testing"
)

// TestFingerprintCatalogParityPin pins the fingerprint name
// catalog against the reference's set, written out in full here
// (sora core/engine/fingerprint.go: KnownFingerprints, the
// versioned-parrot syntax and the randomized set). The expected
// values are literals in this test — not derived from the catalog
// under test — so a drift in fingerprint.go fails here. This is
// the executable parity pin for §8.8's early fingerprint
// validation; the catalog is plain plan-validation data, so no
// contract or mirror change was needed to carry it.
func TestFingerprintCatalogParityPin(t *testing.T) {
	wantKnown := []string{"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random"}
	if !slices.Equal(KnownFingerprints, wantKnown) {
		t.Fatalf("KnownFingerprints = %v, want the reference set %v", KnownFingerprints, wantKnown)
	}
	for _, name := range []string{"hellochrome_131", "HelloChrome_155", "hellofirefox_120", "helloios_auto", "hellochrome_auto"} {
		if !IsVersionedParrot(name) {
			t.Errorf("IsVersionedParrot(%q) = false, want true (reference syntax)", name)
		}
	}
	for _, name := range []string{"chrome", "random", "hellochrome_", "hellonokia_3310", "bogus-fp"} {
		if IsVersionedParrot(name) {
			t.Errorf("IsVersionedParrot(%q) = true, want false", name)
		}
	}
	for _, name := range []string{"random", "randomized", "Randomized", "hellorandomizedalpn", "randomizednoalpn"} {
		if !IsRandomizedFingerprint(name) {
			t.Errorf("IsRandomizedFingerprint(%q) = false, want true (reference set)", name)
		}
	}
}

// TestValidateRejectsGarbageFingerprintEarly is the §8.8 fix: a
// garbage fingerprint name must fail at plan validation with a
// named refusal, not late at the engine binary's config check.
func TestValidateRejectsGarbageFingerprintEarly(t *testing.T) {
	base := func() Outbound {
		return Outbound{
			ID: "fp1", Protocol: ProtocolVLESS, Server: "203.0.113.7", Port: 443,
			TLS: TLS{Enabled: true, ServerName: "example.com"},
		}
	}
	for _, bad := range []string{"bogus-fp", "not-a-parrot", "opera", "chrome133", "hello chrome"} {
		o := base()
		o.TLS.Fingerprint = bad
		err := o.Validate()
		if err == nil || !strings.Contains(err.Error(), "fingerprint") || !strings.Contains(err.Error(), bad) {
			t.Errorf("Validate(fingerprint %q) = %v, want a named fingerprint refusal", bad, err)
		}
		// The plan-level entry point must surface the same refusal.
		p := &Plan{SessionID: "s1", Outbounds: []Outbound{o}}
		if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "fingerprint") {
			t.Errorf("Plan.Validate(fingerprint %q) = %v, want a named fingerprint refusal", bad, err)
		}
	}
	// Every legitimate spelling stays valid: known aliases in any
	// case, randomized names, versioned parrots, and the empty
	// (unconfigured) name.
	for _, good := range []string{"", "chrome", "Chrome", " CHROME ", "firefox", "iOS", "random", "randomized", "hellochrome_133", "hellochrome_auto", "hellofirefox_148"} {
		o := base()
		o.TLS.Fingerprint = good
		if err := o.Validate(); err != nil {
			t.Errorf("Validate(fingerprint %q) = %v, want nil", good, err)
		}
	}
}
