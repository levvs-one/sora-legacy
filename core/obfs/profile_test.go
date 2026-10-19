package obfs

import (
	"errors"
	"testing"
	"time"
)

func TestValidateAcceptsPresetsAndZero(t *testing.T) {
	for name, p := range map[string]Profile{
		"zero":     {},
		"fast":     PresetFast,
		"balanced": PresetBalanced,
		"max":      PresetMax,
	} {
		if err := p.Validate(); err != nil {
			t.Errorf("%s: Validate() = %v, want nil", name, err)
		}
	}
}

func TestValidateRejectsBadProfiles(t *testing.T) {
	cases := []struct {
		name    string
		profile Profile
	}{
		{"unknown fingerprint", Profile{UTLS: "internet-explorer"}},
		{"empty frag sizes", Profile{FragSizes: []int{}}},
		{"zero frag size", Profile{FragSizes: []int{0}}},
		{"negative frag size", Profile{FragSizes: []int{64, -1}}},
		{"oversize frag", Profile{FragSizes: []int{MaxFragmentSize + 1}}},
		{"negative delay", Profile{FragDelay: -time.Second}},
	}
	for _, tc := range cases {
		if err := tc.profile.Validate(); err == nil {
			t.Errorf("%s: Validate() = nil, want error", tc.name)
		}
	}
}

func TestValidateIsCaseInsensitive(t *testing.T) {
	p := Profile{UTLS: "  Chrome "}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if !p.UTLSEnabled() {
		t.Error("UTLSEnabled() = false for \"  Chrome \", want true")
	}
}

func TestClampCapsDelays(t *testing.T) {
	p := (Profile{FragDelay: time.Hour}).Clamp()
	if p.FragDelay != MaxFragDelay {
		t.Errorf("FragDelay = %s, want %s", p.FragDelay, MaxFragDelay)
	}
	// Clamp must not mutate the receiver's other fields.
	orig := Profile{UTLS: UTLSChrome, FragSizes: []int{64}, FragDelay: time.Hour}
	clamped := orig.Clamp()
	if orig.FragDelay != time.Hour {
		t.Error("Clamp mutated the original profile")
	}
	if clamped.UTLS != UTLSChrome || len(clamped.FragSizes) != 1 {
		t.Error("Clamp dropped profile fields")
	}
}

func TestFragmentationAndUTLSEnabled(t *testing.T) {
	if (Profile{}).Fragmentation() {
		t.Error("zero profile reports fragmentation")
	}
	if !(Profile{FragSizes: []int{32}}).Fragmentation() {
		t.Error("profile with FragSizes reports no fragmentation")
	}
	for _, name := range []string{"", "none", "NONE"} {
		if (Profile{UTLS: name}).UTLSEnabled() {
			t.Errorf("UTLS %q reports enabled", name)
		}
	}
	for _, name := range []string{UTLSChrome, UTLSFirefox, UTLSSafari, UTLSRandomized} {
		if !(Profile{UTLS: name}).UTLSEnabled() {
			t.Errorf("UTLS %q reports disabled", name)
		}
	}
}

func TestFingerprintIDMapping(t *testing.T) {
	for _, name := range []string{UTLSChrome, UTLSFirefox, UTLSSafari, UTLSRandomized} {
		id, err := (Profile{UTLS: name}).FingerprintID()
		if err != nil {
			t.Errorf("FingerprintID(%q) = %v, want nil", name, err)
			continue
		}
		if id.Client == "" {
			t.Errorf("FingerprintID(%q) has empty Client", name)
		}
	}
	for _, name := range []string{"", "none"} {
		if _, err := (Profile{UTLS: name}).FingerprintID(); !errors.Is(err, ErrUTLSDisabled) {
			t.Errorf("FingerprintID(%q) = %v, want ErrUTLSDisabled", name, err)
		}
	}
	if _, err := (Profile{UTLS: "mosaic"}).FingerprintID(); err == nil {
		t.Error("FingerprintID(mosaic) = nil, want error")
	}
}
