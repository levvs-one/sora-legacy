package obfs

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Fingerprint names accepted by Profile.UTLS. The empty string means "none".
const (
	UTLSNone       = "none"
	UTLSChrome     = "chrome"
	UTLSFirefox    = "firefox"
	UTLSSafari     = "safari"
	UTLSRandomized = "randomized"
)

// Hard limits. Delays above these are clamped (never rejected) so a
// misconfigured profile degrades gracefully instead of hanging forever.
const (
	// MaxFragDelay caps the pause between ClientHello fragments.
	MaxFragDelay = 2 * time.Second
	// MaxFragmentSize caps a single ClientHello fragment payload: a TLS
	// record payload never exceeds 2^14 bytes.
	MaxFragmentSize = 16 * 1024
)

// Profile describes one obfuscation setup for TLS handshakes the core
// initiates itself (subscription fetches, direct TLS dials).
//
// A zero Profile is valid and means "no obfuscation".
type Profile struct {
	// UTLS selects the ClientHello fingerprint: "chrome", "firefox",
	// "safari", "randomized", "none" ("" is treated as "none").
	// It only takes effect on direct TLS dials through Dialer: the
	// subscription fetcher's http.Transport owns its TLS handshake and
	// cannot use uTLS (see the package doc).
	UTLS string

	// FragSizes enables ClientHello fragmentation when non-nil. Each entry
	// is the size of one leading chunk of the first TLS record's bytes;
	// the remainder of the record forms the final chunk. A non-nil but
	// empty slice is rejected by Validate as ambiguous: use nil to
	// disable.
	FragSizes []int

	// FragDelay is the pause between ClientHello fragments. Clamped to
	// MaxFragDelay.
	FragDelay time.Duration
}

// PresetFast is the lightest touch: a common browser fingerprint, no
// fragmentation, no artificial delays.
var PresetFast = Profile{UTLS: UTLSChrome}.Clamp()

// PresetBalanced adds modest fragmentation on top of a browser
// fingerprint. Suitable as the default for subscription fetches.
var PresetBalanced = Profile{
	UTLS:      UTLSChrome,
	FragSizes: []int{64, 128},
	FragDelay: 10 * time.Millisecond,
}.Clamp()

// PresetMax is the most aggressive masking: randomized fingerprint and
// aggressive fragmentation. Handshakes take longer.
var PresetMax = Profile{
	UTLS:      UTLSRandomized,
	FragSizes: []int{32, 64, 96},
	FragDelay: 50 * time.Millisecond,
}.Clamp()

// Validate reports whether the profile is well-formed. Extreme but
// representable delays are not errors: they are normalized by Clamp.
func (p Profile) Validate() error {
	switch normalizeUTLS(p.UTLS) {
	case "", UTLSNone, UTLSChrome, UTLSFirefox, UTLSSafari, UTLSRandomized:
	default:
		return fmt.Errorf("obfs: unknown UTLS fingerprint %q", p.UTLS)
	}
	if p.FragSizes != nil && len(p.FragSizes) == 0 {
		return errors.New("obfs: FragSizes is non-nil but empty: use nil to disable fragmentation")
	}
	for i, s := range p.FragSizes {
		if s <= 0 {
			return fmt.Errorf("obfs: FragSizes[%d] = %d: must be positive", i, s)
		}
		if s > MaxFragmentSize {
			return fmt.Errorf("obfs: FragSizes[%d] = %d: exceeds max TLS record payload %d", i, s, MaxFragmentSize)
		}
	}
	if p.FragDelay < 0 {
		return fmt.Errorf("obfs: FragDelay = %s: must not be negative", p.FragDelay)
	}
	return nil
}

// Clamp returns a copy of the profile with delays limited to their maxima.
func (p Profile) Clamp() Profile {
	if p.FragDelay > MaxFragDelay {
		p.FragDelay = MaxFragDelay
	}
	return p
}

// Fragmentation reports whether ClientHello fragmentation is enabled.
func (p Profile) Fragmentation() bool { return len(p.FragSizes) > 0 }

// UTLSEnabled reports whether a uTLS fingerprint is selected.
func (p Profile) UTLSEnabled() bool {
	switch normalizeUTLS(p.UTLS) {
	case UTLSChrome, UTLSFirefox, UTLSSafari, UTLSRandomized:
		return true
	}
	return false
}

func normalizeUTLS(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
