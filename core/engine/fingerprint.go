package engine

import (
	"regexp"
	"strings"
)

// Canonical uTLS fingerprint name catalog, ported from sora's
// core/engine/fingerprint.go (snapshot on the audit branch; the
// name set and the versioned-parrot syntax are the reference's).
// Legacy previously had no such catalog — the xray renderer's own
// comment recorded the gap — so a garbage fingerprint name in a
// plan passed validation and failed only late, at the engine
// binary's config check (pinned as a negative control in
// engine/xray/binary_floor_test.go). Validate now refuses such
// names early, by name (see ValidFingerprintName in this file
// and its use in Outbound.Validate in validate.go).
//
// Scope, honestly: this file judges NAMES only. It makes no claim
// about the ClientHello bytes a name resolves to on any engine
// build — freshness of the parrots themselves is a property of
// the pinned engine binaries, exactly as in the reference.

// KnownFingerprints is the union of fingerprint names accepted by
// all three engines, exactly as in the reference. Values outside
// this set are either engine-specific (versioned parrots, below)
// or invalid.
var KnownFingerprints = []string{
	"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random",
}

// versionedParrot matches Xray-style explicit parrots such as
// "hellochrome_131" or "hellofirefox_120" (reference syntax,
// verbatim). sing-box and mihomo do not accept these names; they
// are legitimate plan data only for Xray, but they are not garbage,
// so plan validation accepts them and engine selection/rendering
// remain responsible for the per-engine spelling — the same
// division the reference's FingerprintPolicy.Validate uses.
var versionedParrot = regexp.MustCompile(`^hello(chrome|firefox|ios|safari|edge|android|360|qq)_(\d+(_\d+)?|auto)$`)

// NormalizeFingerprint trims and lowercases a fingerprint name
// coming from a subscription link (reference behaviour).
func NormalizeFingerprint(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// IsKnownFingerprint reports whether name is accepted by every
// engine. An empty name is valid: it means "no fingerprint
// configured" and lets the caller apply its own default.
func IsKnownFingerprint(name string) bool {
	name = NormalizeFingerprint(name)
	if name == "" {
		return true
	}
	for _, known := range KnownFingerprints {
		if name == known {
			return true
		}
	}
	return false
}

// IsVersionedParrot reports whether name looks like an
// engine-specific explicit parrot (Xray spelling).
func IsVersionedParrot(name string) bool {
	return versionedParrot.MatchString(NormalizeFingerprint(name))
}

// IsRandomizedFingerprint reports whether name selects a randomized
// fingerprint (reference set, verbatim).
func IsRandomizedFingerprint(name string) bool {
	switch NormalizeFingerprint(name) {
	case "random", "randomized", "randomizednoalpn", "hellorandomized", "hellorandomizedalpn", "hellorandomizednoalpn":
		return true
	}
	return false
}

// ValidFingerprintName reports whether a plan's TLS fingerprint
// name is one any engine can spell: a known alias, a randomized
// name, or a versioned parrot. Anything else is a typo/garbage
// name that every engine would refuse at load, so plan validation
// refuses it first, by name. This mirrors the acceptance predicate
// of the reference's FingerprintPolicy.Validate.
func ValidFingerprintName(name string) bool {
	n := NormalizeFingerprint(name)
	if n == "" {
		return true
	}
	return IsKnownFingerprint(n) || IsRandomizedFingerprint(n) || IsVersionedParrot(n)
}
