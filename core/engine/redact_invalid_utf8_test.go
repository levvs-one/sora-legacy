package engine

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// REVIEW-PERFFIX (legacy deliberately stronger than the sora
// reference): seeds are credentials lifted from provider configs and
// may hold arbitrary bytes, not valid UTF-8. The ported
// singleEscapes sliced v[i+utf8.RuneLen(r):] on its rune walk, but
// RuneLen(RuneError) is 3 while an invalid byte decodes as RuneError
// with size 1 — a seed ending in invalid bytes panicked the redactor
// build (138/200 byte-fuzz seeds), and an invalid byte mid-seed
// silently skipped the two bytes after it, manufacturing forms no
// encoder emits and dropping the ones it does. The sora snapshot in
// redact_review_g_test.go panics the same way; it is therefore NOT
// used as the reference for the invalid seeds below — the contract
// here is only: no panic, masking keeps working, and the byte-based
// and valid-position forms of such seeds are still registered. For
// valid UTF-8 seeds the fix must change nothing, pinned against the
// snapshot by TestRedactorValidUTF8MatchesSnapshot below.
func TestRedactorInvalidUTF8SeedsDoNotPanicAndStillMask(t *testing.T) {
	cases := []struct {
		name string
		seed string
	}{
		{"lone 0xFF at end", "secret1234\xff"},
		{"lone 0xFF in middle", "secr\xffet12345"},
		{"truncated two-byte sequence at end", "secret1234\xc3"},
		{"truncated three-byte sequence at end", "secret1234\xe2\x82"},
		{"truncated three-byte sequence in middle", "sec\xe2\x82ret12345"},
		{"continuation byte 0x80 in middle", "secret\x8012345abc"},
		{"continuation byte 0x80 at end", "secret1234\x80"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := NewRedactor(c.seed)
			// Byte-based forms of the seed: raw, hex, base64 and the
			// percent-encode-all form are encodings of the seed's
			// bytes and must mask exactly as for a valid seed.
			forms := map[string]string{
				"raw":               c.seed,
				"hex":               hex.EncodeToString([]byte(c.seed)),
				"base64":            base64.StdEncoding.EncodeToString([]byte(c.seed)),
				"percent all":       percentEncodeAll(c.seed, true),
				"single % escape":   "%73" + c.seed[1:], // %73 is 's', the first byte of every seed above
				"single \\u escape": `\u0073` + c.seed[1:],
			}
			for formName, form := range forms {
				out := r.String("leak " + form + " end")
				if out != "leak [masked] end" {
					t.Errorf("%s form of an invalid-UTF-8 seed leaked:\nform: %q\n out: %q", formName, form, out)
				}
			}
			// A clean line stays byte-identical (and allocation-free,
			// pinned by BenchmarkRedactCleanLine).
			clean := "2026-10-20T05:30:03Z INF [tun] interface sora0 up, mtu 9000"
			if out := r.String(clean); out != clean {
				t.Errorf("clean line changed: %q", out)
			}
		})
	}
}

// TestRedactorInvalidUTF8SingleEscapeForms pins the size-1 semantics
// themselves: the invalid byte is one rune position (escaped as
// \ufffd, the replacement an encoder's decoder would produce), and
// the walk resumes at the very next byte instead of skipping it.
func TestRedactorInvalidUTF8SingleEscapeForms(t *testing.T) {
	seed := "ab\xffcd1234"
	forms := derivedForms(seed)
	for _, want := range []string{
		`ab\ufffdcd1234`, // invalid byte as \ufffd, lower hex digits
		`ab\uFFFDcd1234`, // same position, upper hex digits
		"ab%FFcd1234",    // per-byte percent form of the invalid byte
		"ab%ffcd1234",
		"ab\xff\\u0063d1234", // the rune AFTER the invalid byte, escaped at its own offset
	} {
		found := false
		for _, form := range forms {
			if form == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("derivedForms(%q) holds no %q", seed, want)
		}
	}
}

// TestRedactorInvalidUTF8ByteSweep runs every invalid byte value at
// the start, in the middle and at the end of a seed: building the
// redactor and masking the raw seed must never panic.
func TestRedactorInvalidUTF8ByteSweep(t *testing.T) {
	base := "secret1234"
	for b := 0x80; b <= 0xff; b++ {
		seed := string([]byte{byte(b)}) + base
		if out := NewRedactor(seed).String("leak " + seed + " end"); out != "leak [masked] end" {
			t.Fatalf("byte %#x at start: raw form leaked: %q", b, out)
		}
		seed = base[:4] + string([]byte{byte(b)}) + base[4:]
		if out := NewRedactor(seed).String("leak " + seed + " end"); out != "leak [masked] end" {
			t.Fatalf("byte %#x in middle: raw form leaked: %q", b, out)
		}
		seed = base + string([]byte{byte(b)})
		if out := NewRedactor(seed).String("leak " + seed + " end"); out != "leak [masked] end" {
			t.Fatalf("byte %#x at end: raw form leaked: %q", b, out)
		}
	}
}

// TestRedactorValidUTF8MatchesSnapshot: for valid UTF-8 seeds —
// multibyte, above-BMP, and an honestly encoded U+FFFD (which decodes
// as RuneError with size 3, exactly like the old RuneLen walk) — the
// redactor's output stays byte-identical to the sora snapshot
// reference after the invalid-UTF-8 fix.
func TestRedactorValidUTF8MatchesSnapshot(t *testing.T) {
	seeds := []string{
		"pässwörd-1234",
		"секретный-пароль-1234",
		"token-😀-1234",
		"abc\ufffddef-1234",
		"mot de passe été 1234",
	}
	for _, seed := range seeds {
		r := NewRedactor(seed)
		inputs := []string{
			"leak " + seed + " end",
			"leak " + hex.EncodeToString([]byte(seed)) + " end",
			"leak " + base64.StdEncoding.EncodeToString([]byte(seed)) + " end",
			"leak " + unicodeEscapeAll(seed, unicodeDigitsLower) + " end",
			"leak " + unicodeEscapeAll(seed, unicodeDigitsUpper) + " end",
		}
		for _, form := range soraSingleEscapes(seed) {
			inputs = append(inputs, "leak "+form+" end")
		}
		for _, in := range inputs {
			if got, ref := r.String(in), soraSeedReference([]string{seed}, in); got != ref {
				t.Errorf("seed %q: output differs from sora snapshot:\n in:  %q\nref: %q\n got: %q", seed, in, ref, got)
			}
			if strings.Contains(r.String(in), seed) && in != "leak "+seed+" end" {
				// Only the raw input may contain the seed at all, and
				// it must be masked there too (checked against ref).
				t.Errorf("seed %q leaked in %q", seed, in)
			}
		}
	}
}
