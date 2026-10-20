package engine

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"testing"
)

// REVIEW-G G3 differential corpus: the legacy two-replacer layout
// (raw seeds first, derived forms applied to the raw pass's output)
// provably diverged from sora's single combined replacer whenever a
// raw seed is a substring of another seed's derived form — the raw
// pass mangled the form from inside and the tail of the encoding
// leaked. The golden expectations below were produced by sora's
// seed stage (one replacer, pairs in value order, each value followed
// by its derived forms); the reference implementation in
// soraSeedReference rebuilds that stage independently so the layout
// itself stays pinned even if the goldens are edited carelessly.

// soraSeedReference is sora's Redactor.String seed stage, rebuilt
// from its construction rules: seeds shorter than 4 are ignored,
// duplicates dropped, longest first (stable), one strings.Replacer
// over raw+derived pairs, then the pattern pipeline.
func soraSeedReference(seeds []string, s string) string {
	var values []string
	for _, v := range seeds {
		if len(v) < 4 {
			continue
		}
		dup := false
		for _, have := range values {
			if have == v {
				dup = true
				break
			}
		}
		if !dup {
			values = append(values, v)
		}
	}
	sort.SliceStable(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	pairs := make([]string, 0, len(values)*2)
	for _, v := range values {
		pairs = append(pairs, v, "[masked]")
		for _, form := range derivedForms(v) {
			if form != v && len(form) >= 4 {
				pairs = append(pairs, form, "[masked]")
			}
		}
	}
	return maskPatterns(strings.NewReplacer(pairs...).Replace(s))
}

func TestRedactorReviewGCrossSeedForms(t *testing.T) {
	hexA := string([]byte{0xde, 0xad, 0xbe, 0xef}) + "TAIL1234"
	b64A := "p@ss word/1234+&"
	jsonForm := func(v string) string {
		m, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(m[1 : len(m)-1])
	}
	cases := []struct {
		name  string
		seeds []string
		in    string
		want  string
	}{
		// The three divergent vectors from REVIEW-G, verbatim in
		// class: a raw seed inside another seed's derived form.
		{"review hex: raw seed inside hex form", []string{hexA, "deadbeef"},
			"leak " + hex.EncodeToString([]byte(hexA)) + " end", "leak [masked] end"},
		{"review percent: raw seed inside percent form", []string{"aa/bb/cc/dd", "%2Fbb%2F"},
			"leak " + url.QueryEscape("aa/bb/cc/dd") + " end", "leak [masked] end"},
		{"review base64: raw seed inside base64 form", []string{b64A, "cyB3b3Jk"},
			"leak " + base64.StdEncoding.EncodeToString([]byte(b64A)) + " end", "leak [masked] end"},
		// Own cross-seed variants: lowercase percent form, and a
		// hex substring at a non-zero offset inside the form.
		{"lowercase percent cross-seed", []string{"aa/bb/cc/dd", "%2fbb%2f"},
			"leak aa%2fbb%2fcc%2fdd end", "leak [masked] end"},
		{"hex cross-seed at offset", []string{"ZZTAIL1234", "5441494c"},
			"leak " + hex.EncodeToString([]byte("ZZTAIL1234")) + " end", "leak [masked] end"},
		{"json cross-seed", []string{"x&y12345", `\u0026y1`},
			"leak " + jsonForm("x&y12345") + " end", "leak [masked] end"},
		// Classes the review found already identical, pinned so
		// they stay identical.
		{"longer raw seed wins over its prefix seed", []string{"abcd1234", "abcd1234efgh"},
			"leak abcd1234efgh end", "leak [masked] end"},
		{"prefix seed alone", []string{"abcd1234", "abcd1234efgh"},
			"leak abcd1234 end", "leak [masked] end"},
		{"seed that is the base64 of another seed", []string{b64A, base64.StdEncoding.EncodeToString([]byte(b64A))},
			"leak " + base64.StdEncoding.EncodeToString([]byte(b64A)) + " end", "leak [masked] end"},
		{"base64 form of a base64 seed", []string{b64A, base64.StdEncoding.EncodeToString([]byte(b64A))},
			"leak " + base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(b64A)))) + " end", "leak [masked] end"},
		{"regex specials raw", []string{`a+b*c?d[e]f$g1234`},
			`leak a+b*c?d[e]f$g1234 end`, "leak [masked] end"},
		{"regex specials percent form", []string{`a+b*c?d[e]f$g1234`},
			"leak " + url.QueryEscape(`a+b*c?d[e]f$g1234`) + " end", "leak [masked] end"},
		{"empty redactor", nil, "leak nothing end", "leak nothing end"},
		{"short seeds ignored with their forms", []string{"abc", "xy"},
			"leak abc xy 616263 end", "leak abc xy 616263 end"},
		{"clean line untouched", []string{"supersecretpassword123"},
			"2026-10-20T05:30:03Z INF [tun] interface sora0 up, mtu 9000, route 0.0.0.0/0",
			"2026-10-20T05:30:03Z INF [tun] interface sora0 up, mtu 9000, route 0.0.0.0/0"},
		{"raw and hex form on one line", []string{b64A},
			"leak " + b64A + " and " + hex.EncodeToString([]byte(b64A)) + " end", "leak [masked] and [masked] end"},
		{"derived form twice on one line", []string{b64A},
			"leak " + base64.StdEncoding.EncodeToString([]byte(b64A)) + " mid " + base64.StdEncoding.EncodeToString([]byte(b64A)) + " end",
			"leak [masked] mid [masked] end"},
		{"padded base64 form", []string{b64A},
			"leak " + base64.StdEncoding.EncodeToString([]byte(b64A)) + " end", "leak [masked] end"},
		{"raw base64 form inside padded form's line", []string{b64A},
			"leak " + base64.RawStdEncoding.EncodeToString([]byte(b64A)) + " end", "leak [masked] end"},
		{"json form with & and angle brackets", []string{"tok&en<12345>"},
			"leak " + jsonForm("tok&en<12345>") + " end", "leak [masked] end"},
		{"json form with quote and backslash", []string{`q"uote\back1234`},
			"leak " + jsonForm(`q"uote\back1234`) + " end", "leak [masked] end"},
	}
	for _, c := range cases {
		if got := NewRedactor(c.seeds...).String(c.in); got != c.want {
			t.Errorf("%s:\n in:   %q\nwant: %q\n got: %q", c.name, c.in, c.want, got)
		}
		if got, ref := NewRedactor(c.seeds...).String(c.in), soraSeedReference(c.seeds, c.in); got != ref {
			t.Errorf("%s: differs from sora seed-stage reference:\n in:  %q\nref: %q\n got: %q", c.name, c.in, ref, got)
		}
	}
}

// TestRedactorReviewGCombinatorialDifferential sweeps combinations
// of fragments built from cross-related seeds and their forms: every
// input must match the sora seed-stage reference byte for byte. This
// is the differential harness REVIEW-G ran ad hoc (16 cases); here
// it is permanent and wider.
func TestRedactorReviewGCombinatorialDifferential(t *testing.T) {
	hexA := string([]byte{0xde, 0xad, 0xbe, 0xef}) + "TAIL1234"
	seeds := []string{hexA, "deadbeef", "aa/bb/cc/dd", "%2Fbb%2F", "p@ss word/1234+&", "cyB3b3Jk"}
	fragments := []string{
		"leak", "end", " ",
		hexA, "deadbeef",
		hex.EncodeToString([]byte(hexA)),
		"aa/bb/cc/dd", "%2Fbb%2F",
		url.QueryEscape("aa/bb/cc/dd"),
		"aa%2fbb%2fcc%2fdd",
		"p@ss word/1234+&", "cyB3b3Jk",
		base64.StdEncoding.EncodeToString([]byte("p@ss word/1234+&")),
		hex.EncodeToString([]byte("p@ss word/1234+&")),
		"[masked]",
		"5441494c31323334",
	}
	r := NewRedactor(seeds...)
	var inputs []string
	inputs = append(inputs, fragments...)
	for _, a := range fragments {
		for _, b := range fragments {
			inputs = append(inputs, a+" "+b)
			inputs = append(inputs, a+b)
		}
	}
	for _, in := range inputs {
		if got, ref := r.String(in), soraSeedReference(seeds, in); got != ref {
			t.Errorf("differential mismatch:\n in:  %q\nref: %q\n got: %q", in, ref, got)
		}
	}
}
