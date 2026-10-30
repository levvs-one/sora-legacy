package engine

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
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
// by its derived forms).
//
// REVIEW-GFOLLOWUP G3-F2: the first version of this reference called
// the production derivedForms/maskPatterns of THIS package, so any
// drift in the form set or the pattern pipeline was invisible to it
// by construction — exactly how the bc54d959 derivedForms extension
// (uppercase hex, percentEncodeAll, per-rune and single-escape forms)
// and the maskPatterns drift of G3-F3 stayed green here. The
// reference below is therefore a SNAPSHOT: verbatim copies of the
// seed-stage and pattern functions from sora's core/engine/redact.go
// at commit 1ec551910016e292eadf666da43b1f8a9715fc9c (HEAD at the
// time of the port; derivedForms/maskPatterns last changed there in
// bc54d959/bf0bf820), renamed with a sora prefix only so they can
// coexist with the production functions in one package. It calls no
// production code. "Byte-identical to sora" anywhere in this package
// means byte-identical to this snapshot — when porting a newer sora
// redactor, refresh the snapshot by diffing it against the new sora
// source, never by pointing it back at production.
//
// Revalidation (final pass 3, 2026-10-22): the snapshot was checked
// against sora's LIVE redactor at sora HEAD 18c3f551 — the only sora
// change to redact.go since 1ec55191 is a dead-code removal
// (keyGateWords, ad8d6171), and a behavioral differential over the
// combinatorial corpus of TestRedactorReviewGCombinatorialDifferential
// plus pattern-only lines (909 outputs) came out byte-identical
// between the two repositories' production redactors. The snapshot
// therefore still pins current sora behavior, not a stale fork.

// --- BEGIN snapshot of sora@1ec55191 core/engine/redact.go ---

func soraDerivedForms(v string) []string {
	forms := make([]string, 0, 10)
	add := func(s string) {
		for _, have := range forms {
			if have == s {
				return
			}
		}
		forms = append(forms, s)
	}
	for _, esc := range []string{url.QueryEscape(v), url.PathEscape(v)} {
		add(esc)
		add(soraLowerPercentHex(esc))
	}
	add(soraPercentEncodeAll(v, true))
	add(soraPercentEncodeAll(v, false))
	raw := []byte(v)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		add(enc.EncodeToString(raw))
	}
	lowerHex := hex.EncodeToString(raw)
	add(lowerHex)
	add(strings.ToUpper(lowerHex))
	if marshalled, err := json.Marshal(v); err == nil && len(marshalled) >= 2 {
		inner := string(marshalled[1 : len(marshalled)-1])
		add(inner)
		add(soraUpperUnicodeHexDigits(inner))
	}
	uni := soraUnicodeEscapeAll(v)
	add(uni)
	add(soraUpperUnicodeHexDigits(uni))
	if len(v) <= 64 {
		for _, form := range soraSingleEscapes(v) {
			add(form)
		}
	}
	return forms
}

func soraPercentEncodeAll(v string, upper bool) string {
	const digitsLower, digitsUpper = "0123456789abcdef", "0123456789ABCDEF"
	digits := digitsLower
	if upper {
		digits = digitsUpper
	}
	var b strings.Builder
	b.Grow(len(v) * 3)
	for i := 0; i < len(v); i++ {
		c := v[i]
		b.WriteByte('%')
		b.WriteByte(digits[c>>4])
		b.WriteByte(digits[c&0x0f])
	}
	return b.String()
}

func soraUnicodeEscapeAll(v string) string {
	var b strings.Builder
	for _, r := range v {
		soraWriteUnicodeEscape(&b, r)
	}
	return b.String()
}

func soraWriteUnicodeEscape(b *strings.Builder, r rune) {
	const digits = "0123456789abcdef"
	put := func(u uint16) {
		b.WriteString(`\u`)
		for shift := 12; shift >= 0; shift -= 4 {
			b.WriteByte(digits[(u>>uint(shift))&0x0f])
		}
	}
	if r > 0xffff {
		r -= 0x10000
		put(uint16(0xd800 + (r >> 10)))
		put(uint16(0xdc00 + (r & 0x3ff)))
		return
	}
	put(uint16(r))
}

func soraUpperUnicodeHexDigits(s string) string {
	b := []byte(s)
	for i := 0; i+5 < len(b); i++ {
		if b[i] != '\\' || b[i+1] != 'u' {
			continue
		}
		ok := true
		for j := i + 2; j <= i+5; j++ {
			c := b[j]
			if (c < '0' || '9' < c) && (c < 'a' || 'f' < c) && (c < 'A' || 'F' < c) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		for j := i + 2; j <= i+5; j++ {
			if 'a' <= b[j] && b[j] <= 'f' {
				b[j] -= 'a' - 'A'
			}
		}
		i += 5
	}
	return string(b)
}

func soraSingleEscapes(v string) []string {
	const digitsLower, digitsUpper = "0123456789abcdef", "0123456789ABCDEF"
	var out []string
	for i := 0; i < len(v); i++ {
		for _, digits := range []string{digitsUpper, digitsLower} {
			c := v[i]
			out = append(out, v[:i]+"%"+string([]byte{digits[c>>4], digits[c&0x0f]})+v[i+1:])
		}
	}
	for i, r := range v {
		var esc strings.Builder
		soraWriteUnicodeEscape(&esc, r)
		lower := esc.String()
		for _, form := range []string{lower, soraUpperUnicodeHexDigits(lower)} {
			out = append(out, v[:i]+form+v[i+len(string(r)):])
		}
	}
	return out
}

func soraLowerPercentHex(s string) string {
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] != '%' {
			continue
		}
		for j := i + 1; j <= i+2; j++ {
			if 'A' <= b[j] && b[j] <= 'F' {
				b[j] += 'a' - 'A'
			}
		}
		i += 2
	}
	return string(b)
}

var (
	soraUUIDPattern             = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	soraKeyValuePattern         = regexp.MustCompile(`(?i)\b(uuid|password|passwd|secret|(?:access|refresh|session|id|auth|api)[_-]?token|token|private[_-]?key|pre[_-]?shared[_-]?key|obfs[_-]?password|obfs[_-]?param|api[_-]?key|auth(?:[_-]?str)?|secret[_-]?key|client[_-]?secret|psk|public[_-]?key|short[_-]?id|spider[_-]?x|username)\b([\"']?\s*[:=]\s*|\s+)("(?:\\.|[^"\\])*"[^\s,;}\]\)]*|'(?:\\.|[^'\\])*'[^\s,;}\]\)]*|\S+)`)
	soraStrictKeyValuePattern   = regexp.MustCompile(`(?i)\b(user|login|key|code|session|seed|hwid|device[_-]?id|session[_-]?id|sni|server[_-]?name|servername|dest|encryption|service[_-]?name|servicename|host)\b([\"']?\s*[:=]\s*)("(?:\\.|[^"\\])*"[^\s,;}\]\)]*|'(?:\\.|[^'\\])*'[^\s,;}\]\)]*|\S+)`)
	soraUserInfoPattern         = regexp.MustCompile(`(?i)\b(https?|socks5?h?|socks4a?|ssr?|vless|vmess|trojan|hysteria2?|hy2|tuic|wireguard|wg|naive|snell)://[^/\s@]+@`)
	soraTokenLinkPattern        = regexp.MustCompile(`(?i)\b(vmess|ssr)://[A-Za-z0-9+/_=-]+`)
	soraAuthHeaderPattern       = regexp.MustCompile(`(?i)\b(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)(\S+)`)
	soraSubscriptionPathPattern = regexp.MustCompile(`(?i)\b(https?://[^\s/]+/(?:(?:api|v[0-9]+)/)*(?:sub|subscribe|subscription|feed|token|link)/)[A-Za-z0-9._~%+/=-]{8,}`)
	soraBearerPattern           = regexp.MustCompile(`(?i)\b(bearer\s+)([A-Za-z0-9._~+/=-]{12,})`)
)

func soraReplaceKeyValues(re *regexp.Regexp, s string) string {
	matches := re.FindAllStringSubmatchIndex(s, -1)
	if matches == nil {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, m := range matches {
		if m[6] < 0 {
			continue
		}
		b.WriteString(s[last:m[0]])
		if strings.HasPrefix(s[m[6]:m[7]], "[masked]") {
			b.WriteString(s[m[0]:m[1]])
		} else {
			b.WriteString(s[m[2]:m[3]])
			b.WriteString(s[m[4]:m[5]])
			b.WriteString("[masked]")
		}
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// soraMaskPatterns is the snapshot's pattern pipeline in its
// unconditional form (sora's own gated fast paths are byte-identical
// to it by construction and pinned on the sora side).
func soraMaskPatterns(s string) string {
	s = soraUserInfoPattern.ReplaceAllString(s, "${1}://[masked]@")
	s = soraTokenLinkPattern.ReplaceAllString(s, "${1}://[masked]")
	s = soraSubscriptionPathPattern.ReplaceAllString(s, "${1}[masked]")
	s = soraAuthHeaderPattern.ReplaceAllString(s, "${1}[masked]")
	s = soraBearerPattern.ReplaceAllString(s, "${1}[masked]")
	s = soraReplaceKeyValues(soraKeyValuePattern, s)
	s = soraReplaceKeyValues(soraStrictKeyValuePattern, s)
	s = soraUUIDPattern.ReplaceAllString(s, "[masked]")
	return s
}

// --- END snapshot ---

// soraSeedReference is the snapshot's Redactor.String: seeds shorter
// than 4 are ignored, duplicates dropped, longest first (stable),
// one strings.Replacer over raw+derived pairs built from the
// SNAPSHOT derivedForms, then the SNAPSHOT pattern pipeline.
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
		for _, form := range soraDerivedForms(v) {
			if form != v && len(form) >= 4 {
				pairs = append(pairs, form, "[masked]")
			}
		}
	}
	return soraMaskPatterns(strings.NewReplacer(pairs...).Replace(s))
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

// TestRedactorReviewGFollowupEncodedForms pins REVIEW-GFOLLOWUP
// G3-F1: the bc54d959 derivedForms extension the first G3 port
// missed. Every probe is the reviewer's, verbatim in substance;
// every expectation is the sora snapshot's output, not legacy's.
func TestRedactorReviewGFollowupEncodedForms(t *testing.T) {
	hexA := string([]byte{0xde, 0xad, 0xbe, 0xef}) + "TAIL1234"
	cases := []struct {
		name  string
		seeds []string
		in    string
		want  string
	}{
		// Cross-seed, uppercase hex: seed B ("DEADBEEF") is a raw
		// substring of seed A's uppercase hex form; the whole form
		// must be consumed, leaving no 5441494C… tail (the REVIEW-G
		// class in the new encoding).
		{"cross-seed uppercase hex", []string{hexA, "DEADBEEF"},
			"leak DEADBEEF5441494C31323334 end", "leak [masked] end"},
		{"cross-seed uppercase hex (computed form)", []string{hexA, "DEADBEEF"},
			"leak " + strings.ToUpper(hex.EncodeToString([]byte(hexA))) + " end", "leak [masked] end"},
		{"uppercase hex single seed", []string{"mysecret1234"},
			"leak 6D7973656372657431323334 end", "leak [masked] end"},
		{"single percent-escape", []string{"mysecret1234"},
			`leak mysecr%65t1234 end`, "leak [masked] end"},
		{"single percent-escape, letter hex upper", []string{"mysecret1234"},
			"leak %6Dysecret1234 end", "leak [masked] end"},
		{"single percent-escape, letter hex lower", []string{"mysecret1234"},
			"leak %6dysecret1234 end", "leak [masked] end"},
		{"single unicode-escape", []string{"mysecret1234"},
			`leak mysecr\u0065t1234 end`, "leak [masked] end"},
		{"single unicode-escape, letter hex upper", []string{"mysecret1234"},
			`leak \u006Dysecret1234 end`, "leak [masked] end"},
		{"single unicode-escape, letter hex lower", []string{"mysecret1234"},
			`leak \u006dysecret1234 end`, "leak [masked] end"},
		{"percentEncodeAll lower", []string{"mysecret1234"},
			"leak %6d%79%73%65%63%72%65%74%31%32%33%34 end", "leak [masked] end"},
		{"percentEncodeAll upper", []string{"mysecret1234"},
			"leak %6D%79%73%65%63%72%65%74%31%32%33%34 end", "leak [masked] end"},
		{"percentEncodeAll slash seed lower", []string{"tok/en"},
			"leak %74%6f%6b%2f%65%6e end", "leak [masked] end"},
		{"percentEncodeAll slash seed upper", []string{"tok/en"},
			"leak %74%6F%6B%2F%65%6E end", "leak [masked] end"},
		{"per-rune unicode all lower", []string{"mysecret1234"},
			`leak \u006d\u0079\u0073\u0065\u0063\u0072\u0065\u0074\u0031\u0032\u0033\u0034 end`, "leak [masked] end"},
		{"per-rune unicode all upper digits", []string{"mysecret1234"},
			`leak \u006D\u0079\u0073\u0065\u0063\u0072\u0065\u0074\u0031\u0032\u0033\u0034 end`, "leak [masked] end"},
		{"json form upper-case digits", []string{"tok&en<12345>"},
			`leak tok\u0026en\u003C12345\u003E end`, "leak [masked] end"},
	}
	for _, c := range cases {
		if got := NewRedactor(c.seeds...).String(c.in); got != c.want {
			t.Errorf("%s:\n in:   %q\nwant: %q\n got: %q", c.name, c.in, c.want, got)
		}
		if got, ref := NewRedactor(c.seeds...).String(c.in), soraSeedReference(c.seeds, c.in); got != ref {
			t.Errorf("%s: differs from sora snapshot reference:\n in:  %q\nref: %q\n got: %q", c.name, c.in, ref, got)
		}
	}
}

// TestRedactorReviewGFollowupPatternDrift pins REVIEW-GFOLLOWUP
// G3-F3, the maskPatterns drift from sora bc54d959/bf0bf820: glued
// suffixes after quoted values, the strict assignment ring, and
// subscription token paths. Expectations are the sora snapshot's.
func TestRedactorReviewGFollowupPatternDrift(t *testing.T) {
	cases := []struct{ in, want string }{
		{`token: "abc"def`, `token: [masked]`},
		{`token: ""0`, `token: [masked]`},
		{`token  ""0`, `token  [masked]`},
		{`token: "abc",`, `token: [masked],`},
		{`token: "abc"]`, `token: [masked]]`},
		{`token: "a \"b\" c"`, `token: [masked]`},
		{`sni: "a.example"443`, `sni: [masked]`},
		{"sni: StrictSNI.example", "sni: [masked]"},
		{"sni=StrictSNI.example", "sni=[masked]"},
		{"host: StrictHost.example", "host: [masked]"},
		{"session: StrictSession123", "session: [masked]"},
		{"key=StrictQueryKey123", "key=[masked]"},
		{"seed: StrictSeed12345678", "seed: [masked]"},
		{"hwid: StrictHWID123456", "hwid: [masked]"},
		{"https://provider.example/sub/StrictPathToken123456", "https://provider.example/sub/[masked]"},
		{"https://h.example/api/v1/sub/NestedToken123456", "https://h.example/api/v1/sub/[masked]"},
		{"https://h.example/api/sub/NestedToken123456", "https://h.example/api/sub/[masked]"},
		{"Authorization: Token StrictHeaderToken123", "Authorization: Token [masked]"},
	}
	for _, c := range cases {
		if got := maskPatterns(c.in); got != c.want {
			t.Errorf("maskPatterns:\n in:   %q\nwant: %q\n got: %q", c.in, c.want, got)
		}
		if got, ref := maskPatterns(c.in), soraMaskPatterns(c.in); got != ref {
			t.Errorf("differs from sora snapshot:\n in:  %q\nref: %q\n got: %q", c.in, ref, got)
		}
		// Idempotence: masking the masked line changes nothing.
		if twice := maskPatterns(c.want); twice != c.want {
			t.Errorf("maskPatterns not idempotent:\n in: %q\nonce: %q\ntwice: %q", c.in, c.want, twice)
		}
		if got := NewRedactor().String(c.in); got != c.want {
			t.Errorf("Redactor.String:\n in:   %q\nwant: %q\n got: %q", c.in, c.want, got)
		}
	}
	// The strict ring needs an explicit assignment: the same words
	// in prose stay readable (sora snapshot agrees).
	for _, in := range []string{
		"status code 200, session expired at noon",
		"the host is down, retrying the key exchange",
		"seed phrase lives elsewhere, host unreachable",
		"https://h.example/api/v1/users/profile12345",
		"https://h.example/apiary/sub/NestedToken123456",
	} {
		if out := maskPatterns(in); out != in {
			t.Errorf("benign text changed:\n in: %q\nout: %q", in, out)
		}
	}
}

// TestRedactorReviewGCombinatorialDifferential sweeps combinations
// of fragments built from cross-related seeds and their forms: every
// input must match the sora snapshot reference byte for byte. This
// is the differential harness REVIEW-G ran ad hoc (16 cases); here
// it is permanent and wider. REVIEW-GFOLLOWUP adds the uppercase-hex
// fragment whose 67/67 sweep diverged before the bc54d959 port, the
// single-escape fragments, and pattern-pipeline fragments (glued
// suffix, strict ring, subscription path). Pass-3 review adds the
// non-ASCII + bare-UUID class: production maskPatterns has a
// separate unconditional branch for non-ASCII lines, and the corpus
// previously held no line that reaches that branch carrying a UUID
// no seed, key-value pair or URL covers — mutating only that
// branch's uuid pass (redact.go's non-ASCII uuidPattern replace)
// stayed green here. The bare-UUID, Cyrillic and pre-combined
// fragments below close that hole (their pairwise combinations
// cover the same class in both orders, spaced and glued).
func TestRedactorReviewGCombinatorialDifferential(t *testing.T) {
	hexA := string([]byte{0xde, 0xad, 0xbe, 0xef}) + "TAIL1234"
	seeds := []string{hexA, "deadbeef", "aa/bb/cc/dd", "%2Fbb%2F", "p@ss word/1234+&", "cyB3b3Jk"}
	fragments := []string{
		"leak", "end", " ",
		hexA, "deadbeef",
		hex.EncodeToString([]byte(hexA)),
		strings.ToUpper(hex.EncodeToString([]byte(hexA))),
		"DEADBEEF",
		"aa/bb/cc/dd", "%2Fbb%2F",
		url.QueryEscape("aa/bb/cc/dd"),
		"aa%2fbb%2fcc%2fdd",
		"p@ss word/1234+&", "cyB3b3Jk",
		base64.StdEncoding.EncodeToString([]byte("p@ss word/1234+&")),
		hex.EncodeToString([]byte("p@ss word/1234+&")),
		"[masked]",
		"5441494c31323334",
		`token: "abc"def`,
		`sni: a.example`,
		"https://h.example/api/v1/sub/NestedToken123456",
		// Bare UUID: no key name, no scheme, no seed overlap —
		// only the uuidPattern pass can mask it.
		"123e4567-e89b-12d3-a456-426614174000",
		// Non-ASCII fragments: any line containing one of these
		// takes production's non-ASCII maskPatterns branch.
		"пароль",
		"ключ: значение",
		"идентификатор сессии",
		// Pre-combined non-ASCII + bare UUID (also generated by
		// pairing the fragments above, pinned here as a literal
		// so the class survives fragment-list edits).
		"лог: сессия 123e4567-e89b-12d3-a456-426614174000 завершена",
		"123e4567-e89b-12d3-a456-426614174000 — ошибка подключения",
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
