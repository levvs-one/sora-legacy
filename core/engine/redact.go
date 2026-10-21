package engine

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

// Redactor masks credentials in engine output, controller errors, and events
// before they leave the core. It matches plan values exactly and uses patterns
// for unknown values such as engine-generated tokens.
type Redactor struct {
	mu        sync.Mutex
	values    []string
	ready     bool // gateForms holds the derived forms for values
	build     *strings.Replacer
	gateForms [][]string // parallel to values: gate list per seed
}

// NewRedactor returns a redactor seeded with the plan secrets.
func NewRedactor(values ...string) *Redactor {
	r := &Redactor{}
	r.Add(values...)
	return r
}

// Add registers values to mask. Values shorter than four characters are ignored
// to preserve ordinary log text.
func (r *Redactor) Add(values ...string) {
	added := false
	r.mu.Lock()
	for _, v := range values {
		if len(v) < 4 {
			continue
		}
		duplicate := false
		for _, have := range r.values {
			if have == v {
				duplicate = true
				break
			}
		}
		if !duplicate {
			r.values = append(r.values, v)
			added = true
		}
	}
	if added {
		// Match longest secrets first so strings.Replacer cannot
		// partially mask a longer value.
		sort.SliceStable(r.values, func(i, j int) bool { return len(r.values[i]) > len(r.values[j]) })
		r.build = nil
		r.ready = false
	}
	r.mu.Unlock()
}

// String masks one piece of text.
func (r *Redactor) String(s string) string {
	if s == "" {
		return s
	}
	r.mu.Lock()
	if !r.ready {
		// The gate list: every seed and its derived forms, kept
		// grouped per seed. The replacer pairs built on the first
		// gate hit consume them flattened — seed, then its forms
		// that differ from it — in exactly this order.
		r.gateForms = r.gateForms[:0]
		for _, v := range r.values {
			// A seed that reaches a log rarely arrives raw: engines
			// and HTTP stacks re-encode it (percent-encoding in URLs
			// and error strings, base64 in vmess-style blobs and
			// subscription bodies, hex in WireGuard tooling, JSON
			// \uXXXX escapes in rendered configs). Masking only the
			// raw form left every one of those encodings readable —
			// the encoded forms are part of the seed, so they are
			// registered alongside it (AUDIT-PARITY G3: close the
			// class, not the latest spelling).
			r.gateForms = append(r.gateForms, derivedForms(v))
		}
		r.build = nil
		r.ready = true
	}
	// The combined replacer is a generic-trie replacer and
	// allocates when it rewrites, so it is gated: strings.Contains
	// over the original string for every registered pattern (raw
	// and derived) allocates nothing, and the replacer runs only
	// when some pattern is actually present. Skipping it otherwise
	// is byte-identical to running it — with ONE replacer over the
	// ORIGINAL string, an input containing none of its patterns is
	// the identity by definition. (That identity claim was false
	// for the old two-replacer layout: its first pass rewrote the
	// very string the second pass scanned.) A clean log line
	// therefore keeps the allocation-free fast path
	// BenchmarkRedactCleanLine pins (0 B/op, 0 allocs/op), and any
	// line the gate lets through is masked by the single combined
	// pass, byte-identical to the seed stage of the sora snapshot
	// named at derivedForms (sora@1ec55191).
	out := s
	hit := false
	for i, v := range r.values {
		if strings.Contains(s, v) {
			hit = true
			break
		}
		for _, form := range r.gateForms[i] {
			if form != v && len(form) >= 4 && strings.Contains(s, form) {
				hit = true
				break
			}
		}
		if hit {
			break
		}
	}
	if hit {
		if r.build == nil {
			// One combined replacer over raw seeds and derived
			// forms, in exactly sora's pair order — the layout
			// is load-bearing, not a style choice. The previous
			// legacy layout kept the forms in a second replacer
			// applied to the OUTPUT of the raw pass, and REVIEW-G
			// proved it diverges: when a raw seed B is a substring
			// of another seed A's derived form, the raw pass
			// masks B inside the form, mangles the form so the
			// second replacer no longer recognises it, and leaks
			// the rest of A's encoding. A single replacer scans
			// the original string once, so a form that starts
			// earlier in the string is consumed whole before the
			// scanner reaches the raw seed inside it.
			//
			// The replacer is built only here, on the first gate
			// hit: its pairs are exactly the gate list — each seed
			// followed by its kept forms — zipped with the mask,
			// so deferring the trie construction cannot change
			// any output; a redactor whose lines never contain a
			// seed simply never pays for it.
			pairs := make([]string, 0, 64)
			for i, v := range r.values {
				pairs = append(pairs, v, "[masked]")
				for _, form := range r.gateForms[i] {
					if form != v && len(form) >= 4 {
						pairs = append(pairs, form, "[masked]")
					}
				}
			}
			r.build = strings.NewReplacer(pairs...)
		}
		out = r.build.Replace(s)
	}
	r.mu.Unlock()
	return maskPatterns(out)
}

// Err masks an error, keeping the wrap chain so errors.Is still works.
func (r *Redactor) Err(err error) error {
	if err == nil {
		return nil
	}
	return &maskedError{Redactor: r, cause: err}
}

// derivedForms returns the re-encodings of a seed value that log
// pipelines commonly produce: URL percent-encoding (query and path
// flavours; every byte escaped as well as only the specials; upper-
// and lowercase hex digits), base64 (standard and URL-safe, padded
// and raw), hex (lower- and uppercase), and the JSON string escaping
// of the value (\" \\ and \uXXXX forms, the fully-escaped per-rune
// form, and single-rune escapes). The list is computed once per
// redactor rebuild, alongside the seeds themselves.
//
// Case contract (CENSOR-LEAK review): real encoders are consistent
// within one string — Go's hex is lowercase, %X-style encoders are
// uppercase, JSON \uXXXX writers pick one case — so the pure upper
// and lower forms of every encoding are registered. Forms that mix
// cases character by character would need a per-character case
// randomiser no known encoder is; they are the documented residual,
// together with multi-character escape subsets beyond the single-
// escape forms registered below.
//
// Port source: this function and its helpers (percentEncodeAll,
// unicodeEscapeAll, writeUnicodeEscape, upperUnicodeHexDigits,
// singleEscapes) are ported from sora's core/engine/redact.go at
// commit 1ec551910016e292eadf666da43b1f8a9715fc9c (HEAD at port
// time; derivedForms itself last changed there in bc54d959, the
// CENSOR-LEAK extension REVIEW-GFOLLOWUP G3-F1 found missing here).
// The returned list — contents and order — is byte-identical to
// the verbatim port for every valid UTF-8 seed (pinned by the
// snapshot differential in redact_review_g_test.go); for a seed
// holding invalid UTF-8, singleEscapes deliberately diverges
// from the reference instead of panicking (see its comment,
// REVIEW-PERFFIX). The construction below only avoids
// allocations the port spent on forms it then deduplicated or on
// intermediate copies (PERF flow B): exact slice capacities,
// pre-grown builders in singleEscapes, the raw/URL base64 forms
// derived from the standard encoding instead of re-encoded, and
// no-op case transforms returned without a copy.
func derivedForms(v string) []string {
	capacity := 20
	if len(v) <= 64 {
		// Base forms plus the single-escape enumeration (up to
		// 2 percent forms per byte and 2 \u forms per rune,
		// fewer after the case dedup in singleEscapes).
		capacity += 2 * len(v)
	}
	forms := make([]string, 0, capacity)
	add := func(s string) {
		for _, have := range forms {
			if have == s {
				return
			}
		}
		forms = append(forms, s)
	}
	// A seed made only of bytes no encoder escapes ([A-Za-z0-9-_.~]
	// is left alone by QueryEscape, PathEscape and encoding/json
	// alike) has esc == json-inner == v: computing those forms
	// would only manufacture copies of v that add() deduplicates
	// and the caller filters out anyway.
	plain := true
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == '~') {
			plain = false
			break
		}
	}
	if !plain {
		for _, esc := range []string{url.QueryEscape(v), url.PathEscape(v)} {
			add(esc)
			add(lowerPercentHex(esc))
		}
	}
	// An encoder that escapes every byte, not only the specials
	// (defensive formatters, some subscription proxies): the seed
	// then survives as one long %XX run in both hex cases. The
	// cases coincide when no byte has a hex-letter nibble — then
	// the second add would only deduplicate a fresh copy.
	hexLetters := false
	for i := 0; i < len(v); i++ {
		if v[i]>>4 >= 10 || v[i]&0x0f >= 10 {
			hexLetters = true
			break
		}
	}
	add(percentEncodeAll(v, true))
	if hexLetters {
		add(percentEncodeAll(v, false))
	}
	raw := []byte(v)
	// The raw encodings are the standard one minus its padding,
	// and the URL-safe ones equal the standard ones whenever the
	// standard output holds no '+' or '/' — derive instead of
	// re-encoding; the forms (and their order) are unchanged.
	std64 := base64.StdEncoding.EncodeToString(raw)
	add(std64)
	pad := len(std64) - len(strings.TrimRight(std64, "="))
	add(std64[:len(std64)-pad])
	if strings.ContainsAny(std64, "+/") {
		url64 := base64.URLEncoding.EncodeToString(raw)
		add(url64)
		add(url64[:len(url64)-pad])
	}
	// WireGuard tooling and %X formatters print hex uppercase; the
	// pure-uppercase form is a different string the replacer must
	// know, symmetric to lowercase percent-hex.
	lowerHex := hex.EncodeToString(raw)
	add(lowerHex)
	if hexLetters {
		add(strings.ToUpper(lowerHex))
	}
	if !plain {
		if marshalled, err := json.Marshal(v); err == nil && len(marshalled) >= 2 {
			inner := string(marshalled[1 : len(marshalled)-1])
			add(inner)
			// Encoders disagree on the case of \uXXXX hex digits in
			// the escapes json.Marshal does emit (\u003c vs \u003C).
			add(upperUnicodeHexDigits(inner))
		}
	}
	// Per-rune \uXXXX: encoders that escape every character, and
	// encoders that escape exactly one character of an otherwise
	// raw string (the reviewer's mysecr\u0065t1234 probe), in both
	// hex cases.
	add(unicodeEscapeAll(v, unicodeDigitsLower))
	upperDiffers := false
	for _, r := range v {
		if hexLetterInRune(r) {
			upperDiffers = true
			break
		}
	}
	if upperDiffers {
		add(unicodeEscapeAll(v, unicodeDigitsUpper))
	}
	// Single-position escapes are enumerated only for bounded
	// seeds: the form count grows linearly with the seed, and a
	// very long seed's single-escape variants would bloat the
	// replacer for a shape no encoder produces at that length.
	if len(v) <= 64 {
		for _, form := range singleEscapes(v) {
			add(form)
		}
	}
	return forms
}

// percentEncodeAll escapes every byte of v as %XX (upper selects the
// hex digit case), the full-encoding form derivedForms documents.
func percentEncodeAll(v string, upper bool) string {
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

const (
	unicodeDigitsLower = "0123456789abcdef"
	unicodeDigitsUpper = "0123456789ABCDEF"
)

// unicodeEscapeAll escapes every rune of v as \uXXXX with the given
// hex digit case, using a surrogate pair above the BMP exactly as
// JSON string encoders do.
func unicodeEscapeAll(v string, digits string) string {
	var b strings.Builder
	b.Grow(len(v) * 6)
	for _, r := range v {
		writeUnicodeEscape(&b, r, digits)
	}
	return b.String()
}

// writeUnicodeEscape writes one rune as \uXXXX in the given digit
// case, or a surrogate pair for runes above U+FFFF.
func writeUnicodeEscape(b *strings.Builder, r rune, digits string) {
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

// upperUnicodeHexDigits uppercases the four hex digits of every
// \uXXXX escape in s; all other bytes pass through unchanged. A
// string holding no lowercase hex digit inside a \uXXXX escape is
// returned as is — the copy is only made when a digit will change.
func upperUnicodeHexDigits(s string) string {
	changes := false
	for i := 0; i+5 < len(s) && !changes; i++ {
		if s[i] != '\\' || s[i+1] != 'u' {
			continue
		}
		for j := i + 2; j <= i+5; j++ {
			if 'a' <= s[j] && s[j] <= 'f' {
				changes = true
				break
			}
		}
	}
	if !changes {
		return s
	}
	b := []byte(s)
	for i := 0; i+5 < len(b); i++ {
		if b[i] != '\\' || b[i+1] != 'u' {
			continue
		}
		ok := true
		for j := i + 2; j <= i+5; j++ {
			c := b[j]
			if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
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

// singleEscapes returns the forms of v in which exactly one position
// is escaped and the rest is raw: per byte as %XX (both hex cases)
// and per rune as \uXXXX (both hex cases). These are the shapes an
// encoder produces when it escapes one character class member inside
// an otherwise literal string. Each form is assembled in one
// pre-grown builder: the list is long (four forms per character)
// and the concatenation chains of the original port made it the
// most expensive part of building a Redactor (PERF flow B).
func singleEscapes(v string) []string {
	const digitsLower, digitsUpper = "0123456789abcdef", "0123456789ABCDEF"
	out := make([]string, 0, len(v)+2*utf8.RuneCountInString(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		// The two digit cases produce the same form when neither
		// nibble of c is a hex letter; generating both would only
		// feed derivedForms' dedup a copy it discards.
		cases := []string{digitsUpper}
		if c>>4 >= 10 || c&0x0f >= 10 {
			cases = append(cases, digitsLower)
		}
		for _, digits := range cases {
			var b strings.Builder
			b.Grow(len(v) + 3)
			b.WriteString(v[:i])
			b.WriteByte('%')
			b.WriteByte(digits[c>>4])
			b.WriteByte(digits[c&0x0f])
			b.WriteString(v[i+1:])
			out = append(out, b.String())
		}
	}
	// Rune offsets for the \u forms; a rune-wise walk keeps
	// multi-byte characters intact (escaping half a UTF-8 sequence
	// is not a form any JSON encoder emits).
	//
	// Deliberate divergence from the sora reference, which panics
	// here (legacy is intentionally harder than the reference on
	// this point): the walk decodes with DecodeRuneInString and
	// advances by its reported size, NOT by utf8.RuneLen(r). A seed
	// is a credential from a provider config and may hold arbitrary
	// bytes; an invalid byte decodes as RuneError with size 1,
	// while RuneLen(RuneError) is 3 — slicing v[i+RuneLen(r):] on
	// an invalid byte at the end of a seed panicked (REVIEW-PERFFIX,
	// 138/200 byte-fuzz seeds), and mid-seed it silently skipped
	// the two following bytes. With the decoded size, an invalid
	// byte is one escape position (\ufffd, upper case \uFFFD) and
	// the walk resumes at the next byte. For every valid UTF-8
	// seed the decoded size equals RuneLen — an honestly encoded
	// U+FFFD included (size 3 either way) — so the form list and
	// every redactor output stay byte-identical there; the other
	// rune walks in derivedForms and its helpers were audited for
	// the same disease and slice nothing by rune length (the
	// upperDiffers scan in derivedForms and unicodeEscapeAll only
	// read the decoded rune, and range decoding already yields one
	// RuneError per invalid byte for them).
	for i := 0; i < len(v); {
		r, size := utf8.DecodeRuneInString(v[i:])
		// Same dedup as above: the cases coincide when no hex
		// digit of the escape is a letter (a surrogate pair always
		// contains a D, so non-BMP runes always differ).
		cases := []string{digitsLower}
		if hexLetterInRune(r) {
			cases = append(cases, digitsUpper)
		}
		for _, digits := range cases {
			var b strings.Builder
			b.Grow(len(v) + 12)
			b.WriteString(v[:i])
			writeUnicodeEscape(&b, r, digits)
			b.WriteString(v[i+size:])
			out = append(out, b.String())
		}
		i += size
	}
	return out
}

// hexLetterInRune reports whether the \uXXXX escape of r contains
// a hex letter digit (a–f): only then do its lower- and uppercase
// forms differ.
func hexLetterInRune(r rune) bool {
	if r > 0xffff {
		return true // the surrogate halves start with D
	}
	for shift := 0; shift < 16; shift += 4 {
		if (r>>uint(shift))&0x0f >= 10 {
			return true
		}
	}
	return false
}

// lowerPercentHex lowercases the hex digits of %XX escapes: encoders
// disagree on the case, and a seed masked as %2F must also be masked
// as %2f. A string with no uppercase hex digit behind a '%' is
// returned as is — the copy is only made when a digit will change.
func lowerPercentHex(s string) string {
	changes := false
	for i := 0; i+2 < len(s) && !changes; i++ {
		if s[i] != '%' {
			continue
		}
		for j := i + 1; j <= i+2; j++ {
			if 'A' <= s[j] && s[j] <= 'F' {
				changes = true
				break
			}
		}
	}
	if !changes {
		return s
	}
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

type maskedError struct {
	Redactor *Redactor
	cause    error
}

func (e *maskedError) Error() string { return e.Redactor.String(e.cause.Error()) }
func (e *maskedError) Unwrap() error { return e.cause }

var (
	uuidPattern = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	// keyValuePattern masks credential pairs. Keys cover the naming
	// styles configs use (kebab, snake, camel); the separator tolerates
	// JSON quoting with or without spaces, and the value tolerates
	// quoting so a quoted phrase is masked whole: without the quoted
	// alternation, token: "my secret value" would mask only "my and
	// leave 'secret value"' in the log. Note the separator deliberately
	// does NOT consume a quote after ":" - eating it would make the
	// value alternation fall through to \S+ and leak the tail of the
	// phrase ("token: \"a b\"" used to mask only "a). Hosts stay
	// readable: only the pair is masked.
	// The key alternation is the canonical superset shared byte-for-byte
	// with sora's redactor: pre[_-]?shared[_-]?key covers every
	// WireGuard spelling (pre_shared_key is the literal sing-box JSON
	// field name), spider[_-]?x covers spider_x/spider-x/spiderx, and
	// public[_-]?key is present on both sides.
	// TestRedactorParityKeySpellings in both repos pins this list by
	// execution.
	// The value's quoted alternatives carry a glued-suffix tail
	// ([^\s,;}\]\)]*): characters stuck to the closing quote with
	// no whitespace are part of the same token — token: "abc"def
	// and token: ""0 are one value, not a value plus a tail. The
	// old pattern stopped at the closing quote and left the tail
	// readable; worse, the tail then merged with the [masked]
	// replacement on a second pass, so masking was not idempotent
	// (FuzzRedactorNoPanicAndIdempotent's token  ""0 crash). The
	// tail class stops at structural delimiters (, ; } ] )) so a
	// compact-JSON separator after a quoted value survives; a
	// suffix behind such a delimiter is frozen by the [masked]
	// guard in replaceKeyValues instead.
	keyValuePattern = regexp.MustCompile(`(?i)\b(uuid|password|passwd|secret|(?:access|refresh|session|id|auth|api)[_-]?token|token|private[_-]?key|pre[_-]?shared[_-]?key|obfs[_-]?password|obfs[_-]?param|api[_-]?key|auth(?:[_-]?str)?|secret[_-]?key|client[_-]?secret|psk|public[_-]?key|short[_-]?id|spider[_-]?x|username)\b([\"']?\s*[:=]\s*|\s+)("(?:\\.|[^"\\])*"[^\s,;}\]\)]*|'(?:\\.|[^'\\])*'[^\s,;}\]\)]*|\S+)`)
	// strictKeyValuePattern masks keys whose names are also ordinary
	// words only with an explicit assignment (":" or "="): a bare space
	// after "user" or "login" is usually prose ("user agent", "login
	// failed"), not a credential pair. The list carries the second ring
	// the loose pattern cannot hold: bare key/code/session (subscription
	// URL query parameters are exactly "?key=…&code=…"), hwid and
	// device/session ids (provider HWID limits), seed and encryption
	// (profile credentials), and the destination identifiers a censor
	// cares about — sni, server_name, dest, host, serviceName — which
	// are prose-safe only behind an explicit assignment.
	strictKeyValuePattern = regexp.MustCompile(`(?i)\b(user|login|key|code|session|seed|hwid|device[_-]?id|session[_-]?id|sni|server[_-]?name|servername|dest|encryption|service[_-]?name|servicename|host)\b([\"']?\s*[:=]\s*)("(?:\\.|[^"\\])*"[^\s,;}\]\)]*|'(?:\\.|[^'\\])*'[^\s,;}\]\)]*|\S+)`)
	// userInfoPattern masks the credentials of proxy links for every
	// protocol the core parses. The password half is optional:
	// trojan://token@host, hysteria2://secret@host and vless://id@host
	// carry a single token. The host stays readable for diagnosis.
	userInfoPattern = regexp.MustCompile(`(?i)\b(https?|socks5?h?|socks4a?|ssr?|vless|vmess|trojan|hysteria2?|hy2|tuic|wireguard|wg|naive|snell)://[^/\s@]+@`)
	// tokenLinkPattern masks schemeless-credential links whose secret is a
	// bare token with no userinfo, such as vmess://base64json. The fragment
	// stays readable: it is the user's display name.
	tokenLinkPattern = regexp.MustCompile(`(?i)\b(vmess|ssr)://[A-Za-z0-9+/_=-]+`)
	// authHeaderPattern masks HTTP Authorization credentials
	// (Authorization: Bearer/Basic ...): the keyValue alternation cannot
	// see them — after "auth" in "Authorization" there is no word
	// boundary, and the credential itself carries no key at all.
	authHeaderPattern = regexp.MustCompile(`(?i)\b(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)(\S+)`)
	// subscriptionPathPattern masks the token segment of a subscription
	// URL: providers hand out https://host/sub/<token> (and feed/token/
	// link spellings) where the credential is a bare path segment with
	// no key name and no userinfo, so neither the key patterns nor the
	// userinfo pattern can see it. Only the segment after a
	// subscription-shaped path element is masked; ordinary URLs (rule
	// sets, documentation, engine downloads) keep readable paths.
	// Between host and the keyword segment, the conventional API
	// prefix is allowed — api and version segments in any combination
	// (https://host/api/v1/sub/<token>, /api/sub/<token>) — because
	// provider panels nest subscriptions exactly there. Arbitrary
	// nesting is deliberately NOT allowed: a keyword segment buried
	// under content segments (…/news/sub/<word>) is at least as
	// likely to be a documentation path as a credential, and masking
	// it would mangle ordinary URLs in logs.
	subscriptionPathPattern = regexp.MustCompile(`(?i)\b(https?://[^\s/]+/(?:(?:api|v[0-9]+)/)*(?:sub|subscribe|subscription|feed|token|link)/)[A-Za-z0-9._~%+/=-]{8,}`)
	// bearerPattern masks a bare Bearer token (curl-style dumps, proxy
	// logs) with no Authorization header around it. The value must look
	// like a token (12+ token characters) so prose ("bearer of news",
	// "bearer instrument") is never masked.
	bearerPattern = regexp.MustCompile(`(?i)\b(bearer\s+)([A-Za-z0-9._~+/=-]{12,})`)
)

// keyGateWords are the substrings that gate keyValuePattern: every
// alternative of its key alternation contains one of them (uuid/password/
// passwd/secret/token/psk/spider/short literally; every *_key/*-key form
// contains "key"; obfs_param contains "param"; auth and auth_str contain
// "auth"; username contains "user"). A line with none of them cannot be
// changed by keyValuePattern. Mirrors sora's redactor gate ([pass3-opt],
// sora 8cdcb6d9); legacy previously ran all five regexp passes on every
// line, clean ones included.
var keyGateWords = []string{
	"uuid", "password", "passwd", "secret", "token", "key", "param",
	"auth", "psk", "user", "spider", "short",
}

// isASCII reports whether s is plain ASCII, where case folding is a
// per-byte operation and the gate scan below is exact. Non-ASCII text
// keeps the unconditional pipeline: Unicode folding (e.g. U+212A KELVIN
// SIGN folding to "k") is observable there and must not change.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// gateFlags holds the per-pattern necessary conditions of one ASCII
// line, computed by gateFlagsASCII in a single pass.
type gateFlags struct {
	scheme bool // "://" present: userInfoPattern/tokenLinkPattern may match
	key    bool // a keyGateWords substring: keyValuePattern may match
	strict bool // a strict-ring substring ("user", "login", "key", "code", "session", "seed", "hwid", "device", "sni", "server", "service", "dest", "encryption", "host"): strictKeyValuePattern may match
	uuid   bool // at least four dashes: uuidPattern may match
	bearer bool // "bearer"/"authorization" present: authHeaderPattern/bearerPattern may match
}

// matchFoldAt reports whether w (lowercase ASCII) occurs in s at i,
// folding ASCII letters only.
func matchFoldAt(s string, i int, w string) bool {
	if i+len(w) > len(s) {
		return false
	}
	for j := 0; j < len(w); j++ {
		c := s[i+j]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != w[j] {
			return false
		}
	}
	return true
}

// gateFlagsASCII computes the flags in one pass over s, trying gate
// words only at positions whose folded byte can start one. It allocates
// nothing.
func gateFlagsASCII(s string) gateFlags {
	var f gateFlags
	dashes := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' {
			dashes++
			continue
		}
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		switch c {
		case ':':
			if i+2 < len(s) && s[i+1] == '/' && s[i+2] == '/' {
				f.scheme = true
			}
		case 'u':
			if matchFoldAt(s, i, "user") {
				f.key, f.strict = true, true
			}
			if matchFoldAt(s, i, "uuid") {
				f.key = true
			}
		case 'p':
			if matchFoldAt(s, i, "password") || matchFoldAt(s, i, "passwd") || matchFoldAt(s, i, "psk") || matchFoldAt(s, i, "param") {
				f.key = true
			}
		case 's':
			if matchFoldAt(s, i, "secret") || matchFoldAt(s, i, "spider") || matchFoldAt(s, i, "short") {
				f.key = true
			}
			if matchFoldAt(s, i, "session") || matchFoldAt(s, i, "seed") || matchFoldAt(s, i, "sni") ||
				matchFoldAt(s, i, "server") || matchFoldAt(s, i, "service") {
				f.strict = true
			}
		case 't':
			if matchFoldAt(s, i, "token") {
				f.key = true
			}
		case 'k':
			if matchFoldAt(s, i, "key") {
				f.key, f.strict = true, true
			}
		case 'a':
			if matchFoldAt(s, i, "auth") {
				f.key = true
			}
			if matchFoldAt(s, i, "authorization") {
				f.bearer = true
			}
		case 'b':
			if matchFoldAt(s, i, "bearer") || matchFoldAt(s, i, "basic") {
				f.bearer = true
			}
		case 'l':
			if matchFoldAt(s, i, "login") {
				f.strict = true
			}
		case 'c':
			if matchFoldAt(s, i, "code") {
				f.strict = true
			}
		case 'h':
			if matchFoldAt(s, i, "hwid") || matchFoldAt(s, i, "host") {
				f.strict = true
			}
		case 'd':
			if matchFoldAt(s, i, "device") || matchFoldAt(s, i, "dest") {
				f.strict = true
			}
		case 'e':
			if matchFoldAt(s, i, "encryption") {
				f.strict = true
			}
		}
		if f.scheme && f.key && f.strict && f.bearer && dashes >= 4 {
			break
		}
	}
	f.uuid = dashes >= 4
	return f
}

// replaceKeyValues applies one of the key-value patterns (groups:
// 1=key, 2=separator, 3=value), replacing the value with [masked]
// while preserving key and separator verbatim. A match whose value
// already starts with [masked] is copied through unchanged: it is a
// mask this pipeline (or an earlier redaction of the same log)
// already produced. Without the guard, the value's \S+ alternative
// re-consumes the mask plus any suffix the first pass deliberately
// preserved — a structural delimiter as in token: [masked], or a
// bracket as in token: [masked]] — and masking is not a fixed
// point. The guard is the second half of the idempotence fix: the
// quoted alternatives' glued-suffix tail (see keyValuePattern)
// consumes what belongs to the value, and the guard freezes what
// was already masked, so maskPatterns(maskPatterns(x)) ==
// maskPatterns(x) holds for the whole pipeline.
func replaceKeyValues(re *regexp.Regexp, s string) string {
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

// maskPatterns masks identifiers, credential pairs, and URL credentials whose
// exact values are unknown.
func maskPatterns(s string) string {
	if !isASCII(s) {
		// The unconditional pipeline, unchanged: Unicode case folding
		// decides what the (?i) patterns can see, so no ASCII shortcut
		// may skip a pass here. Each ReplaceAllString pass is still
		// probed with MatchString first: ReplaceAllString spends
		// allocations even when nothing matches, MatchString spends
		// none, and a pass without a match is the identity — so the
		// probe cannot change any output.
		if userInfoPattern.MatchString(s) {
			s = userInfoPattern.ReplaceAllString(s, "${1}://[masked]@")
		}
		if tokenLinkPattern.MatchString(s) {
			s = tokenLinkPattern.ReplaceAllString(s, "${1}://[masked]")
		}
		if subscriptionPathPattern.MatchString(s) {
			s = subscriptionPathPattern.ReplaceAllString(s, "${1}[masked]")
		}
		if authHeaderPattern.MatchString(s) {
			s = authHeaderPattern.ReplaceAllString(s, "${1}[masked]")
		}
		if bearerPattern.MatchString(s) {
			s = bearerPattern.ReplaceAllString(s, "${1}[masked]")
		}
		s = replaceKeyValues(keyValuePattern, s)
		s = replaceKeyValues(strictKeyValuePattern, s)
		if uuidPattern.MatchString(s) {
			s = uuidPattern.ReplaceAllString(s, "[masked]")
		}
		return s
	}
	// ASCII fast path: one gate per pattern, each a necessary condition
	// for that pattern to match at all —
	//   userInfo/tokenLink/subscriptionPath need a literal "://";
	//   keyValue needs one of keyGateWords (see its comment);
	//   strictKeyValue needs one of its ring substrings (see
	//   gateFlagsASCII: user/login/key/code/session/seed/hwid/
	//   device/sni/server/service/dest/encryption/host);
	//   uuid needs at least four dashes (the pattern has exactly four).
	// The flags are computed once, on entry. That stays a superset for
	// the string each later pattern actually receives: the replacements
	// only delete spans and insert "[masked]"/"[masked]@", whose bracket
	// characters no gate word can span, and keyValue preserves its key
	// and separator verbatim — so no pass can create a trigger (scheme,
	// key word, strict-ring word, dashes) that the entry string lacked. A
	// skipped pattern therefore provably cannot match, and the output is
	// byte-identical to the unconditional pipeline (pinned by
	// TestMaskPatternsDifferential).
	f := gateFlagsASCII(s)
	if !f.scheme && !f.key && !f.strict && !f.uuid && !f.bearer {
		return s
	}
	// The flags are necessary conditions, not exact ones (the
	// strict flag, say, fires on the substring "server", which the
	// pattern itself cannot match without an assignment). Each
	// ReplaceAllString pass is therefore probed with MatchString
	// first — ReplaceAllString spends allocations even on a
	// no-match line, MatchString spends none, and a pass without
	// a match is the identity (PERF flow B).
	if f.scheme {
		if userInfoPattern.MatchString(s) {
			s = userInfoPattern.ReplaceAllString(s, "${1}://[masked]@")
		}
		if tokenLinkPattern.MatchString(s) {
			s = tokenLinkPattern.ReplaceAllString(s, "${1}://[masked]")
		}
		if subscriptionPathPattern.MatchString(s) {
			s = subscriptionPathPattern.ReplaceAllString(s, "${1}[masked]")
		}
	}
	if f.bearer {
		if authHeaderPattern.MatchString(s) {
			s = authHeaderPattern.ReplaceAllString(s, "${1}[masked]")
		}
		if bearerPattern.MatchString(s) {
			s = bearerPattern.ReplaceAllString(s, "${1}[masked]")
		}
	}
	if f.key {
		s = replaceKeyValues(keyValuePattern, s)
	}
	if f.strict {
		s = replaceKeyValues(strictKeyValuePattern, s)
	}
	if f.uuid && uuidPattern.MatchString(s) {
		s = uuidPattern.ReplaceAllString(s, "[masked]")
	}
	return s
}
