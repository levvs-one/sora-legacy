package engine

import (
	"strings"
	"testing"
)

// TestRedactorMasksEveryProtocolFormat runs unregistered secrets through the
// pattern backstop: values the plan never registered must still not leak.
// The leak marker must not appear anywhere in the masked output.
func TestRedactorMasksEveryProtocolFormat(t *testing.T) {
	redactor := NewRedactor() // patterns only, no registered values
	cases := []struct {
		name string
		in   string
		leak string
	}{
		// Proxy links: every scheme the parser accepts, single-token and
		// user:password userinfo alike.
		{"vless uuid", `dial vless://de305d54-75b4-431b-adb2-eb6b9e546013@example.com:443`, "de305d54"},
		{"vless non-uuid id", `dial vless://customNonUuidId99@example.com:443`, "customNonUuidId99"},
		{"trojan token", `dial trojan://Sup3rSecretPass99@example.com:443`, "Sup3rSecretPass99"},
		{"hysteria2 token", `dial hysteria2://hysteriaPass99@example.com:443`, "hysteriaPass99"},
		{"hy2 token", `dial hy2://hysteriaPass99@example.com:443`, "hysteriaPass99"},
		{"tuic pair", `dial tuic://de305d54-75b4-431b-adb2-eb6b9e546013:tuicPass99@example.com:443`, "tuicPass99"},
		{"ss base64", `dial ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388`, "YWVzLTI1Ni1nY206cGFzcw"},
		{"ss plain", `dial ss://aes-256-gcm:plainpass99@example.com:8388`, "plainpass99"},
		{"socks", `dial socks://proxyUser99:proxyPass99@example.com:1080`, "proxyPass99"},
		{"socks5", `dial socks5://proxyUser99:proxyPass99@example.com:1080`, "proxyPass99"},
		{"socks5h", `dial socks5h://proxyUser99:proxyPass99@example.com:1080`, "proxyPass99"},
		{"http proxy", `dial http://proxyUser99:proxyPass99@example.com:8080`, "proxyPass99"},
		{"wireguard", `dial wireguard://WGPrivKey99@example.com:51820`, "WGPrivKey99"},
		{"vmess base64", `import vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCJ9`, "eyJ2IjoiMiIs"},
		// Config pairs: JSON with and without spaces, INI, query strings,
		// and every naming style (kebab, snake, camel).
		{`compact json`, `cfg {"password":"s3cr3tPass99"}`, "s3cr3tPass99"},
		{`pretty json`, `cfg {"password": "s3cr3tPass99"}`, "s3cr3tPass99"},
		{`quoted phrase`, `cfg password="my secret phrase"`, "my secret phrase"},
		{`json privateKey`, `cfg {"privateKey":"WGPrivKey99"}`, "WGPrivKey99"},
		{`ini PrivateKey`, "[Interface]\nPrivateKey = WGPrivKey99", "WGPrivKey99"},
		{`ini PresharedKey`, "[Peer]\nPresharedKey = WGPreShared99", "WGPreShared99"},
		{`snake private_key`, `private_key=WGPrivKey99`, "WGPrivKey99"},
		{`flat presharedkey`, `presharedkey=WGPreShared99`, "WGPreShared99"},
		{`kebab pre-shared-key`, `pre-shared-key=WGPreShared99`, "WGPreShared99"},
		{`hysteria auth`, `auth=hysteriaAuth99`, "hysteriaAuth99"},
		{`hysteria auth_str`, `auth_str=hysteriaAuth99`, "hysteriaAuth99"},
		{`api_key`, `api_key=APIKeySecret99`, "APIKeySecret99"},
		{`client_secret`, `client_secret=ClientSecret99`, "ClientSecret99"},
		{`spiderX`, `spiderX=SpiderSecret99`, "SpiderSecret99"},
		{`obfs_param`, `obfs_param=ObfsParam99`, "ObfsParam99"},
		{`secretKey`, `secretKey=SecretKey99`, "SecretKey99"},
		{`username=`, `username=proxyUser99`, "proxyUser99"},
		{`user:`, `"user": "proxyUser99"`, "proxyUser99"},
		{`query password`, `dial failed: ?password=s3cr3tPass99&x=1`, "s3cr3tPass99"},
	}
	for _, c := range cases {
		out := redactor.String(c.in)
		if strings.Contains(out, c.leak) {
			t.Errorf("%s: %q leaked into %q", c.name, c.leak, out)
		}
		if !strings.Contains(out, "[masked]") {
			t.Errorf("%s: nothing was masked in %q", c.name, out)
		}
	}
}

// TestRedactorKeepsHostsAndBenignTextReadable locks the diagnosis-friendly
// behavior: hosts, paths and ordinary prose survive masking.
func TestRedactorKeepsHostsAndBenignTextReadable(t *testing.T) {
	redactor := NewRedactor()
	unchanged := []string{
		`dial https://b.example.com:8443/path failed`,
		`dial vless://b.example.com:443 failed`,
		`connect to b.example.com:443`,
		`the server responded in 42 ms`,
		`subscription: the User-Agent is longer than 256 bytes`,
		`the user agent string was empty`,
		`login failed for the account`,
		`"password"`,
		`password`,
	}
	for _, in := range unchanged {
		if out := redactor.String(in); out != in {
			t.Errorf("benign text changed:\n in: %q\nout: %q", in, out)
		}
	}
	// Hosts stay readable next to masked credentials.
	out := redactor.String(`dial https://user:pass@b.example.com:8443 failed`)
	if !strings.Contains(out, "b.example.com") {
		t.Errorf("hostname was masked: %q", out)
	}
	if strings.Contains(out, "user:pass") {
		t.Errorf("credentials leaked: %q", out)
	}
}

// TestRedactorQuotedPhrasesMaskedWhole pins the separator fix shared with
// sora: the key/value separator must not consume the opening quote of a
// quoted value, or the value alternation falls through to a bare token
// and the phrase tail leaks word by word (token: "a b" used to mask
// only "a).
func TestRedactorQuotedPhrasesMaskedWhole(t *testing.T) {
	for in, leaks := range map[string][]string{
		`token: "a b"`:                      {"a b", `b"`},
		`password: "correct horse battery"`: {"correct", "horse", "battery"},
		`"token": "abc def"`:                {"abc", "def"},
		`user = "bob jones"`:                {"bob", "jones"},
	} {
		out := maskPatterns(in)
		for _, leak := range leaks {
			if strings.Contains(out, leak) {
				t.Errorf("secret leaked:\n in: %q\nout: %q\nleak: %q", in, out, leak)
			}
		}
	}
}

// TestRedactorParityKeySpellings pins the canonical key-superset shared
// byte-for-byte with sora (M1, pass 3/3): every WireGuard pre-shared-key
// spelling, every spider spelling and every public-key spelling must
// mask, plain and as a quoted JSON value (quoted form verifies the
// phrase tail is not leaked word by word — the pass-1 false closure).
func TestRedactorParityKeySpellings(t *testing.T) {
	keys := []string{
		"pre_shared_key", "pre-shared-key", "preshared_key", "presharedkey",
		"public_key", "public-key", "publickey",
		"spider_x", "spider-x", "spiderx", "spiderX",
		"private_key", "auth_str", "short_id",
	}
	for _, key := range keys {
		for _, in := range []string{
			key + "=ParitySecret99",
			key + ": ParitySecret99",
			`"` + key + `": "ParitySecret99"`,
			key + `: "secret phrase tail"`,
		} {
			out := maskPatterns(in)
			if strings.Contains(out, "ParitySecret99") || strings.Contains(out, "phrase tail") {
				t.Errorf("key %q leaked: in=%q out=%q", key, in, out)
			}
			if !strings.Contains(out, "[masked]") {
				t.Errorf("key %q masked nothing: in=%q out=%q", key, in, out)
			}
		}
	}
	// pre_shared_key is the literal WireGuard field name in sing-box JSON:
	// a quoted multi-word value must be masked whole, not word by word.
	out := maskPatterns(`"pre_shared_key": "a b c"`)
	for _, leak := range []string{"a b", `b"`, "c"} {
		if strings.Contains(out, leak) {
			t.Errorf("quoted pre_shared_key tail leaked: out=%q leak=%q", out, leak)
		}
	}
}

// TestMaskPatternsDifferential pins the [pass3-opt] per-pattern gates:
// maskPatterns must stay byte-identical to the unconditional pattern
// pipeline on every input, ASCII or not. The reference below is that
// pipeline verbatim.
func TestMaskPatternsDifferential(t *testing.T) {
	reference := func(s string) string {
		s = userInfoPattern.ReplaceAllString(s, "${1}://[masked]@")
		s = tokenLinkPattern.ReplaceAllString(s, "${1}://[masked]")
		s = subscriptionPathPattern.ReplaceAllString(s, "${1}[masked]")
		s = authHeaderPattern.ReplaceAllString(s, "${1}[masked]")
		s = bearerPattern.ReplaceAllString(s, "${1}[masked]")
		s = replaceKeyValues(keyValuePattern, s)
		s = replaceKeyValues(strictKeyValuePattern, s)
		s = uuidPattern.ReplaceAllString(s, "[masked]")
		return s
	}
	fragments := []string{
		"plain log line, latency 45ms",
		"token: \"my secret value\"",
		"Token: abc",
		"PASSWORD=hunter2",
		"pre_shared_key: zzz",
		"pre-shared-key: zzz",
		"public_key: q",
		"spider_x=1",
		"api_key: k",
		"auth_str: s",
		"client_secret: c",
		"short_id: 6ba8",
		"user = bob",
		"login: root",
		"username: eve",
		"vless://123e4567-e89b-12d3-a456-426614174000@h:443",
		"vmess://dG9rZW4td2l0aC1kYXNoZXM=",
		"https://user:pass@host/path",
		"uuid is 123e4567-e89b-12d3-a456-426614174000 ok",
		"a-b-c-d-e",
		"Key: kelvin",
		"пароль token: y",
		"ключ: значение",
		"obfs_param: p",
		"access_token=xyz123",
		"Authorization: Bearer abcdefgh123456",
		"Bearer abcdefgh12345678",
		"psk: p",
		"key",
		"user",
		"://",
		"-",
		"",
		`token: "abc"def`,
		`token: ""0`,
		"sni: a.example",
		"host: h.example",
		"session: xyz",
		"key=abc123",
		"seed: s",
		"hwid: hw",
		"dest: d.example:443",
		"encryption: none",
		"https://h.example/sub/AbCdEfGh12345678",
		"https://h.example/api/v1/sub/NestedToken123456",
		"Authorization: Token abcdefgh123456",
		"[masked]",
		"token: [masked],",
		// Bare UUID with no key, scheme or seed covering it, and
		// the same UUID in non-ASCII lines (production's separate
		// non-ASCII maskPatterns branch): only the uuidPattern
		// pass in that branch can mask these. The pass-3 review
		// found this class absent from the snapshot differential
		// corpus; it is pinned explicitly here too so neither
		// differential depends on the accidental "uuid is ..."
		// fragment above for non-ASCII UUID coverage.
		"123e4567-e89b-12d3-a456-426614174000",
		"пароль 123e4567-e89b-12d3-a456-426614174000",
		"лог: идентификатор 123e4567-e89b-12d3-a456-426614174000 завершён",
		"сессия 123e4567-e89b-12d3-a456-426614174000 закрыта",
	}
	var inputs []string
	inputs = append(inputs, fragments...)
	for _, a := range fragments {
		for _, b := range fragments {
			inputs = append(inputs, a+" "+b)
		}
	}
	for _, in := range inputs {
		if got, want := maskPatterns(in), reference(in); got != want {
			t.Errorf("maskPatterns differs from unconditional pipeline:\n in: %q\nwant: %q\n got: %q", in, want, got)
		}
	}
}

// TestRedactorParityCompoundTokens pins the S5 seams extension shared by
// both repos' redactors: compound *_token keys (access_token and friends,
// snake and camelCase) and HTTP Authorization/Bearer credentials were
// invisible to the canonical key alternation — \btoken\b has no word
// boundary inside access_token, and "Authorization" has none after
// "auth" — so both forms leaked verbatim into logs in both cores.
func TestRedactorParityCompoundTokens(t *testing.T) {
	leaks := []string{
		"access_token=CompoundSecret111",
		`access_token: "CompoundSecret111 phrase tail"`,
		"refresh_token=CompoundSecret222",
		"session_token: CompoundSecret333",
		"id_token=CompoundSecret444",
		"auth_token=CompoundSecret555",
		"api_token=CompoundSecret666",
		`"accessToken": "CompoundSecret777"`,
		"Authorization: Bearer CompoundSecret888token",
		"Authorization: Basic CompoundSecret999",
		"curl -H 'Bearer CompoundSecret000abcdefgh'",
	}
	for _, in := range leaks {
		out := maskPatterns(in)
		if strings.Contains(out, "CompoundSecret") || strings.Contains(out, "phrase tail") {
			t.Errorf("compound secret leaked:\n in: %q\nout: %q", in, out)
		}
		if !strings.Contains(out, "[masked]") {
			t.Errorf("nothing masked:\n in: %q\nout: %q", in, out)
		}
	}
	// Prose must survive: "bearer" without a token-shaped value is not
	// a credential.
	for _, in := range []string{
		"bearer of good news",
		"the bearer instrument is payable at sight",
		"tokens are counted per bucket, 45ms",
	} {
		if out := maskPatterns(in); out != in {
			t.Errorf("benign text changed:\n in: %q\nout: %q", in, out)
		}
	}
}
