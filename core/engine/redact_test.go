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
