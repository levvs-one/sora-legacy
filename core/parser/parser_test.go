package parser

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseLinks(t *testing.T) {
	// Normalize schemes and apply protocol-specific security defaults.
	tests := []struct{ name, input, protocol, security string }{
		{"vless", "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls&type=ws&path=%2F#🇩🇪%20Berlin", "vless", "tls"},
		{"vless plain", "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443", "vless", "none"},
		{"trojan", "trojan://secret@example.com:443?sni=example.com#Trojan", "trojan", "tls"},
		{"shadowsocks", "ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388#SS", "shadowsocks", "none"},
		{"hysteria2", "hysteria2://secret@example.com:443?sni=example.com#H2", "hysteria2", "tls"},
		{"hy2", "hy2://secret@example.com:443#H2", "hysteria2", "tls"},
		{"tuic", "tuic://123e4567-e89b-12d3-a456-426614174000:pass@example.com:443", "tuic", "tls"},
		{"socks", "socks://user:pass@example.com:1080", "socks5", "none"},
		{"socks5", "socks5://example.com:1080", "socks5", "none"},
		{"https", "https://user:pass@example.com:443", "http", "tls"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := (LinkParser{}).Parse([]byte(tt.input))
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Servers) != 1 || r.Servers[0].Protocol != tt.protocol || r.Servers[0].Security != tt.security {
				t.Fatalf("unexpected result: %#v", r)
			}
		})
	}
}

func TestBase64Wrapped(t *testing.T) {
	raw := "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443\n"
	enc := base64.StdEncoding.EncodeToString([]byte(raw))
	enc = strings.Join([]string{enc[:8], enc[8:]}, "\n")
	r, err := (LinkParser{}).Parse([]byte(enc))
	if err != nil || r.Report.Imported != 1 {
		t.Fatalf("result=%#v err=%v", r, err)
	}
}

func TestRejectsHTTPSubscription(t *testing.T) {
	if _, err := (LinkParser{}).Parse([]byte("http://example.com/sub")); err == nil {
		t.Fatal("expected rejection")
	}
}
func TestLimit(t *testing.T) {
	r, err := (LinkParser{MaxItems: 1}).Parse([]byte("vless://123e4567-e89b-12d3-a456-426614174000@a.example:443\nvless://123e4567-e89b-12d3-a456-426614174000@b.example:443"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Report.Unsupported != 1 {
		t.Fatalf("%#v", r.Report)
	}
}

// TestLimitAppliesToEveryFormat is the regression test for LEGACY-M5: the
// item limit must cap JSON, YAML and WireGuard inputs, not just link lists.
func TestLimitAppliesToEveryFormat(t *testing.T) {
	jsonPayload := `[{"type":"vless","server":"a.example.com","port":443,"uuid":"123e4567-e89b-12d3-a456-426614174000"},` +
		`{"type":"vless","server":"b.example.com","port":443,"uuid":"123e4567-e89b-12d3-a456-426614174001"}]`
	yamlPayload := "proxies:\n" +
		"  - {name: a, type: vless, server: a.example.com, port: 443, uuid: 123e4567-e89b-12d3-a456-426614174000}\n" +
		"  - {name: b, type: vless, server: b.example.com, port: 443, uuid: 123e4567-e89b-12d3-a456-426614174001}\n"
	wgPayload := "[Interface]\nPrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\n" +
		"[Peer]\nPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=\nEndpoint = a.example.com:51820\n" +
		"[Peer]\nPublicKey = ccccccccccccccccccccccccccccccccccccccccccc=\nEndpoint = b.example.com:51820\n"
	for name, payload := range map[string]string{"json": jsonPayload, "yaml": yamlPayload, "wireguard": wgPayload} {
		r, err := (LinkParser{MaxItems: 1}).Parse([]byte(payload))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "wireguard" {
			if len(r.Servers) != 1 || len(r.Servers[0].Peers) > 1 {
				t.Errorf("%s: peers not capped: %+v", name, r.Servers)
			}
		} else if len(r.Servers) > 1 {
			t.Errorf("%s: %d servers accepted with MaxItems=1", name, len(r.Servers))
		}
		if r.Report.Unsupported == 0 {
			t.Errorf("%s: excess items were not reported as unsupported: %#v", name, r.Report)
		}
	}
}
func FuzzDetect(f *testing.F) {
	f.Add([]byte("vless://x.example:443"))
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = (ImportDetector{}).Detect(b) })
}
func FuzzParseLink(f *testing.F) {
	f.Add("vless://123e4567-e89b-12d3-a456-426614174000@example.com:443")
	f.Fuzz(func(_ *testing.T, s string) { _, _ = (LinkParser{MaxItems: 100}).Parse([]byte(s)) })
}
func BenchmarkParseBase64Subscription(b *testing.B) {
	var lines strings.Builder
	for i := 0; i < 5000; i++ {
		lines.WriteString("vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?type=tcp\n")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(lines.String()))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = (LinkParser{}).Parse([]byte(encoded))
	}
}

// TestXrayConfigurationsBecomeProfiles checks one profile per configuration in
// Remnawave-style subscription lists.
func TestXrayConfigurationsBecomeProfiles(t *testing.T) {
	config := func(name string) string {
		return `{"remarks":"` + name + `","inbounds":[{"listen":"127.0.0.1","port":10808,"protocol":"socks"}],
		"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"185.92.222.239","port":443,
		"users":[{"id":"123e4567-e89b-12d3-a456-426614174000","encryption":"none"}]}]},
		"streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"publicKey":"k","shortId":"s"}}},
		{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[{"domain":["domain:openai.com"],"outboundTag":"proxy"}]}}`
	}
	r, err := (LinkParser{}).Parse([]byte("[" + config("🇳🇱 Нидерланды") + "," + config("Авто") + "]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Servers) != 2 {
		t.Fatalf("servers = %d, report %+v", len(r.Servers), r.Report)
	}
	a, b := r.Servers[0], r.Servers[1]
	if a.Protocol != "xray-profile" || a.DisplayName != "🇳🇱 Нидерланды" || a.Host != "185.92.222.239" || a.Port != 443 {
		t.Fatalf("profile = %+v", a)
	}
	if a.Transport != "xhttp" || a.Security != "reality" || a.CountryCode != "🇳🇱" {
		t.Fatalf("transport, security and country come from the profile: %+v", a)
	}
	if a.Options["profile"] == "" {
		t.Fatal("the configuration travels whole")
	}
	if a.StableKey() == b.StableKey() {
		t.Fatal("two profiles on one server must keep two identities")
	}
}

// TestParserAcceptsNewerUUIDVersions is the regression test for R5-LG-2-3:
// the UUID check rejected versions 6-8, which RFC 9562 defines.
func TestParserAcceptsNewerUUIDVersions(t *testing.T) {
	for _, id := range []string{
		"123e4567-e89b-12d3-a456-426614174000", // v1
		"123e4567-e89b-42d3-a456-426614174000", // v4
		"01926f2a-9c6e-7c3b-b9e8-2b1b3f6a4c5d", // v7
		"123e4567-e89b-82d3-a456-426614174000", // v8
	} {
		r, err := (LinkParser{}).Parse([]byte("vless://" + id + "@a.example:443"))
		if err != nil {
			t.Errorf("uuid %q: Parse error = %v", id, err)
			continue
		}
		if len(r.Servers) != 1 || r.Servers[0].UUID != id {
			t.Errorf("uuid %q was not imported: %#v", id, r.Report)
		}
	}
}

// TestReportItemsAreBounded is the regression test for R5-LG-2-7: the
// per-item reasons must not grow with the input past the item limit.
func TestReportItemsAreBounded(t *testing.T) {
	var sb strings.Builder
	for range 5000 {
		sb.WriteString("vless://123e4567-e89b-12d3-a456-426614174000@a.example:443\n")
	}
	r, err := (LinkParser{MaxItems: 1}).Parse([]byte(sb.String()))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r.Report.UnsupportedItems); got > maxReportItems {
		t.Errorf("UnsupportedItems holds %d reasons, want at most %d", got, maxReportItems)
	}
	if r.Report.Unsupported != 4999 {
		t.Errorf("Unsupported = %d, want 4999", r.Report.Unsupported)
	}
}

// TestPinnedHysteria2LinkIsRefusedNotUnpinned mirrors the sora
// pass1-detail test: pinSHA256 is defined for Hysteria2 links, but no
// engine consumes it, so the link must be refused (counted
// unsupported) instead of imported without its pin.
func TestPinnedHysteria2LinkIsRefusedNotUnpinned(t *testing.T) {
	r, err := (LinkParser{}).Parse([]byte(
		"hysteria2://secret@example.com:443#plain\n" +
			"hy2://secret@example.com:443?pinSHA256=PEgHXXPzTsMBr6Uf5FYZ9CDpGHuCkSKpAZcJZU1hRVc%3D#pinned"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Report.Imported != 1 || r.Report.Unsupported != 1 {
		t.Fatalf("report = %+v, want 1 imported and 1 unsupported", r.Report)
	}
}

// TestParseClashDuplicatesByStableKey is the regression test for the
// duplicate-ValueKey bug: parseYAML appended every proxy without the
// StableKey deduplication parseList already had, so a Clash subscription
// listing one endpoint+UUID under two names produced two specs with the
// same identity.
func TestParseClashDuplicatesByStableKey(t *testing.T) {
	const uuid = "123e4567-e89b-12d3-a456-426614174000"
	payload := "proxies:\n" +
		"  - {name: First, type: vless, server: a.example.com, port: 443, uuid: " + uuid + "}\n" +
		"  - {name: Second, type: vless, server: a.example.com, port: 443, uuid: " + uuid + "}\n"
	r, err := (LinkParser{}).Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Servers) != 1 || r.Servers[0].DisplayName != "First" {
		t.Fatalf("servers = %#v, want only the first entry kept", r.Servers)
	}
	if r.Report.Imported != 1 || r.Report.SkippedDuplicates != 1 {
		t.Fatalf("report = %+v, want 1 imported and 1 skipped duplicate", r.Report)
	}
	if len(r.Report.DuplicateItems) != 1 || r.Report.DuplicateItems[0].Index != 1 || r.Report.DuplicateItems[0].Reason != "duplicate server" {
		t.Fatalf("duplicate items = %#v, want one entry at index 1", r.Report.DuplicateItems)
	}
}

// TestParseJSONDuplicatesByStableKey is the same regression for the
// sing-box JSON path of parseJSON.
func TestParseJSONDuplicatesByStableKey(t *testing.T) {
	const uuid = "123e4567-e89b-12d3-a456-426614174000"
	payload := `{"outbounds":[` +
		`{"type":"vless","tag":"First","server":"a.example.com","server_port":443,"uuid":"` + uuid + `"},` +
		`{"type":"vless","tag":"Second","server":"a.example.com","server_port":443,"uuid":"` + uuid + `"}]}`
	r, err := (LinkParser{}).Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Servers) != 1 || r.Servers[0].DisplayName != "First" {
		t.Fatalf("servers = %#v, want only the first entry kept", r.Servers)
	}
	if r.Report.Imported != 1 || r.Report.SkippedDuplicates != 1 {
		t.Fatalf("report = %+v, want 1 imported and 1 skipped duplicate", r.Report)
	}
	if len(r.Report.DuplicateItems) != 1 || r.Report.DuplicateItems[0].Index != 1 || r.Report.DuplicateItems[0].Reason != "duplicate server" {
		t.Fatalf("duplicate items = %#v, want one entry at index 1", r.Report.DuplicateItems)
	}
}

// TestParseJSONAndYAMLKeepDistinctServers guards the deduplication against
// overreach: a different UUID or a different endpoint is a different
// server, and xray-profile entries keep distinct remarks (their
// StableKey includes the display name).
func TestParseJSONAndYAMLKeepDistinctServers(t *testing.T) {
	const uuidA = "123e4567-e89b-12d3-a456-426614174000"
	const uuidB = "123e4567-e89b-42d3-a456-426614174001"
	cases := map[string]string{
		"json different uuid": `{"outbounds":[` +
			`{"type":"vless","tag":"One","server":"a.example.com","server_port":443,"uuid":"` + uuidA + `"},` +
			`{"type":"vless","tag":"Two","server":"a.example.com","server_port":443,"uuid":"` + uuidB + `"}]}`,
		"json different endpoint": `{"outbounds":[` +
			`{"type":"vless","tag":"One","server":"a.example.com","server_port":443,"uuid":"` + uuidA + `"},` +
			`{"type":"vless","tag":"Two","server":"b.example.com","server_port":443,"uuid":"` + uuidA + `"}]}`,
		"yaml different uuid": "proxies:\n" +
			"  - {name: One, type: vless, server: a.example.com, port: 443, uuid: " + uuidA + "}\n" +
			"  - {name: Two, type: vless, server: a.example.com, port: 443, uuid: " + uuidB + "}\n",
		"yaml different endpoint": "proxies:\n" +
			"  - {name: One, type: vless, server: a.example.com, port: 443, uuid: " + uuidA + "}\n" +
			"  - {name: Two, type: vless, server: b.example.com, port: 443, uuid: " + uuidA + "}\n",
	}
	for name, payload := range cases {
		r, err := (LinkParser{}).Parse([]byte(payload))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(r.Servers) != 2 || r.Report.SkippedDuplicates != 0 {
			t.Errorf("%s: servers = %d, report = %+v, want both servers kept", name, len(r.Servers), r.Report)
		}
	}
	// Xray profiles on one endpoint with different remarks are distinct
	// (the name is part of their StableKey); the exact same profile
	// twice is a duplicate on the xray-config append site.
	config := func(name string) string {
		return `{"remarks":"` + name + `","inbounds":[{"listen":"127.0.0.1","port":10808,"protocol":"socks"}],` +
			`"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"185.92.222.239","port":443,` +
			`"users":[{"id":"123e4567-e89b-12d3-a456-426614174000","encryption":"none"}]}]},` +
			`"streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"publicKey":"k","shortId":"s"}}},` +
			`{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[{"domain":["domain:openai.com"],"outboundTag":"proxy"}]}}`
	}
	r, err := (LinkParser{}).Parse([]byte("[" + config("One") + "," + config("Two") + "]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Servers) != 2 || r.Report.SkippedDuplicates != 0 {
		t.Fatalf("profiles with different remarks: servers = %d, report = %+v, want both kept", len(r.Servers), r.Report)
	}
	r, err = (LinkParser{}).Parse([]byte("[" + config("Same") + "," + config("Same") + "]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Servers) != 1 || r.Report.SkippedDuplicates != 1 || len(r.Report.DuplicateItems) != 1 {
		t.Fatalf("identical profiles: servers = %d, report = %+v, want 1 kept and 1 skipped duplicate", len(r.Servers), r.Report)
	}
}
