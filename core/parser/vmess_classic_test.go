package parser

import (
	"encoding/base64"
	"errors"
	"testing"
)

// Classic VMess parity with sora (AUDIT-PARITY §3 neighbor #3): the
// classic share form vmess://<base64 JSON> must import end-to-end
// through the public Parse. Legacy's parseVMess once read the blob
// from u.Opaque/u.Path, which never hold it (url.Parse puts it in
// u.Host/u.Path), so every classic link failed validation and
// vanished from mixed imports, and the G2 alterId refusal was
// unreachable on this path. Ported from sora's
// TestParseClassicVMessJSON / TestParseVMessURLStyleStillWorks.

func TestParseClassicVMessJSON(t *testing.T) {
	doc := `{"v":"2","ps":"🇩🇪 VMess Berlin","add":"vmess.example.com","port":"24444","id":"123e4567-e89b-12d3-a456-426614174000","aid":"0","scy":"aes-128-gcm","net":"ws","type":"none","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"vmess.example.com","alpn":"h2,http/1.1","fp":"chrome"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(doc))
	r, err := (LinkParser{}).Parse([]byte(link))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Servers) != 1 {
		t.Fatalf("servers = %d, want 1 (report %+v)", len(r.Servers), r.Report)
	}
	o := r.Servers[0]
	if o.Protocol != "vmess" || o.Host != "vmess.example.com" || o.Port != 24444 {
		t.Fatalf("endpoint = %s %s:%d", o.Protocol, o.Host, o.Port)
	}
	if o.UUID != "123e4567-e89b-12d3-a456-426614174000" || o.Cipher != "aes-128-gcm" {
		t.Fatalf("credentials = uuid %q cipher %q", o.UUID, o.Cipher)
	}
	if o.Transport != "ws" || o.Security != "tls" || o.ServerName != "vmess.example.com" {
		t.Fatalf("transport/security/sni = %q %q %q", o.Transport, o.Security, o.ServerName)
	}
	if o.HostHeader != "cdn.example.com" || o.Path != "/ws" || o.Fingerprint != "chrome" {
		t.Fatalf("ws fields = host %q path %q fp %q", o.HostHeader, o.Path, o.Fingerprint)
	}
	if len(o.ALPN) != 2 || o.DisplayName != "🇩🇪 VMess Berlin" {
		t.Fatalf("alpn/name = %v %q", o.ALPN, o.DisplayName)
	}

	// Numeric port/aid and the plain (no-TLS) variant.
	doc2 := `{"v":"2","ps":"plain","add":"192.0.2.5","port":443,"id":"123e4567-e89b-12d3-a456-426614174000","aid":0,"net":"tcp","tls":""}`
	r2, err := (LinkParser{}).Parse([]byte("vmess://" + base64.RawURLEncoding.EncodeToString([]byte(doc2))))
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.Servers) != 1 || r2.Servers[0].Port != 443 || r2.Servers[0].Security != "none" || r2.Servers[0].Cipher != "auto" {
		t.Fatalf("numeric variant = %+v", r2.Servers)
	}

	// Without "ps", the link fragment is the fallback display name.
	doc3 := `{"v":"2","add":"vmess.example.com","port":443,"id":"123e4567-e89b-12d3-a456-426614174000","aid":0}`
	r3, err := (LinkParser{}).Parse([]byte("vmess://" + base64.StdEncoding.EncodeToString([]byte(doc3)) + "#FromFragment"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r3.Servers) != 1 || r3.Servers[0].DisplayName != "FromFragment" {
		t.Fatalf("fragment fallback = %+v", r3.Servers)
	}

	// A classic link inside a mixed list must not be dropped silently.
	mixed := link + "\n" + "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls#V"
	r4, err := (LinkParser{}).Parse([]byte(mixed))
	if err != nil {
		t.Fatal(err)
	}
	if len(r4.Servers) != 2 {
		t.Fatalf("mixed import servers = %d, want 2 (report %+v)", len(r4.Servers), r4.Report)
	}
}

// TestParseClassicVMessAlterIDRefusedEndToEnd pins G2 on the classic
// path: a non-zero alterId (pre-AEAD) in a classic vmess:// link is
// refused as unsupported, never silently upgraded to AEAD.
func TestParseClassicVMessAlterIDRefusedEndToEnd(t *testing.T) {
	for _, doc := range []string{
		`{"v":"2","ps":"legacy","add":"vmess.example.com","port":"443","id":"123e4567-e89b-12d3-a456-426614174000","aid":"64","scy":"auto","net":"ws","tls":"tls"}`,
		`{"v":"2","ps":"legacy","add":"vmess.example.com","port":443,"id":"123e4567-e89b-12d3-a456-426614174000","aid":64,"net":"tcp","tls":""}`,
	} {
		link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(doc))
		if _, err := parseLink(link); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("doc %s: parseLink = %v, want ErrUnsupported", doc, err)
		}
		r, err := (LinkParser{}).Parse([]byte(link))
		if err != nil {
			t.Fatalf("doc %s: Parse = %v", doc, err)
		}
		if len(r.Servers) != 0 || r.Report.Imported != 0 || r.Report.Unsupported != 1 {
			t.Fatalf("doc %s: servers = %d, report = %+v, want 0 imported / 1 unsupported", doc, len(r.Servers), r.Report)
		}
	}
}

// TestParseClassicVMessBrokenBlob pins the failure shape for a
// classic-looking link whose payload is unusable: an honest error at
// the link level and a counted invalid item at the Parse level —
// never a panic and never a silently imported (or vanished) server.
func TestParseClassicVMessBrokenBlob(t *testing.T) {
	links := map[string]string{
		"not base64":       "vmess://!!!not-base64!!!",
		"base64 non-JSON":  "vmess://" + base64.StdEncoding.EncodeToString([]byte("this is not json")),
		"truncated JSON":   "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"vmess.example.com","port":443,`)),
		"JSON no endpoint": "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"empty"}`)),
	}
	for name, link := range links {
		t.Run(name, func(t *testing.T) {
			if _, err := parseLink(link); err == nil {
				t.Fatalf("parseLink(%q) = nil error, want an honest error", link)
			}
			r, _ := (LinkParser{}).Parse([]byte(link))
			if len(r.Servers) != 0 || r.Report.Imported != 0 {
				t.Fatalf("Parse(%q) imported %d servers, want 0", link, len(r.Servers))
			}
			if r.Report.Invalid+r.Report.Unsupported == 0 {
				t.Fatalf("Parse(%q) report = %+v, want the broken item counted, not silently skipped", link, r.Report)
			}
		})
	}
}

// TestParseClassicVMessAllowInsecure pins the classic path's
// AllowInsecure field (REVIEW-G4 remark Z1: the reviewer verified
// the behaviour by probes in both repositories — eight forms — but
// no test pinned it in either). Both spellings feed it, and
// jsonBool's truth set is the whole contract: JSON true, a non-zero
// number, "1" and case-insensitive "true" are true; everything else,
// including "yes", is false.
func TestParseClassicVMessAllowInsecure(t *testing.T) {
	parse := func(t *testing.T, extra string) OutboundSpec {
		t.Helper()
		doc := `{"v":"2","add":"vmess.example.com","port":443,"id":"123e4567-e89b-12d3-a456-426614174000","aid":0` + extra + `}`
		r, err := (LinkParser{}).Parse([]byte("vmess://" + base64.StdEncoding.EncodeToString([]byte(doc))))
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Servers) != 1 {
			t.Fatalf("servers = %d, want 1 (report %+v)", len(r.Servers), r.Report)
		}
		return r.Servers[0]
	}
	if o := parse(t, `,"insecure":true`); !o.AllowInsecure {
		t.Error(`"insecure":true must set AllowInsecure`)
	}
	if o := parse(t, `,"allowInsecure":true`); !o.AllowInsecure {
		t.Error(`"allowInsecure":true must set AllowInsecure`)
	}
	for _, form := range []string{`1`, `"1"`, `"true"`, `"TRUE"`} {
		if o := parse(t, `,"insecure":`+form); !o.AllowInsecure {
			t.Errorf(`"insecure":%s must set AllowInsecure`, form)
		}
	}
	for _, form := range []string{`false`, `0`, `"yes"`, `"false"`} {
		if o := parse(t, `,"insecure":`+form); o.AllowInsecure {
			t.Errorf(`"insecure":%s must not set AllowInsecure`, form)
		}
	}
	if o := parse(t, ``); o.AllowInsecure {
		t.Error("a document without the key must not set AllowInsecure")
	}
}

// TestParseVMessURLStyleStillWorks guards the Xray query form, the
// only VMess dialect the suite exercised before the classic form was
// restored.
func TestParseVMessURLStyleStillWorks(t *testing.T) {
	r, err := (LinkParser{}).Parse([]byte("vmess://123e4567-e89b-12d3-a456-426614174000@node.example.com:443?type=ws&security=tls&path=%2Fws&host=cdn.example.com&sni=cdn.example.com#VMess"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Servers) != 1 || r.Servers[0].Protocol != "vmess" || r.Servers[0].Transport != "ws" || r.Servers[0].Security != "tls" {
		t.Fatalf("url-style vmess = %+v", r.Servers)
	}
}
