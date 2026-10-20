package parser

import (
	"net/url"
	"testing"
)

// TestParseExtraDownloadSettings is ported from sora's parser_test.go
// (S5-SP4): the XHTTP up/down split rides in the extra=<url-encoded
// JSON> parameter (de-facto link standard, Xray camelCase).
func TestParseExtraDownloadSettings(t *testing.T) {
	link := func(extra string) string {
		q := url.Values{}
		q.Set("type", "xhttp")
		q.Set("security", "tls")
		if extra != "" {
			q.Set("extra", extra)
		}
		return "vless://123e4567-e89b-12d3-a456-426614174000@up.example.com:443?" + q.Encode() + "#X"
	}
	parse := func(extra string) OutboundSpec {
		r, err := (LinkParser{}).Parse([]byte(link(extra)))
		if err != nil {
			t.Fatalf("extra %q: import failed: %v", extra, err)
		}
		if len(r.Servers) != 1 {
			t.Fatalf("extra %q: %#v", extra, r.Report)
		}
		return r.Servers[0]
	}
	// Valid extra: downloadSettings reaches the spec.
	s := parse(`{"downloadSettings":{"address":"down.example.com","port":8443}}`)
	if s.DownloadAddress != "down.example.com" || s.DownloadPort != 8443 {
		t.Errorf("valid extra: got %q:%d", s.DownloadAddress, s.DownloadPort)
	}
	// An xmux/padding-only extra leaves the split zero — and its own
	// sections still parse (in sora's copy of this test the xmux
	// fields had no producer yet; the sections are independent, see
	// TestParseExtraXmuxAndPadding).
	s = parse(`{"xmux":{"maxConcurrency":64},"xPaddingBytes":"100-1000"}`)
	if s.DownloadAddress != "" || s.DownloadPort != 0 {
		t.Errorf("xmux-only extra: got %q:%d, want zero", s.DownloadAddress, s.DownloadPort)
	}
	if s.XmuxMaxConcurrency != 64 || s.XPaddingBytes != "100-1000" {
		t.Errorf("xmux-only extra: tuning lost: %+v", s)
	}
	// No extra: zero split.
	s = parse("")
	if s.DownloadAddress != "" || s.DownloadPort != 0 {
		t.Errorf("no extra: got %q:%d, want zero", s.DownloadAddress, s.DownloadPort)
	}
	// Garbage extra is provider decoration: the import survives, the
	// split is dropped.
	for name, extra := range map[string]string{
		"malformed json":        "{not json",
		"empty object":          "{}",
		"address without port":  `{"downloadSettings":{"address":"down.example.com"}}`,
		"port without address":  `{"downloadSettings":{"port":8443}}`,
		"zero port":             `{"downloadSettings":{"address":"down.example.com","port":0}}`,
		"out of range port":     `{"downloadSettings":{"address":"down.example.com","port":99999}}`,
		"negative port":         `{"downloadSettings":{"address":"down.example.com","port":-1}}`,
		"string port":           `{"downloadSettings":{"address":"down.example.com","port":"8443"}}`,
		"null downloadSettings": `{"downloadSettings":null}`,
		"non-object extra":      `[1,2,3]`,
	} {
		s = parse(extra)
		if s.DownloadAddress != "" || s.DownloadPort != 0 {
			t.Errorf("%s: got %q:%d, want zero", name, s.DownloadAddress, s.DownloadPort)
		}
	}
}
