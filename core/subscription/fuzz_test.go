package subscription

import (
	"net/http"
	"testing"
)

// Wave-B fuzz targets (parity with sora): the subscription metadata
// surface parses provider-controlled headers and bodies.

// FuzzParseInfo drives parseInfo over a fuzzed body plus fuzzed values
// for the headers providers actually use to carry metadata.
func FuzzParseInfo(f *testing.F) {
	f.Add([]byte("#profile-title: seed\nvless://123e4567-e89b-12d3-a456-426614174000@a.example:443"), "upload=1; download=2; total=100; expire=1893456000", "base64:c2VlZA==", "https://example.com/panel")
	f.Add([]byte(""), "", "", "")
	f.Add([]byte("#subscription-userinfo: upload=18446744073709551615; download=0; total=0; expire=-1"), "garbage", "", "")
	f.Fuzz(func(_ *testing.T, body []byte, userinfo, title, web string) {
		h := http.Header{}
		if userinfo != "" {
			h.Set("subscription-userinfo", userinfo)
		}
		if title != "" {
			h.Set("profile-title", title)
		}
		if web != "" {
			h.Set("profile-web-page-url", web)
		}
		_ = parseInfo(h, body)
		_, _ = bodyHeaders(body)
		_, _ = decodeBody(body)
	})
}

// FuzzSplitFallback drives the fallback-reference splitter/joiner pair.
func FuzzSplitFallback(f *testing.F) {
	f.Add("https://a.example/sub")
	f.Add("https://a.example/sub|https://b.example/sub")
	f.Add("|")
	f.Add("https://a.example/sub|")
	f.Fuzz(func(_ *testing.T, s string) {
		primary, fallback, err := SplitFallback(s)
		if err != nil {
			return
		}
		_ = JoinFallback(primary, fallback)
	})
}
