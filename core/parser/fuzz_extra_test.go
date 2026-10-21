package parser

import "testing"

// Wave-B fuzz targets (corpus parity with sora): direct entry into each
// format branch. The olcrtc target differs from sora's on purpose:
// legacy has no ShareLink emitter (see olcrtc.go), so it pins parse
// determinism instead of the parse∘ShareLink identity.

// FuzzParseJSONFormats drives parseJSON in each of its three shapes
// (SIP008, sing-box, Xray/Remnawave).
func FuzzParseJSONFormats(f *testing.F) {
	f.Add([]byte(`{"version":2,"servers":[{"id":1,"remarks":"r","server":"a.example","server_port":8388,"method":"aes-256-gcm","password":"pw"}]}`), uint8(0))
	f.Add([]byte(`{"outbounds":[{"type":"shadowsocks","tag":"p","server":"a.example","server_port":8388,"method":"aes-256-gcm","password":"pw"}]}`), uint8(1))
	f.Add([]byte(`[{"remarks":"x","outbounds":[{"protocol":"trojan","settings":{"servers":[{"address":"a.example","port":443,"password":"pw"}]}}]}]`), uint8(2))
	f.Add([]byte(`{"version":2,"servers":[]}`), uint8(0))
	f.Add([]byte(`null`), uint8(1))
	formats := []Format{FormatSIP008, FormatSingBox, FormatXray}
	f.Fuzz(func(_ *testing.T, b []byte, which uint8) {
		_, _ = (LinkParser{MaxItems: 100}).parseJSON(b, formats[which%uint8(len(formats))])
	})
}

// FuzzParseYAML drives the Clash subset decoder directly.
func FuzzParseYAML(f *testing.F) {
	f.Add([]byte("proxies:\n  - name: a\n    type: ss\n    server: a.example\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw"))
	f.Add([]byte("proxies: []"))
	f.Add([]byte("proxies:\n  - &x {name: a, type: vmess, server: a.example, port: 443, uuid: 123e4567-e89b-12d3-a456-426614174000}\n  - *x"))
	f.Add([]byte("proxies:\n  - name: [nested, list]\n    type: {deep: map}"))
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = (LinkParser{MaxItems: 100}).parseYAML(b)
	})
}

// FuzzParseWG drives the WireGuard config decoder directly.
func FuzzParseWG(f *testing.F) {
	f.Add("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBE=\nEndpoint = a.example:51820")
	f.Add("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBE=\nEndpoint = [2001:db8::1]:51820\nAllowedIPs = ::/0")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = (LinkParser{MaxItems: 100}).parseWG(s)
	})
}

// FuzzOlcRTCLink drives the hand-cut olcrtc:// grammar; parsing one
// link twice must yield the same stable identities (determinism pins
// the map-ordering hazards a hand parser can hide).
func FuzzOlcRTCLink(f *testing.F) {
	const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	f.Add("olcrtc://wbstream?datachannel@room-01#" + key + "$seed")
	f.Add("olcrtc://jitsi?vp8channel<vp8-fps=30>@https://meet.jit.si/room#" + key)
	f.Add("olcrtc://telemost?videochannel<video-codec=qrcode>@room#" + key + "$name")
	f.Add("olcrtc://none?seichannel<batch=1&frag=1200>@r#" + key)
	f.Fuzz(func(t *testing.T, s string) {
		r1, err1 := (LinkParser{MaxItems: 100}).Parse([]byte(s))
		r2, err2 := (LinkParser{MaxItems: 100}).Parse([]byte(s))
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("parse of %q is non-deterministic: %v vs %v", s, err1, err2)
		}
		if err1 != nil {
			return
		}
		if len(r1.Servers) != len(r2.Servers) {
			t.Fatalf("parse of %q changed server count: %d vs %d", s, len(r1.Servers), len(r2.Servers))
		}
		for i := range r1.Servers {
			if r1.Servers[i].StableKey() != r2.Servers[i].StableKey() {
				t.Fatalf("parse of %q changed identity at %d", s, i)
			}
		}
	})
}
