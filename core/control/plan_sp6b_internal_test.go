package control

import (
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/errs"
	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
	"github.com/levvs-one/sora-client/core/parser"
)

// SP6b (REVIEW-SP6 F1): an unquoted all-digit short-id in a Clash
// document is turned into a number by the YAML decoder, and "tls":
// null is how both dialects spell an absent TLS block. Both used to
// fail blob extraction, and because ParseImport is atomic, one such
// server rejected the whole subscription. The reference does not
// reject these documents at import at all (its parser stores the
// blobs unexamined); legacy now converts the number to the digits
// mihomo itself would read and treats null as absent.

const (
	sp6bUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
	sp6bPbk  = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"
)

func TestImportedNumericShortIDSurvives(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want string
	}{
		{
			name: "clash flow numeric short-id 8 digits",
			src: "proxies:\n  - name: p\n    type: vless\n    server: edge.example.com\n    port: 443\n" +
				"    uuid: " + sp6bUUID + "\n    tls: true\n    reality-opts: {public-key: " + sp6bPbk + ", short-id: 12345678}\n",
			want: "12345678",
		},
		{
			name: "clash block numeric short-id 16 digits",
			src: "proxies:\n  - name: p\n    type: vless\n    server: edge.example.com\n    port: 443\n" +
				"    uuid: " + sp6bUUID + "\n    tls: true\n    reality-opts:\n      public-key: " + sp6bPbk + "\n      short-id: 1234567890123456\n",
			want: "1234567890123456",
		},
		{
			name: "sing-box numeric short_id",
			src: `{"outbounds":[{"type":"vless","tag":"p","server":"edge.example.com","server_port":443,` +
				`"uuid":"` + sp6bUUID + `","tls":{"enabled":true,"reality":{"enabled":true,"public_key":"` + sp6bPbk + `","short_id":12345678}}}]}`,
			want: "12345678",
		},
		{
			name: "clash string short-id unchanged",
			src: "proxies:\n  - name: p\n    type: vless\n    server: edge.example.com\n    port: 443\n" +
				"    uuid: " + sp6bUUID + "\n    tls: true\n    reality-opts: {public-key: " + sp6bPbk + ", short-id: 6ba85179e30d4fc2}\n",
			want: "6ba85179e30d4fc2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parser.LinkParser{}.Parse([]byte(tc.src))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			plan, _ := importedPlan(t, result)
			o := plan.Outbounds[0]
			if !o.TLS.Reality || o.TLS.RealityPublicKey != sp6bPbk {
				t.Fatalf("REALITY lost on the way to the engine: %+v", o.TLS)
			}
			if o.TLS.RealityShortID != tc.want {
				t.Errorf("short-id = %q, want %q", o.TLS.RealityShortID, tc.want)
			}
		})
	}
}

func TestImportedFractionalShortIDFailsClosed(t *testing.T) {
	src := "proxies:\n  - name: p\n    type: vless\n    server: edge.example.com\n    port: 443\n" +
		"    uuid: " + sp6bUUID + "\n    tls: true\n    reality-opts: {public-key: " + sp6bPbk + ", short-id: 123.5}\n"
	result, err := parser.LinkParser{}.Parse([]byte(src))
	if err != nil || len(result.Servers) != 1 {
		t.Fatalf("Parse = %+v, %v", result, err)
	}
	if _, err := credentialDocument(result.Servers[0]); err == nil {
		t.Fatal("a fractional short-id is a short-id in no dialect and must fail the import")
	} else if errs.CodeOf(err) != errs.CodeInvalidArgument {
		t.Fatalf("code = %q, want invalid_argument (%v)", errs.CodeOf(err), err)
	}
}

func TestImportedNullTLSIsAbsent(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		{
			name: "clash empty tls line",
			src: "proxies:\n  - name: p\n    type: vless\n    server: edge.example.com\n    port: 443\n" +
				"    uuid: " + sp6bUUID + "\n    network: ws\n    tls:\n    ws-opts: {path: /ws}\n",
		},
		{
			name: "clash tls false",
			src: "proxies:\n  - name: p\n    type: vless\n    server: edge.example.com\n    port: 443\n" +
				"    uuid: " + sp6bUUID + "\n    network: ws\n    tls: false\n    ws-opts: {path: /ws}\n",
		},
		{
			name: "sing-box tls null",
			src: `{"outbounds":[{"type":"vless","tag":"p","server":"edge.example.com","server_port":443,` +
				`"uuid":"` + sp6bUUID + `","tls":null,"transport":{"type":"ws","path":"/ws"}}]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parser.LinkParser{}.Parse([]byte(tc.src))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			plan, wire := importedPlan(t, result)
			if wire.Security == "tls" || wire.Security == "reality" {
				t.Errorf("wire security = %q, want no TLS claim for an absent tls value", wire.Security)
			}
			o := plan.Outbounds[0]
			if o.TLS.Reality {
				t.Errorf("an absent tls value must not invent REALITY: %+v", o.TLS)
			}
			if o.Transport.Type != "ws" || o.Transport.Path != "/ws" {
				t.Errorf("transport lost next to the null tls: %+v", o.Transport)
			}
		})
	}
}

// SP6b (REVIEW-SP6 F2): Clash h2-opts used to be silently dropped —
// the plan validated but carried no path or host. It is now extracted
// like the ws/grpc/xhttp option blocks. The http transport is the
// opposite case and is pinned by TestImportedHTTPTransportRefused.
func TestImportedH2OptsSurvive(t *testing.T) {
	src := "proxies:\n  - name: p\n    type: vless\n    server: edge.example.com\n    port: 443\n" +
		"    uuid: " + sp6bUUID + "\n    network: h2\n    tls: true\n    servername: s.example.com\n" +
		"    h2-opts: {path: /h2-path, host: [h2cdn.example.com]}\n"
	result, err := parser.LinkParser{}.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	plan, wire := importedPlan(t, result)
	if wire.Transport != "h2" {
		t.Errorf("wire transport = %q, want h2", wire.Transport)
	}
	o := plan.Outbounds[0]
	if o.Transport.Type != "h2" || o.Transport.Path != "/h2-path" || o.Transport.Host != "h2cdn.example.com" {
		t.Errorf("h2-opts lost on the way to the engine: %+v", o.Transport)
	}
	if o.TLS.ServerName != "s.example.com" {
		t.Errorf("server name = %q, want s.example.com", o.TLS.ServerName)
	}
}

// SP6b (REVIEW-SP6 F2): the Clash http transport is refused at
// import. No engine carries an "http" plan transport (the whitelist
// is byte-identical in the reference, which refuses the same plans
// at session build), and renaming it to h2 would silently change
// the wire protocol — in the Clash dialect the two are different
// transports. The sing-box transport of the same name IS the plan's
// h2 (see TestImportedSingBoxHTTPTransportIsH2): the difference is
// the dialect, not the spelling.
func TestImportedHTTPTransportRefused(t *testing.T) {
	src := "proxies:\n  - name: p\n    type: vless\n    server: edge.example.com\n    port: 443\n" +
		"    uuid: " + sp6bUUID + "\n    network: http\n    tls: true\n" +
		"    http-opts: {path: [/http-path], headers: {Host: [httpcdn.example.com]}}\n"
	result, err := parser.LinkParser{}.Parse([]byte(src))
	if err != nil || len(result.Servers) != 1 {
		t.Fatalf("Parse = %+v, %v", result, err)
	}
	_, err = credentialDocument(result.Servers[0])
	if err == nil {
		t.Fatal("the http transport must fail the import instead of importing clean and failing at session build")
	}
	if errs.CodeOf(err) != errs.CodeInvalidArgument {
		t.Fatalf("code = %q, want invalid_argument (%v)", errs.CodeOf(err), err)
	}
	if !strings.Contains(err.Error(), "http transport") {
		t.Errorf("the refusal must name the transport: %v", err)
	}
}

func TestImportedSingBoxHTTPTransportIsH2(t *testing.T) {
	src := `{"outbounds":[{"type":"vless","tag":"p","server":"edge.example.com","server_port":443,` +
		`"uuid":"` + sp6bUUID + `","tls":{"enabled":true},"transport":{"type":"http","path":"/sb-path","host":["sbcdn.example.com"]}}]}`
	result, err := parser.LinkParser{}.Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	plan, _ := importedPlan(t, result)
	o := plan.Outbounds[0]
	if o.Transport.Type != "h2" || o.Transport.Path != "/sb-path" || o.Transport.Host != "sbcdn.example.com" {
		t.Errorf("sing-box http transport = %+v, want the plan's h2 with its path and first host", o.Transport)
	}
}

// SP6b (REVIEW-SP6 F3): a present but malformed REALITY key or
// short-id is NOT refused at import — only a claimed-but-absent key
// is. The form is judged by plan validation, whose messages name the
// defect; the reference's import performs no form check at all, so
// this split is the parity behaviour, pinned here deliberately.
func TestImportedMalformedRealityFailsAtValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want string
	}{
		{
			name: "public key not a key",
			src: "proxies:\n  - name: p\n    type: vless\n    server: edge.example.com\n    port: 443\n" +
				"    uuid: " + sp6bUUID + "\n    tls: true\n    reality-opts: {public-key: AAAA, short-id: 6ba85179e30d4fc2}\n",
			want: "REALITY public key is not a 32-byte base64url X25519 key",
		},
		{
			name: "short-id not hex",
			src: "proxies:\n  - name: p\n    type: vless\n    server: edge.example.com\n    port: 443\n" +
				"    uuid: " + sp6bUUID + "\n    tls: true\n    reality-opts: {public-key: " + sp6bPbk + ", short-id: zzzz}\n",
			want: "REALITY shortId must be hex",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parser.LinkParser{}.Parse([]byte(tc.src))
			if err != nil || len(result.Servers) != 1 {
				t.Fatalf("Parse = %+v, %v", result, err)
			}
			document, err := credentialDocument(result.Servers[0])
			if err != nil {
				t.Fatalf("a malformed-but-present key must pass the import (the form is validation's job): %v", err)
			}
			wire := outboundToProto(result.Servers[0], "vault:sp6b")
			in := &corev1.SessionPlan{
				TunnelMode: corev1.TunnelMode_TUNNEL_MODE_APPLICATION,
				Outbounds:  []*corev1.OutboundSpec{wire},
			}
			_, err = planFromProto(in, "s", mapResolver{data: map[string][]byte{"vault:sp6b": document}})
			if err == nil {
				t.Fatal("a malformed REALITY form must fail plan validation")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("plan error = %v, want it to name %q", err, tc.want)
			}
		})
	}
}
