package control_test

import (
	"context"
	"strings"
	"testing"

	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
)

// SP6b (REVIEW-SP6 F1) at the full ParseImport path: a subscription
// mixing a healthy trojan with a REALITY vless whose short-id is an
// unquoted YAML number used to fail as one atomic unit — the number
// reached blob extraction as a float64 and was rejected as "not a
// string". The import must now succeed as a whole and the stored
// credential must hold the short-id in its digit-string form.
func TestParseImportNumericShortIDSubscription(t *testing.T) {
	server, store := newTestServer(t)
	payload := "proxies:\n" +
		"  - name: trojan-ok\n    type: trojan\n    server: tj.example.com\n    port: 443\n    password: secret-pass\n" +
		"  - name: vless-numeric-sid\n    type: vless\n    server: edge.example.com\n    port: 443\n" +
		"    uuid: b831381d-6324-4d53-ad4f-8cda48b30811\n    tls: true\n" +
		"    reality-opts: {public-key: Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw, short-id: 12345678}\n"
	response, err := server.ParseImport(context.Background(), &corev1.ParseImportRequest{
		ApiVersion: clientVersion(),
		RequestId:  "req-sp6b",
		Payload:    []byte(payload),
	})
	if err != nil {
		t.Fatalf("ParseImport() error = %v", err)
	}
	if response.GetError() != nil {
		t.Fatalf("ParseImport() failed with %v", response.GetError())
	}
	outbounds := response.GetSessionPlan().GetOutbounds()
	if len(outbounds) != 2 {
		t.Fatalf("import produced %d outbounds, want 2 (the whole subscription, atomically)", len(outbounds))
	}
	found := false
	for _, ob := range outbounds {
		material, err := store.Get(ob.GetCredentials().GetReference())
		if err != nil {
			t.Fatalf("the store does not hold a reference: %v", err)
		}
		if strings.Contains(string(material), `"short_id":"12345678"`) {
			found = true
		}
	}
	if !found {
		t.Error("no stored credential holds the converted short-id \"12345678\"")
	}
}
