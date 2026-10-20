package parser

import (
	"encoding/json"
	"errors"
	"testing"
)

// VMess alterId parity with sora (AUDIT-PARITY G2): a non-zero alterId
// is the legacy pre-AEAD protocol and must be refused as unsupported at
// import, never silently upgraded to AEAD. Ported from sora's
// TestCensorP2VMessAlterIDLegacyRefused, adapted to the legacy parser
// shape: AEAD acceptance here is pinned on the URL form and on the
// sing-box-shaped JSON documents
// mapJSONSpec imports, and the classic v2rayN documents of sora's test
// are pinned at the mapJSONSpec level itself. The classic-link path
// itself (vmess://<base64 JSON> through Parse) reaches mapVMessJSON
// since the G4 port and is pinned end-to-end in vmess_classic_test.go.

func TestVMessAlterIDLegacyRefused(t *testing.T) {
	for _, doc := range []string{
		`{"v":"2","ps":"legacy","add":"vmess.example.com","port":"443","id":"123e4567-e89b-12d3-a456-426614174000","aid":"64","scy":"auto","net":"ws","tls":"tls"}`,
		`{"v":"2","ps":"legacy","add":"vmess.example.com","port":443,"id":"123e4567-e89b-12d3-a456-426614174000","aid":64,"net":"tcp","tls":""}`,
	} {
		var m map[string]any
		if err := json.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatal(err)
		}
		if _, err := mapJSONSpec(m, "vmess"); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("doc %s: mapJSONSpec = %v, want ErrUnsupported", doc, err)
		}
	}
	// URL form with ?aid=16.
	if _, err := parseLink("vmess://123e4567-e89b-12d3-a456-426614174000@vmess.example.com:443?aid=16#x"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("url-form aid = %v, want ErrUnsupported", err)
	}
	// sing-box-shaped JSON document with a non-zero alter_id, through
	// the generic JSON mapper and through a full Parse.
	if _, err := mapJSONSpec(map[string]any{
		"type": "vmess", "server": "vmess.example.com", "server_port": float64(443),
		"uuid": "123e4567-e89b-12d3-a456-426614174000", "alter_id": float64(64),
	}, ""); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("mapJSONSpec alter_id = %v, want ErrUnsupported", err)
	}
	res, _ := (LinkParser{}).Parse([]byte(`{"outbounds":[{"type":"vmess","server":"vmess.example.com","server_port":443,"uuid":"123e4567-e89b-12d3-a456-426614174000","alter_id":64}]}`))
	if res.Report.Imported != 0 {
		t.Fatalf("sing-box doc with alter_id 64: imported %d servers, want 0", res.Report.Imported)
	}
	// The direct check, exactly as the sora test pins it.
	if err := checkVMessAlterID(float64(4)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("checkVMessAlterID(4) = %v, want ErrUnsupported", err)
	}
	if err := checkVMessAlterID("64"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("checkVMessAlterID(\"64\") = %v, want ErrUnsupported", err)
	}
	if err := checkVMessAlterID(nil); err != nil {
		t.Fatalf("checkVMessAlterID(nil) = %v", err)
	}
}

func TestVMessAlterIDAEADAccepted(t *testing.T) {
	// Zero, "0", "" and absent are AEAD and pass the direct check.
	for _, v := range []any{nil, float64(0), 0, "0", ""} {
		if err := checkVMessAlterID(v); err != nil {
			t.Fatalf("checkVMessAlterID(%v) = %v, want nil", v, err)
		}
	}
	// AEAD URL forms (aid 0 / absent) still import.
	for _, link := range []string{
		"vmess://123e4567-e89b-12d3-a456-426614174000@vmess.example.com:443?aid=0#x",
		"vmess://123e4567-e89b-12d3-a456-426614174000@vmess.example.com:443#x",
	} {
		if _, err := parseLink(link); err != nil {
			t.Fatalf("AEAD link %q refused: %v", link, err)
		}
	}
	// AEAD sing-box-shaped JSON documents (alter_id 0 / aid "0" /
	// absent) still import through a full Parse.
	for _, doc := range []string{
		`{"outbounds":[{"type":"vmess","server":"vmess.example.com","server_port":443,"uuid":"123e4567-e89b-12d3-a456-426614174000","alter_id":0}]}`,
		`{"outbounds":[{"type":"vmess","server":"vmess.example.com","server_port":443,"uuid":"123e4567-e89b-12d3-a456-426614174000","aid":"0"}]}`,
		`{"outbounds":[{"type":"vmess","server":"vmess.example.com","server_port":443,"uuid":"123e4567-e89b-12d3-a456-426614174000"}]}`,
	} {
		res, err := (LinkParser{}).Parse([]byte(doc))
		if err != nil {
			t.Fatalf("AEAD doc %s: Parse = %v", doc, err)
		}
		if res.Report.Imported != 1 {
			t.Fatalf("AEAD doc %s: imported %d servers, want 1", doc, res.Report.Imported)
		}
	}
	// A non-VMess JSON entry carrying an aid key is not a VMess
	// alterId and must not be refused by this check.
	if _, err := mapJSONSpec(map[string]any{
		"type": "trojan", "server": "trojan.example.com", "server_port": float64(443),
		"password": "pw", "aid": float64(64),
	}, ""); err != nil {
		t.Fatalf("non-vmess aid refused: %v", err)
	}
}
