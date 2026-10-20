package parser

import (
	"encoding/base64"
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
//
// REVIEW-G follow-up: two residual accept paths the reference still
// has — the camelCase alterId key in JSON/Clash documents and
// alter_id in the URL query — are closed here on purpose; legacy is
// stricter than sora in exactly these spots (plus the nested
// users[].alterId of full Xray profiles, which legacy imports through
// profileSpec and sora also still accepts). The AEAD pins below keep
// the stricter spellings from refusing alterId 0.

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

// TestVMessAlterIDCamelCaseAndSnakePaths pins the REVIEW-G G2
// follow-up closures: the camelCase alterId key in JSON/Clash/classic
// documents and alter_id in the URL query are refused exactly like
// aid/alter_id in JSON were, and zero in those spellings stays AEAD.
func TestVMessAlterIDCamelCaseAndSnakePaths(t *testing.T) {
	const uuid = "123e4567-e89b-12d3-a456-426614174000"
	// camelCase in the generic JSON mapper (number and string forms).
	for _, m := range []map[string]any{
		{"type": "vmess", "server": "vmess.example.com", "server_port": float64(443), "uuid": uuid, "alterId": float64(64)},
		{"type": "vmess", "server": "vmess.example.com", "server_port": float64(443), "uuid": uuid, "alterId": "64"},
	} {
		if _, err := mapJSONSpec(m, ""); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("mapJSONSpec alterId %v = %v, want ErrUnsupported", m["alterId"], err)
		}
	}
	// camelCase through full Parse: sing-box document and bare list.
	for _, doc := range []string{
		`{"outbounds":[{"type":"vmess","server":"vmess.example.com","server_port":443,"uuid":"` + uuid + `","alterId":64}]}`,
		`[{"type":"vmess","server":"vmess.example.com","server_port":443,"uuid":"` + uuid + `","alterId":64}]`,
	} {
		res, _ := (LinkParser{}).Parse([]byte(doc))
		if res.Report.Imported != 0 || len(res.Servers) != 0 {
			t.Fatalf("doc %s: imported %d, want 0", doc, res.Report.Imported)
		}
	}
	// camelCase in a Clash YAML proxy (the spelling Clash natively
	// emits) through full Parse.
	clash := "proxies:\n  - name: legacy\n    type: vmess\n    server: vmess.example.com\n    port: 443\n    uuid: " + uuid + "\n    alterId: 64\n"
	res, _ := (LinkParser{}).Parse([]byte(clash))
	if res.Report.Imported != 0 || len(res.Servers) != 0 {
		t.Fatalf("clash alterId: imported %d, want 0 (report %+v)", res.Report.Imported, res.Report)
	}
	// alter_id (and the new spellings) in the URL query form.
	for _, link := range []string{
		"vmess://" + uuid + "@vmess.example.com:443?alter_id=16#x",
		"vmess://" + uuid + "@vmess.example.com:443?alterId=16#x",
	} {
		if _, err := parseLink(link); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("url %q = %v, want ErrUnsupported", link, err)
		}
	}
	// camelCase in a classic vmess:// document (mapVMessJSON path).
	classic := `{"v":"2","ps":"legacy","add":"vmess.example.com","port":"443","id":"` + uuid + `","alterId":"64","net":"tcp","tls":""}`
	if _, err := parseLink("vmess://" + base64.StdEncoding.EncodeToString([]byte(classic))); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("classic alterId = %v, want ErrUnsupported", err)
	}
	// Zero in the new spellings is still AEAD and imports everywhere.
	for _, link := range []string{
		"vmess://" + uuid + "@vmess.example.com:443?alter_id=0#x",
		"vmess://" + uuid + "@vmess.example.com:443?alterId=0#x",
	} {
		if _, err := parseLink(link); err != nil {
			t.Fatalf("AEAD url %q refused: %v", link, err)
		}
	}
	for _, doc := range []string{
		`{"outbounds":[{"type":"vmess","server":"vmess.example.com","server_port":443,"uuid":"` + uuid + `","alterId":0}]}`,
		`{"outbounds":[{"type":"vmess","server":"vmess.example.com","server_port":443,"uuid":"` + uuid + `","alter_id":"0"}]}`,
	} {
		res, err := (LinkParser{}).Parse([]byte(doc))
		if err != nil || res.Report.Imported != 1 {
			t.Fatalf("AEAD doc %s: imported %d, err %v, want 1", doc, res.Report.Imported, err)
		}
	}
}

// TestXrayProfileNestedVMessAlterIDRefused pins the third REVIEW-G
// path on the legacy side: legacy DOES import full Xray
// configurations (profileSpec → xray-profile, rendered as written), so
// a VMess user with a non-zero alterId nested in one is refused with
// the same check instead of running verbatim as pre-AEAD.
func TestXrayProfileNestedVMessAlterIDRefused(t *testing.T) {
	const uuid = "123e4567-e89b-12d3-a456-426614174000"
	config := func(alterID string) string {
		return `{"remarks":"profile","outbounds":[{"tag":"proxy","protocol":"vmess",` +
			`"settings":{"vnext":[{"address":"vmess.example.com","port":443,` +
			`"users":[{"id":"` + uuid + `","alterId":` + alterID + `}]}]},` +
			`"streamSettings":{"network":"tcp","security":"none"}},` +
			`{"protocol":"freedom","tag":"direct"}]}`
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(config("64")), &m); err != nil {
		t.Fatal(err)
	}
	if _, err := profileSpec(m); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("profileSpec nested alterId 64 = %v, want ErrUnsupported", err)
	}
	if err := checkProfileVMessAlterID(m); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("checkProfileVMessAlterID = %v, want ErrUnsupported", err)
	}
	res, _ := (LinkParser{}).Parse([]byte(config("64")))
	if res.Report.Imported != 0 || len(res.Servers) != 0 {
		t.Fatalf("profile with nested alterId 64: imported %d, want 0", res.Report.Imported)
	}
	// String spelling of the nested value is refused too.
	if err := json.Unmarshal([]byte(config(`"64"`)), &m); err != nil {
		t.Fatal(err)
	}
	if _, err := profileSpec(m); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("profileSpec nested alterId \"64\" = %v, want ErrUnsupported", err)
	}
	// AEAD (0 / absent) profiles still import as xray-profile, and a
	// non-VMess profile is untouched by the scan.
	absent := `{"remarks":"profile","outbounds":[{"tag":"proxy","protocol":"vmess",` +
		`"settings":{"vnext":[{"address":"vmess.example.com","port":443,` +
		`"users":[{"id":"` + uuid + `"}]}]},` +
		`"streamSettings":{"network":"tcp","security":"none"}},` +
		`{"protocol":"freedom","tag":"direct"}]}`
	for _, doc := range []string{config("0"), absent} {
		res, err := (LinkParser{}).Parse([]byte(doc))
		if err != nil || res.Report.Imported != 1 || len(res.Servers) != 1 || res.Servers[0].Protocol != "xray-profile" {
			t.Fatalf("AEAD profile %s: imported %d, err %v, want 1 xray-profile", doc, res.Report.Imported, err)
		}
	}
}
