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
//
// REVIEW-GFOLLOWUP follow-up: three more deliberate strictness
// closures on top of that — the alterId VALUE must be a non-negative
// integer (float -1/0.5 and bool true used to coerce to 0 through
// number() in JSON paths while Clash YAML refused -1, and an Xray
// profile carried such values verbatim into the runtime), the
// document TYPE match is case-insensitive ("VMess"/"VMESS" used to
// skip the alterId gate in mapJSONSpec entirely), and a URL carrying
// several alterId keys/values (?aid=0&alter_id=16) is refused when
// ANY of them is non-zero. All three are conscious divergences
// beyond sora, marked as such in parser.go.

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

// TestVMessAlterIDStrictIntegerSemantics pins REVIEW-GFOLLOWUP
// G2-F1: the alterId value must be a non-negative integer. Negative
// and fractional floats and booleans are refused (not coerced to 0
// by number(), not carried verbatim into an Xray runtime); an
// integer-valued float (64.0, the shape JSON/YAML actually emit)
// counts as the integer it denotes; null is an absent value.
func TestVMessAlterIDStrictIntegerSemantics(t *testing.T) {
	const uuid = "123e4567-e89b-12d3-a456-426614174000"
	// Direct check: AEAD values pass.
	for _, v := range []any{nil, float64(0), float64(0.0), 0, int64(0), uint64(0), "0", "0.0", ""} {
		if err := checkVMessAlterID(v); err != nil {
			t.Errorf("checkVMessAlterID(%#v) = %v, want nil", v, err)
		}
	}
	// Direct check: valid non-zero integers refuse as pre-AEAD,
	// malformed values refuse as not-a-non-negative-integer; both
	// are ErrUnsupported.
	for _, v := range []any{
		float64(64), float64(64.0), "64", "64.0", 64, int64(64),
		float64(-1), float64(-64.0), -1, "-1", float64(0.5), "0.5", true, false, "abc",
	} {
		if err := checkVMessAlterID(v); !errors.Is(err, ErrUnsupported) {
			t.Errorf("checkVMessAlterID(%#v) = %v, want ErrUnsupported", v, err)
		}
	}
	// Mapper level: the evil values refuse in the generic JSON
	// mapper under every spelling.
	for _, bad := range []any{float64(-1), float64(0.5), true, "abc"} {
		for _, k := range []string{"aid", "alter_id", "alterId"} {
			m := map[string]any{
				"type": "vmess", "server": "vmess.example.com", "server_port": float64(443),
				"uuid": uuid, k: bad,
			}
			if _, err := mapJSONSpec(m, ""); !errors.Is(err, ErrUnsupported) {
				t.Errorf("mapJSONSpec %s=%#v = %v, want ErrUnsupported", k, bad, err)
			}
		}
	}
	// Mapper level: the classic-document mapper refuses them too.
	classic := func(aidJSON string) string {
		return `{"v":"2","ps":"legacy","add":"vmess.example.com","port":"443","id":"` + uuid + `","aid":` + aidJSON + `,"net":"tcp","tls":""}`
	}
	for _, aidJSON := range []string{`-1`, `0.5`, `true`, `"abc"`, `64.0`} {
		if _, err := parseLink("vmess://" + base64.StdEncoding.EncodeToString([]byte(classic(aidJSON)))); !errors.Is(err, ErrUnsupported) {
			t.Errorf("classic aid=%s = %v, want ErrUnsupported", aidJSON, err)
		}
	}
	// null is an absent value: the classic document and a generic
	// JSON document carrying "alterId": null import as AEAD.
	for _, doc := range []string{classic(`null`)} {
		if _, err := parseLink("vmess://" + base64.StdEncoding.EncodeToString([]byte(doc))); err != nil {
			t.Errorf("classic aid=null refused: %v", err)
		}
	}
	// Full Parse: JSON documents with evil values import nothing;
	// 64.0 refuses as the integer 64; null imports.
	for _, frag := range []string{`"alterId":-1`, `"alterId":0.5`, `"alterId":true`, `"alterId":"abc"`, `"alterId":64.0`} {
		doc := `{"outbounds":[{"type":"vmess","server":"vmess.example.com","server_port":443,"uuid":"` + uuid + `",` + frag + `}]}`
		res, _ := (LinkParser{}).Parse([]byte(doc))
		if res.Report.Imported != 0 || len(res.Servers) != 0 {
			t.Fatalf("doc %s: imported %d, want 0", frag, res.Report.Imported)
		}
	}
	res, err := (LinkParser{}).Parse([]byte(`{"outbounds":[{"type":"vmess","server":"vmess.example.com","server_port":443,"uuid":"` + uuid + `","alterId":null}]}`))
	if err != nil || res.Report.Imported != 1 {
		t.Fatalf("alterId null doc: imported %d, err %v, want 1 (null = absent)", res.Report.Imported, err)
	}
	// Full Parse: Clash YAML — the same asymmetry the review found
	// (YAML -1 refused, JSON -1 accepted) is gone; YAML int, float
	// and bool spellings all refuse, YAML 0 imports.
	for _, line := range []string{"alterId: -1", "alterId: 0.5", "alterId: true"} {
		clash := "proxies:\n  - name: legacy\n    type: vmess\n    server: vmess.example.com\n    port: 443\n    uuid: " + uuid + "\n    " + line + "\n"
		res, _ := (LinkParser{}).Parse([]byte(clash))
		if res.Report.Imported != 0 || len(res.Servers) != 0 {
			t.Fatalf("clash %q: imported %d, want 0", line, res.Report.Imported)
		}
	}
	// Xray profile level: evil nested values refuse instead of
	// reaching the runtime verbatim; 64.0 refuses as 64; 0.0 and
	// null import.
	profile := func(alterID string) string {
		return `{"remarks":"profile","outbounds":[{"tag":"proxy","protocol":"vmess",` +
			`"settings":{"vnext":[{"address":"vmess.example.com","port":443,` +
			`"users":[{"id":"` + uuid + `","alterId":` + alterID + `}]}]},` +
			`"streamSettings":{"network":"tcp","security":"none"}},` +
			`{"protocol":"freedom","tag":"direct"}]}`
	}
	for _, bad := range []string{`-1`, `0.5`, `true`, `"abc"`, `64.0`} {
		var m map[string]any
		if err := json.Unmarshal([]byte(profile(bad)), &m); err != nil {
			t.Fatal(err)
		}
		if _, err := profileSpec(m); !errors.Is(err, ErrUnsupported) {
			t.Errorf("profileSpec nested alterId %s = %v, want ErrUnsupported", bad, err)
		}
		res, _ := (LinkParser{}).Parse([]byte(profile(bad)))
		if res.Report.Imported != 0 {
			t.Errorf("profile alterId %s: imported %d, want 0", bad, res.Report.Imported)
		}
	}
	for _, ok := range []string{`0.0`, `null`} {
		res, err := (LinkParser{}).Parse([]byte(profile(ok)))
		if err != nil || res.Report.Imported != 1 {
			t.Errorf("profile alterId %s: imported %d, err %v, want 1", ok, res.Report.Imported, err)
		}
	}
}

// TestVMessAlterIDTypeCaseInsensitive pins REVIEW-GFOLLOWUP G2-F2:
// the document type gate in mapJSONSpec is case-insensitive, so
// "VMess"/"VMESS" documents face the alterId check like "vmess"
// ones — and valid AEAD documents in those spellings still import.
// (mapVMessJSON has no type gate to fix: the classic mapper's
// protocol is fixed to vmess by construction.)
func TestVMessAlterIDTypeCaseInsensitive(t *testing.T) {
	const uuid = "123e4567-e89b-12d3-a456-426614174000"
	for _, typ := range []string{"VMess", "VMESS", "vMeSs"} {
		m := map[string]any{
			"type": typ, "server": "vmess.example.com", "server_port": float64(443),
			"uuid": uuid, "alterId": float64(64),
		}
		if _, err := mapJSONSpec(m, ""); !errors.Is(err, ErrUnsupported) {
			t.Errorf("mapJSONSpec type %q alterId 64 = %v, want ErrUnsupported", typ, err)
		}
	}
	for _, doc := range []string{
		`{"outbounds":[{"type":"VMess","server":"vmess.example.com","server_port":443,"uuid":"` + uuid + `","alterId":64}]}`,
		`[{"type":"VMESS","server":"vmess.example.com","server_port":443,"uuid":"` + uuid + `","alter_id":64}]`,
	} {
		res, _ := (LinkParser{}).Parse([]byte(doc))
		if res.Report.Imported != 0 || len(res.Servers) != 0 {
			t.Fatalf("doc %s: imported %d, want 0", doc, res.Report.Imported)
		}
	}
	clash := "proxies:\n  - name: legacy\n    type: VMess\n    server: vmess.example.com\n    port: 443\n    uuid: " + uuid + "\n    alterId: 64\n"
	res, _ := (LinkParser{}).Parse([]byte(clash))
	if res.Report.Imported != 0 || len(res.Servers) != 0 {
		t.Fatalf("clash type VMess alterId 64: imported %d, want 0", res.Report.Imported)
	}
	// AEAD documents in upper-case spellings still import.
	for _, doc := range []string{
		`{"outbounds":[{"type":"VMess","server":"vmess.example.com","server_port":443,"uuid":"` + uuid + `"}]}`,
		`{"outbounds":[{"type":"VMESS","server":"vmess.example.com","server_port":443,"uuid":"` + uuid + `","alterId":0}]}`,
		`{"outbounds":[{"type":"VMess","server":"vmess.example.com","server_port":443,"uuid":"` + uuid + `","aid":"0"}]}`,
	} {
		res, err := (LinkParser{}).Parse([]byte(doc))
		if err != nil || res.Report.Imported != 1 {
			t.Fatalf("AEAD doc %s: imported %d, err %v, want 1", doc, res.Report.Imported, err)
		}
	}
}

// TestVMessAlterIDURLMultipleValues pins REVIEW-GFOLLOWUP G2-F3: a
// vmess URL carrying several alterId keys — or a repeated key — is
// refused when ANY value is non-zero; getq's first-value view used
// to let ?aid=0&alter_id=16 through.
func TestVMessAlterIDURLMultipleValues(t *testing.T) {
	const uuid = "123e4567-e89b-12d3-a456-426614174000"
	for _, link := range []string{
		"vmess://" + uuid + "@vmess.example.com:443?aid=0&alter_id=16#x",
		"vmess://" + uuid + "@vmess.example.com:443?aid=0&alterId=16#x",
		"vmess://" + uuid + "@vmess.example.com:443?alterId=0&aid=16#x",
		"vmess://" + uuid + "@vmess.example.com:443?alter_id=0&alter_id=64#x",
		"vmess://" + uuid + "@vmess.example.com:443?aid=0&aid=16#x",
	} {
		if _, err := parseLink(link); !errors.Is(err, ErrUnsupported) {
			t.Errorf("url %q = %v, want ErrUnsupported", link, err)
		}
	}
	for _, link := range []string{
		"vmess://" + uuid + "@vmess.example.com:443?aid=0&alter_id=0#x",
		"vmess://" + uuid + "@vmess.example.com:443?aid=0&aid=0#x",
		"vmess://" + uuid + "@vmess.example.com:443?alterId=0&alter_id=0&aid=0#x",
	} {
		if _, err := parseLink(link); err != nil {
			t.Errorf("AEAD url %q refused: %v", link, err)
		}
	}
}
