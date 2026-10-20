package engine

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// TestRedactorEncodedSeedForms pins the seeded path (AUDIT-PARITY G3,
// ported from sora's CENSOR-LEAK corpus): a registered secret must be
// masked in every re-encoding a log pipeline produces, not only raw.
func TestRedactorEncodedSeedForms(t *testing.T) {
	secret := "p@ss word/1234+&"
	r := NewRedactor(secret)
	forms := map[string]string{
		"raw":            secret,
		"query escape":   url.QueryEscape(secret),
		"path escape":    url.PathEscape(secret),
		"base64 std":     base64.StdEncoding.EncodeToString([]byte(secret)),
		"base64 raw std": base64.RawStdEncoding.EncodeToString([]byte(secret)),
		"base64 url":     base64.URLEncoding.EncodeToString([]byte(secret)),
		"base64 raw url": base64.RawURLEncoding.EncodeToString([]byte(secret)),
		"hex":            hex.EncodeToString([]byte(secret)),
	}
	if m, err := json.Marshal(secret); err == nil {
		forms["json escaped"] = string(m[1 : len(m)-1])
	}
	// Lowercase percent-hex is a distinct string from QueryEscape's
	// uppercase form; build it from a secret whose escape uses A-F.
	lf := NewRedactor("aa/bb")
	if got := lf.String("x aa%2fbb y"); strings.Contains(got, "%2f") {
		t.Errorf("lowercase percent form leaked: %q", got)
	}
	for name, form := range forms {
		out := r.String("dial failed: " + form + " end")
		if strings.Contains(out, form) {
			t.Errorf("%s form of a seed leaked:\nform: %q\n out: %q", name, form, out)
		}
		if !strings.Contains(out, "[masked]") {
			t.Errorf("%s form masked nothing: %q", name, out)
		}
	}
}
