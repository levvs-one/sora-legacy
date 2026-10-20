package engine

import (
	"strings"
	"testing"
)

// The decoder tests are ported from sora's echconfig_test.go
// (S5-SP5). The fixture is one ECHConfig with public_name
// "public.example.com", config_id 7, X25519. The canonical-PEM and
// base64 render tests are not ported: legacy ports only the decoder
// (see echconfig.go), so there is no render spelling to pin yet.

var testECHListLines = strings.Split(testECHListPEM, "\n")

const testECHListPEM = `-----BEGIN ECH CONFIGS-----
AEX+DQBBBwAgACAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHwAEAAEAAQAScHVibGlj
LmV4YW1wbGUuY29tAAA=
-----END ECH CONFIGS-----`

func TestECHConfigListBytesShapes(t *testing.T) {
	// The canonical label, the historical label, bare base64 and a
	// list split across lines all decode to the same bytes.
	want, err := ECHConfigListBytes(testECHListLines)
	if err != nil || len(want) == 0 {
		t.Fatalf("canonical PEM must decode, got %v (%d bytes)", err, len(want))
	}
	historical := strings.ReplaceAll(testECHListPEM, "ECH CONFIGS", "ECHCONFIG")
	if got, err := ECHConfigListBytes(strings.Split(historical, "\n")); err != nil || string(got) != string(want) {
		t.Errorf("historical label = %v / %x, want the same bytes", err, got)
	}
	joined := strings.Join(strings.Split(testECHListPEM, "\n")[1:3], "")
	if got, err := ECHConfigListBytes([]string{joined}); err != nil || string(got) != string(want) {
		t.Errorf("bare base64 = %v / %x, want the same bytes", err, got)
	}
	// No lines at all is "no pin", not an error: callers gate on
	// len(Config) before decoding.
	if got, err := ECHConfigListBytes(nil); err != nil || len(got) != 0 {
		t.Errorf("empty input = %v / %d bytes, want no error and no bytes", err, len(got))
	}
}

func TestECHConfigListBytesRejects(t *testing.T) {
	two := append(append([]string{}, testECHListLines...), testECHListLines...)
	for name, lines := range map[string][]string{
		"armor only":   {"-----BEGIN ECH CONFIGS-----", "-----END ECH CONFIGS-----"},
		"not base64":   {"!!! not a config !!!"},
		"two blocks":   two,
		"begin no end": {"-----BEGIN ECH CONFIGS-----", "QUJD"},
		"end no begin": {"QUJD", "-----END ECH CONFIGS-----"},
	} {
		if _, err := ECHConfigListBytes(lines); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}
