package parser

// Sora<->legacy parser parity pin (final pass 3).
//
// The link/subscription parser is a port of sora's, and until now the
// parity claim rested on the ported test files and on prose: the two
// parsers were never run over one corpus by an executable check in
// this tree. testdata/sora_parity_golden.txt closes that: it holds,
// per link, the output of SORA's parser at snapshot 18c3f551 (see the
// file's header for how it was generated), and this test requires the
// legacy parser to reproduce it exactly — same first server, same
// normalized fields, same refusal — over a corpus harvested from
// both repositories' parser, subscription and control test suites
// (share links of every protocol family, olcrtc links from the
// OpenLibre merge, subscription URLs, malformed inputs).
//
// The one deliberate divergence is encoded in the golden itself:
// sora's OutboundSpec carries a typed MLDSA65Verify (the vless pqv
// parameter, routed to Xray); legacy has no such field and keeps pqv
// as a raw entry in Options. The golden strips the sora-only field,
// and TestSoraParityGoldenPQVStaysVisible pins the legacy behavior
// for it explicitly, so the gap is a recorded decision surface, not
// a silent loss. Refreshing the golden is a deliberate act tied to
// a sora snapshot bump, exactly like the redactor snapshot in
// core/engine.

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func normalizedSpec(t *testing.T, spec OutboundSpec) string {
	t.Helper()
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		t.Fatal(err)
	}
	delete(asMap, "MLDSA65Verify") // sora-only; legacy has no such key.
	out, err := json.Marshal(asMap)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestSoraParityGolden(t *testing.T) {
	file, err := os.Open("testdata/sora_parity_golden.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	cases, refusals := 0, 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		encoded, want, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("golden line without a tab: %.40q", line)
		}
		rawLink, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("golden link does not decode: %v", err)
		}
		link := string(rawLink)
		cases++
		result, err := (LinkParser{}).Parse([]byte(link))
		if want == "ERR" {
			refusals++
			if err == nil && len(result.Servers) > 0 {
				t.Errorf("link %q: sora refuses it, legacy parsed %d servers", link, len(result.Servers))
			}
			continue
		}
		if err != nil || len(result.Servers) == 0 {
			t.Errorf("link %q: sora parses it, legacy refused (%v)", link, err)
			continue
		}
		if got := normalizedSpec(t, result.Servers[0]); got != want {
			t.Errorf("link %q: parser drift from the sora snapshot:\n got: %s\nwant: %s", link, got, want)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if cases < 100 {
		t.Fatalf("golden corpus shrank to %d cases; the pin must keep its sweep", cases)
	}
	t.Logf("sora parity golden: %d links, %d of them refusals", cases, refusals)
}

// TestSoraParityGoldenPQVStaysVisible records the legacy behavior for
// the one sora field legacy does not carry: a vless link's pqv
// parameter stays visible as a raw option (it is not promoted to a
// typed field, and no legacy engine claims MLDSA65 verification).
func TestSoraParityGoldenPQVStaysVisible(t *testing.T) {
	link := "vless://123e4567-e89b-12d3-a456-426614174000@edge.example.com:443?security=reality&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&pqv=pqv-test-key#x"
	result, err := (LinkParser{}).Parse([]byte(link))
	if err != nil || len(result.Servers) != 1 {
		t.Fatalf("pqv link: %v (%d servers)", err, len(result.Servers))
	}
	if got := result.Servers[0].Options["pqv"]; got != "pqv-test-key" {
		t.Fatalf("pqv option = %q, want it kept visible as a raw option", got)
	}
}
