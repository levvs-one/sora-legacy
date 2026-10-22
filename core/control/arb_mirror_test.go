package control_test

// Executable port of the ARB parity pin (final pass 3).
//
// legacy/tests/Sora.ArbParity.ps1 has pinned the C# client's
// localization mirror since the uplift — the ARB key sets of all 31
// locales, the languages.json picker list, and every key the Client
// code asks Strings for — but the script is PowerShell-only and is
// not wired into any workflow in this repository, so in practice the
// mirror held only when someone on Windows ran it by hand. This test
// is the same three checks, with the same extraction shapes, in the
// test suite that already runs everywhere:
//
//  1. every locale in legacy/Client/Assets/l10n carries exactly the
//     same message keys as app_en.arb ('@' metadata entries are not
//     message keys; a metadata entry naming a key its own file does
//     not carry is a failure);
//  2. languages.json and the app_*.arb files name the same locales;
//  3. every ARB key the C# code asks Strings for exists in
//     app_en.arb, with keys extracted through the same literal
//     shapes the script scans (indexer calls, the two ternary
//     shapes, MakeButton tags, and `=> "key"` switch arms).
//
// The PowerShell script stays for Windows-side manual runs; this
// test is the pin that executes.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func arbClientDir(t *testing.T) string {
	t.Helper()
	root := mirrorRoot(t)
	dir := filepath.Join(root, "legacy", "Client")
	if _, err := os.Stat(filepath.Join(dir, "Assets", "l10n", "app_en.arb")); err != nil {
		t.Fatalf("legacy Client tree not found: %v", err)
	}
	return dir
}

func arbKeys(t *testing.T, path string) (messages, metas map[string]bool) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	messages, metas = map[string]bool{}, map[string]bool{}
	for k := range doc {
		switch {
		case strings.HasPrefix(k, "@@"):
		case strings.HasPrefix(k, "@"):
			metas[k[1:]] = true
		default:
			messages[k] = true
		}
	}
	return messages, metas
}

func TestARBMirrorLocalesLanguagesAndCodeKeys(t *testing.T) {
	client := arbClientDir(t)
	l10n := filepath.Join(client, "Assets", "l10n")
	entries, err := os.ReadDir(l10n)
	if err != nil {
		t.Fatal(err)
	}
	sets := map[string]map[string]bool{}
	var locales []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "app_") || !strings.HasSuffix(name, ".arb") {
			continue
		}
		locale := strings.TrimSuffix(strings.TrimPrefix(name, "app_"), ".arb")
		locales = append(locales, locale)
		messages, metas := arbKeys(t, filepath.Join(l10n, name))
		sets[locale] = messages
		for meta := range metas {
			if !messages[meta] {
				t.Errorf("%s: metadata @%s has no matching message key", name, meta)
			}
		}
	}
	if len(locales) < 2 {
		t.Fatalf("expected the locale ARB files, found %v", locales)
	}
	reference := sets["en"]
	if reference == nil {
		t.Fatal("app_en.arb not found")
	}
	for _, locale := range locales {
		for key := range reference {
			if !sets[locale][key] {
				t.Errorf("app_%s.arb: missing key %s", locale, key)
			}
		}
		for key := range sets[locale] {
			if !reference[key] {
				t.Errorf("app_%s.arb: extra key %s", locale, key)
			}
		}
	}

	// languages.json <-> files on disk.
	raw, err := os.ReadFile(filepath.Join(client, "Assets", "languages.json"))
	if err != nil {
		t.Fatal(err)
	}
	var languages []struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(raw, &languages); err != nil {
		t.Fatalf("languages.json: %v", err)
	}
	listed := map[string]bool{}
	for _, l := range languages {
		listed[l.Code] = true
	}
	for _, locale := range locales {
		if !listed[locale] {
			t.Errorf("app_%s.arb exists but languages.json does not list %s", locale, locale)
		}
	}
	for code := range listed {
		if sets[code] == nil {
			t.Errorf("languages.json lists %s but app_%s.arb is missing", code, code)
		}
	}

	// Keys the Client code asks Strings for — the same extraction
	// shapes as Sora.ArbParity.ps1.
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`text\["([A-Za-z][A-Za-z0-9]*)"\]`),
		regexp.MustCompile(`text\[[^\]\r\n]*\?\s*"([A-Za-z][A-Za-z0-9]*)"\s*:\s*"([A-Za-z][A-Za-z0-9]*)"\]`),
		regexp.MustCompile(`\?\s*"(state[A-Za-z][A-Za-z0-9]*)"\s*:\s*"(state[A-Za-z][A-Za-z0-9]*)"`),
		regexp.MustCompile(`MakeButton\("([A-Za-z][A-Za-z0-9]*)"`),
		regexp.MustCompile(`=>\s*"([a-z][A-Za-z0-9]*)"`),
	}
	used := map[string]bool{}
	sources, err := filepath.Glob(filepath.Join(client, "*.cs"))
	if err != nil || len(sources) == 0 {
		t.Fatalf("Client sources: %v (%d files)", err, len(sources))
	}
	for _, src := range sources {
		code, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		for _, re := range patterns {
			for _, m := range re.FindAllSubmatch(code, -1) {
				for _, g := range m[1:] {
					if len(g) > 0 {
						used[string(g)] = true
					}
				}
			}
		}
	}
	if len(used) == 0 {
		t.Fatal("no ARB keys extracted from the Client sources")
	}
	var missing []string
	for key := range used {
		if !reference[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("keys used in Client code but missing from ARB: %v", missing)
	}
	t.Logf("ARB mirror: %d locales, %d keys in app_en.arb, %d distinct keys requested from Strings", len(locales), len(reference), len(used))
}
