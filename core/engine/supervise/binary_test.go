package supervise_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/supervise"
)

// fakeEngine writes an executable that answers the version probe.
func fakeEngine(t *testing.T, dir string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake engine is a shell script")
	}
	path := filepath.Join(dir, "sing-box")
	script := "#!/bin/sh\necho 'sing-box version 1.2.3'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func testProber(allowUnverified bool) supervise.Prober {
	return supervise.Prober{
		Kind:            engine.KindSingBox,
		Name:            "sing-box",
		Args:            []string{"version"},
		Pattern:         regexp.MustCompile(`^sing-box version (\d+\.\d+\.\d+)$`),
		AllowUnverified: allowUnverified,
	}
}

// F-04: a missing digest manifest must fail discovery closed. Before the
// fix, LoadDigests' error was swallowed and the engine ran unverified —
// deleting SHA256SUMS was enough to run an arbitrary binary.
func TestDiscoverWithoutManifestFailsClosed(t *testing.T) {
	dir := t.TempDir()
	fakeEngine(t, dir)
	if _, err := testProber(false).Discover(context.Background(), dir); err == nil {
		t.Fatal("Discover() succeeded without a manifest; want fail-closed error")
	}
}

func TestDiscoverWithoutManifestAllowedWhenOperatorOptsOut(t *testing.T) {
	dir := t.TempDir()
	fakeEngine(t, dir)
	if _, err := testProber(true).Discover(context.Background(), dir); err != nil {
		t.Fatalf("Discover() with AllowUnverified error = %v", err)
	}
}

func TestDiscoverWithManifestVerifies(t *testing.T) {
	dir := t.TempDir()
	path := fakeEngine(t, dir)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	manifest := hex.EncodeToString(sum[:]) + "  sing-box\n"
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := testProber(false).Discover(context.Background(), dir); err != nil {
		t.Fatalf("Discover() with a valid manifest error = %v", err)
	}
}

func TestDiscoverWithMalformedManifestFailsClosed(t *testing.T) {
	dir := t.TempDir()
	fakeEngine(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte("not a digest\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := testProber(false).Discover(context.Background(), dir); err == nil {
		t.Fatal("Discover() succeeded with a malformed manifest; want fail-closed error")
	}
}
