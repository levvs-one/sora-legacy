package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyKeepsOrdinaryProfileSeparate(t *testing.T) {
	t.Setenv("SORA_DATA_DIR", filepath.Join(t.TempDir(), "ordinary"))
	t.Setenv("SORA_LEGACY_DATA_DIR", "")
	config, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if got, fromEnv := defaultDataDir(); got != filepath.Join(config, "sora-legacy", "core") || fromEnv {
		t.Fatalf("legacy profile = %s (fromEnv=%v), want %s", got, fromEnv, filepath.Join(config, "sora-legacy", "core"))
	}
	legacy := filepath.Join(t.TempDir(), "legacy")
	t.Setenv("SORA_LEGACY_DATA_DIR", legacy)
	if got, fromEnv := defaultDataDir(); got != legacy || !fromEnv {
		t.Fatalf("explicit legacy profile = %s (fromEnv=%v), want %s", got, fromEnv, legacy)
	}
}
