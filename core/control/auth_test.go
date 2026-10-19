package control_test

import (
	"testing"

	"github.com/levvs-one/sora-client/core/control"
)

// TestRotatePersistsToken is the regression test for LEGACY-M4: after Rotate,
// a restart (reloading the token file) must reject the old token and accept
// the new one.
func TestRotatePersistsToken(t *testing.T) {
	dir := t.TempDir()
	auth, err := control.LoadOrCreateToken(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateToken() error = %v", err)
	}
	old := auth.Token()
	fresh, err := auth.Rotate()
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if auth.Verify(old) {
		t.Error("the old token is still valid after Rotate")
	}
	if !auth.Verify(fresh) {
		t.Error("the fresh token is not valid after Rotate")
	}
	// Simulate a restart: reload from the token file.
	reloaded, err := control.LoadOrCreateToken(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateToken() after Rotate error = %v", err)
	}
	if reloaded.Verify(old) {
		t.Error("the old token survived a restart after Rotate")
	}
	if !reloaded.Verify(fresh) {
		t.Error("the fresh token did not survive a restart after Rotate")
	}
}
