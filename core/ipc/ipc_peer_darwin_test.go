//go:build darwin

package ipc

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestPeerOfDarwin verifies LOCAL_PEERCRED wiring on real macOS hardware:
// it compiles everywhere darwin tests build, but only runs on a Mac
// (verify-on-mac checklist, macos/README.md). The peer of a socket pair
// must come back kernel-verified with this process's own UID.
func TestPeerOfDarwin(t *testing.T) {
	address := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.Listen("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- connection
		}
	}()
	client, err := net.Dial("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	server := <-accepted
	defer func() { _ = server.Close() }()
	peer := peerOf(server)
	if !peer.Verified {
		t.Fatalf("peer is not kernel-verified: %+v", peer)
	}
	if peer.UID != os.Getuid() {
		t.Fatalf("peer UID = %d, want %d", peer.UID, os.Getuid())
	}
	if peer.PID != os.Getpid() {
		t.Logf("peer PID = %d, this process is %d (LOCAL_PEERPID is informational; a mismatch is a verify-on-mac finding, not a failure)", peer.PID, os.Getpid())
	}
}
