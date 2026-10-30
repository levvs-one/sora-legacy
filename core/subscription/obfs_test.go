package subscription

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/levvs-one/sora-client/core/obfs"
)

// helloRecord builds a fake TLS handshake record for fragmentation tests.
func helloRecord(payloadSize int) []byte {
	rec := []byte{0x16, 0x03, 0x01, byte(payloadSize >> 8), byte(payloadSize)}
	return append(rec, make([]byte, payloadSize)...)
}

// dialLocal dials a loopback listener through the fetcher's default
// transport DialContext, allowing private destinations.
func dialLocal(t *testing.T, f *Fetcher, ln net.Listener) (client, server net.Conn) {
	t.Helper()
	tr, ok := f.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("default transport is %T, want *http.Transport", f.client.Transport)
	}
	ctx := context.WithValue(context.Background(), privateKey{}, true)
	cc, err := tr.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext() = %v", err)
	}
	sc, err := ln.Accept()
	if err != nil {
		_ = cc.Close()
		t.Fatalf("Accept() = %v", err)
	}
	return cc, sc
}

func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// TestObfsFragmentsClientHello dials through the default transport with
// an obfuscation profile and verifies the ClientHello arrives in delayed
// fragments: the bytes after the first chunk must not arrive before the
// configured fragment delay.
func TestObfsFragmentsClientHello(t *testing.T) {
	profile := obfs.Profile{FragSizes: []int{10}, FragDelay: 300 * time.Millisecond}
	f := New(Options{Obfs: &profile})
	ln := listenLocal(t)
	cc, sc := dialLocal(t, f, ln)
	defer func() { _ = cc.Close() }()
	defer func() { _ = sc.Close() }()

	rec := helloRecord(50) // 55 bytes: chunks of 10 and 45
	go func() { _, _ = cc.Write(rec) }()

	if err := sc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() = %v", err)
	}
	first := make([]byte, 10)
	if _, err := io.ReadFull(sc, first); err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	// The second fragment is delayed: a short read must time out.
	if err := sc.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() = %v", err)
	}
	var one [1]byte
	if _, err := io.ReadFull(sc, one[:]); !os.IsTimeout(err) {
		t.Fatalf("second fragment arrived without delay (err=%v): not fragmented", err)
	}
	// ...but it does arrive after the delay, intact.
	if err := sc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() = %v", err)
	}
	rest := make([]byte, len(rec)-10)
	if _, err := io.ReadFull(sc, rest); err != nil {
		t.Fatalf("second fragment: %v", err)
	}
	got := append(first, rest...)
	for i := range got {
		if got[i] != rec[i] {
			t.Fatal("reassembled fragments differ from the original record")
		}
	}
}

// TestObfsDisabledByDefault verifies the historical behavior is kept
// when no profile is configured: the ClientHello goes out in one write.
func TestObfsDisabledByDefault(t *testing.T) {
	f := New(Options{})
	ln := listenLocal(t)
	cc, sc := dialLocal(t, f, ln)
	defer func() { _ = cc.Close() }()
	defer func() { _ = sc.Close() }()

	rec := helloRecord(50)
	go func() { _, _ = cc.Write(rec) }()
	if err := sc.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() = %v", err)
	}
	got := make([]byte, len(rec))
	if _, err := io.ReadFull(sc, got); err != nil {
		t.Fatalf("ReadFull() = %v: without a profile the record must arrive promptly", err)
	}
}

// TestObfsInvalidProfileIgnored verifies an invalid profile does not
// change dialing behavior.
func TestObfsInvalidProfileIgnored(t *testing.T) {
	f := New(Options{Obfs: &obfs.Profile{FragSizes: []int{}}})
	ln := listenLocal(t)
	cc, sc := dialLocal(t, f, ln)
	defer func() { _ = cc.Close() }()
	defer func() { _ = sc.Close() }()

	rec := helloRecord(50)
	go func() { _, _ = cc.Write(rec) }()
	if err := sc.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() = %v", err)
	}
	got := make([]byte, len(rec))
	if _, err := io.ReadFull(sc, got); err != nil {
		t.Fatalf("ReadFull() = %v: invalid profile must be ignored", err)
	}
}
