package obfs

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// recordConn captures every Write as a separate chunk.
type recordConn struct {
	net.Conn
	mu     sync.Mutex
	chunks [][]byte
}

func (c *recordConn) Write(b []byte) (int, error) {
	cp := append([]byte(nil), b...)
	c.mu.Lock()
	c.chunks = append(c.chunks, cp)
	c.mu.Unlock()
	return len(b), nil
}

func (c *recordConn) writes() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.chunks...)
}

// clientHelloRecord builds a fake TLS handshake record with a payload of
// the given size.
func clientHelloRecord(payloadSize int) []byte {
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	rec := []byte{0x16, 0x03, 0x01, byte(payloadSize >> 8), byte(payloadSize)}
	return append(rec, payload...)
}

func TestWrapConnIdentityWhenDisabled(t *testing.T) {
	inner := &recordConn{}
	if got := (Profile{}).WrapConn(inner); got != net.Conn(inner) {
		t.Error("zero profile did not return the conn unchanged")
	}
	if got := (Profile{UTLS: UTLSChrome}).WrapConn(inner); got != net.Conn(inner) {
		t.Error("non-fragmenting profile did not return the conn unchanged")
	}
	if (Profile{FragSizes: []int{32}}).WrapConn(nil) != nil {
		t.Error("WrapConn(nil) did not return nil")
	}
}

func TestFragmentSplitsFirstRecord(t *testing.T) {
	inner := &recordConn{}
	conn := Profile{FragSizes: []int{10, 20}}.WrapConn(inner)
	rec := clientHelloRecord(100) // 5 header + 100 payload = 105 bytes
	if _, err := conn.Write(rec); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	chunks := inner.writes()
	wantSizes := []int{10, 20, 75}
	if len(chunks) != len(wantSizes) {
		t.Fatalf("got %d chunks, want %d", len(chunks), len(wantSizes))
	}
	for i, want := range wantSizes {
		if len(chunks[i]) != want {
			t.Errorf("chunk %d = %d bytes, want %d", i, len(chunks[i]), want)
		}
	}
	if got := bytes.Join(chunks, nil); !bytes.Equal(got, rec) {
		t.Error("reassembled chunks differ from the original record")
	}
}

func TestFragmentOnlyFirstWrite(t *testing.T) {
	inner := &recordConn{}
	conn := Profile{FragSizes: []int{10}}.WrapConn(inner)
	rec := clientHelloRecord(50)
	if _, err := conn.Write(rec); err != nil {
		t.Fatalf("first Write() = %v", err)
	}
	second := []byte{0x17, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4} // app data
	if _, err := conn.Write(second); err != nil {
		t.Fatalf("second Write() = %v", err)
	}
	chunks := inner.writes()
	if len(chunks) != 3 { // 10 + rest of first record, then second write whole
		t.Fatalf("got %d chunks, want 3", len(chunks))
	}
	if !bytes.Equal(chunks[2], second) {
		t.Error("second write was fragmented, want passthrough")
	}
}

func TestFragmentSkipsNonTLS(t *testing.T) {
	inner := &recordConn{}
	conn := Profile{FragSizes: []int{10}}.WrapConn(inner)
	plain := []byte("GET / HTTP/1.1\r\n\r\n")
	if _, err := conn.Write(plain); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	chunks := inner.writes()
	if len(chunks) != 1 || !bytes.Equal(chunks[0], plain) {
		t.Error("non-TLS bytes were not passed through untouched")
	}
}

func TestFragmentSkipsShortWrite(t *testing.T) {
	inner := &recordConn{}
	conn := Profile{FragSizes: []int{10}}.WrapConn(inner)
	short := []byte{0x16, 0x03} // too short for a record header
	if _, err := conn.Write(short); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	chunks := inner.writes()
	if len(chunks) != 1 || !bytes.Equal(chunks[0], short) {
		t.Error("short write was not passed through untouched")
	}
}

// TestFragmentAfterPlaintextPreamble simulates an HTTP CONNECT proxy:
// the plaintext proxy handshake goes out whole and must not disarm the
// one-shot — the ClientHello that follows is still fragmented.
func TestFragmentAfterPlaintextPreamble(t *testing.T) {
	inner := &recordConn{}
	conn := Profile{FragSizes: []int{10}}.WrapConn(inner)
	preamble := []byte("CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	if _, err := conn.Write(preamble); err != nil {
		t.Fatalf("preamble Write() = %v", err)
	}
	rec := clientHelloRecord(50) // 55 bytes: chunks of 10 and 45
	if _, err := conn.Write(rec); err != nil {
		t.Fatalf("record Write() = %v", err)
	}
	chunks := inner.writes()
	if len(chunks) != 3 {
		t.Fatalf("got %d chunks, want 3 (preamble + 2 fragments)", len(chunks))
	}
	if !bytes.Equal(chunks[0], preamble) {
		t.Error("proxy preamble was not passed through untouched")
	}
	if len(chunks[1]) != 10 || len(chunks[2]) != 45 {
		t.Errorf("ClientHello fragments = %d+%d bytes, want 10+45",
			len(chunks[1]), len(chunks[2]))
	}
	if got := bytes.Join(chunks[1:], nil); !bytes.Equal(got, rec) {
		t.Error("reassembled fragments differ from the original record")
	}
}

func TestFragmentPartialRecord(t *testing.T) {
	inner := &recordConn{}
	conn := Profile{FragSizes: []int{10, 20}}.WrapConn(inner)
	rec := clientHelloRecord(100)
	// Declare a longer record than the bytes present: fragment what we have.
	rec[3], rec[4] = 0x01, 0x00 // length 256, only 105 bytes present
	partial := rec[:60]
	if _, err := conn.Write(partial); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	chunks := inner.writes()
	if len(chunks) != 3 {
		t.Fatalf("got %d chunks, want 3", len(chunks))
	}
	if got := bytes.Join(chunks, nil); !bytes.Equal(got, partial) {
		t.Error("reassembled chunks differ from the partial write")
	}
}

func TestFragmentPropagatesWriteError(t *testing.T) {
	want := errors.New("boom")
	inner := &failConn{err: want}
	conn := Profile{FragSizes: []int{10}}.WrapConn(inner)
	if _, err := conn.Write(clientHelloRecord(50)); !errors.Is(err, want) {
		t.Errorf("Write() = %v, want %v", err, want)
	}
}

type failConn struct {
	net.Conn
	err error
}

func (c *failConn) Write([]byte) (int, error) { return 0, c.err }

func TestFragmentDelayIsBounded(t *testing.T) {
	inner := &recordConn{}
	// An absurd delay must be clamped, not honored.
	conn := Profile{FragSizes: []int{10}, FragDelay: time.Hour}.WrapConn(inner)
	start := time.Now()
	if _, err := conn.Write(clientHelloRecord(50)); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("fragmented write took %s, delay was not clamped", elapsed)
	}
}
