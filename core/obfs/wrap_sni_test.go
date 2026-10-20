package obfs

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// W4 wiring on legacy's write path: WrapConn with a FakeSNI profile
// rewrites the ClientHello before the fragmenter splits it, so the
// reassembled bytes carry the decoy name; non-TLS writes pass through.

type collectConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *collectConn) Write(p []byte) (int, error) { return c.buf.Write(p) }

func TestWrapConnRewritesSNI(t *testing.T) {
	sink := &collectConn{}
	conn := Profile{FakeSNI: "decoy.test"}.WrapConn(sink)
	rec := testClientHelloRecord(t, "example.com", true)
	if n, err := conn.Write(rec); err != nil || n != len(rec) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if got := testRecordSNI(t, sink.buf.Bytes()); got != "decoy.test" {
		t.Fatalf("SNI on the wire = %q, want decoy.test", got)
	}
}

func TestWrapConnRewritesThenFragments(t *testing.T) {
	sink := &collectConn{}
	conn := Profile{FakeSNI: "decoy.test", FragSizes: []int{10, 20}}.WrapConn(sink)
	rec := testClientHelloRecord(t, "example.com", false)
	if _, err := conn.Write(rec); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// The fragmenter splits the raw record bytes; concatenated, they
	// are the rewritten record with the decoy SNI.
	want, err := RewriteClientHelloSNI(rec, "decoy.test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sink.buf.Bytes(), want) {
		t.Fatal("fragmented wire bytes are not the rewritten record")
	}
}

func TestWrapConnNoSNIPassesThrough(t *testing.T) {
	sink := &collectConn{}
	conn := Profile{FakeSNI: "decoy.test"}.WrapConn(sink)
	rec := testClientHelloRecordNoSNI(t)
	if _, err := conn.Write(rec); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !bytes.Equal(sink.buf.Bytes(), rec) {
		t.Fatal("a hello without SNI must pass through unchanged")
	}
}

func TestWrapConnFailsClosedOnUnrewritableHello(t *testing.T) {
	sink := &collectConn{}
	conn := Profile{FakeSNI: "decoy.test"}.WrapConn(sink)
	// A record that parses as a ClientHello but is truncated inside
	// the extensions cannot be rewritten: nothing may reach the wire.
	rec := testClientHelloRecord(t, "example.com", false)
	broken := append([]byte(nil), rec[:len(rec)-2]...)
	// Keep the record length prefix consistent so the record parses,
	// but cut the SNI name short inside the extension data.
	broken[3] = byte((len(broken) - recordHeaderLen) >> 8)
	broken[4] = byte(len(broken) - recordHeaderLen)
	if _, err := conn.Write(broken); err == nil {
		t.Fatal("Write of an unrewritable hello must fail closed")
	} else if errors.Is(err, nil) {
		t.Fatal("unreachable")
	}
	if sink.buf.Len() != 0 {
		t.Fatalf("%d bytes leaked to the wire", sink.buf.Len())
	}
}

func TestWrapConnJitterOnlyWraps(t *testing.T) {
	sink := &collectConn{}
	conn := Profile{Jitter: time.Millisecond}.WrapConn(sink)
	if conn == net.Conn(sink) {
		t.Fatal("a jitter-only profile must wrap the connection")
	}
	if _, err := conn.Write([]byte("plain")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if sink.buf.String() != "plain" {
		t.Fatalf("wire = %q", sink.buf.String())
	}
}

func TestProfileValidatesFakeSNIAndJitter(t *testing.T) {
	if err := (Profile{FakeSNI: "decoy.test", Jitter: time.Second}).Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for _, p := range []Profile{
		{FakeSNI: "-bad.example"},
		{FakeSNI: "203.0.113.7"},
		{Jitter: -time.Second},
	} {
		if err := p.Validate(); err == nil {
			t.Fatalf("Validate(%+v) = nil, want error", p)
		}
	}
	if got := (Profile{Jitter: time.Hour}).Clamp().Jitter; got != MaxJitter {
		t.Fatalf("Clamp jitter = %s, want %s", got, MaxJitter)
	}
}
