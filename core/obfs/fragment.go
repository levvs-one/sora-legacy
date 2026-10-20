package obfs

import (
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"time"
)

// TLS record layer constants used by the SNI rewriter and the record
// parser (ported from sora's frag.go).
const (
	recordTypeHandshake  = 22
	handshakeClientHello = 1
	recordHeaderLen      = 5
)

// parseTLSRecords splits buf into individual TLS records. It returns an
// error if buf does not consist of complete, well-formed records.
func parseTLSRecords(buf []byte) ([][]byte, error) {
	var out [][]byte
	for len(buf) > 0 {
		if len(buf) < recordHeaderLen {
			return nil, errors.New("obfs: truncated TLS record header")
		}
		n := int(binary.BigEndian.Uint16(buf[3:5]))
		if recordHeaderLen+n > len(buf) {
			return nil, errors.New("obfs: truncated TLS record payload")
		}
		out = append(out, buf[:recordHeaderLen+n])
		buf = buf[recordHeaderLen+n:]
	}
	return out, nil
}

// isClientHelloRecord reports whether rec is a single TLS record whose
// first handshake message is a ClientHello.
func isClientHelloRecord(rec []byte) bool {
	return len(rec) > recordHeaderLen &&
		rec[0] == recordTypeHandshake &&
		rec[recordHeaderLen] == handshakeClientHello
}

func hasClientHello(recs [][]byte) bool {
	for _, r := range recs {
		if isClientHelloRecord(r) {
			return true
		}
	}
	return false
}

// WrapConn applies the profile's connection-level obfuscation to conn:
// ClientHello fragmentation, FakeSNI rewriting and inter-write jitter.
// It returns conn unchanged when conn is nil or the profile enables none
// of the three.
//
// The layers stack in write order: jitter sleeps first, the SNI
// rewriter transforms a complete ClientHello record, and the
// fragmenter splits the (possibly rewritten) record — so a rewritten
// hello is fragmented exactly like an original one.
//
// Only the first write that looks like a TLS handshake record (content
// type 0x16, major version 0x03) is ever fragmented. Earlier plaintext
// writes — e.g. a proxy CONNECT request — pass through untouched without
// disarming the one-shot, so the ClientHello that follows them is still
// fragmented. A connection that never carries TLS passes through with
// only a 5-byte sniff per write, so wrapping a non-TLS connection is
// harmless.
func (p Profile) WrapConn(conn net.Conn) net.Conn {
	if conn == nil || (!p.Fragmentation() && p.FakeSNI == "" && p.Jitter <= 0) {
		return conn
	}
	p = p.Clamp()
	out := conn
	if p.Fragmentation() {
		out = &fragmentConn{
			Conn:  out,
			sizes: append([]int(nil), p.FragSizes...),
			delay: p.FragDelay,
		}
	}
	if p.FakeSNI != "" {
		out = &sniConn{Conn: out, fake: p.FakeSNI}
	}
	if p.Jitter > 0 {
		out = &jitterConn{Conn: out, max: p.Jitter, rng: newJitterRand()}
	}
	return out
}

// sniConn rewrites the SNI of ClientHello records on the write path
// with the profile's FakeSNI (see RewriteClientHelloSNI). A write that
// does not parse as complete TLS records, or carries no ClientHello,
// passes through untouched — the same rule sora's wrapper applies. A
// ClientHello that parses but cannot be rewritten fails closed: the
// profile asked for a fake SNI, and sending the original would put the
// real SNI on the wire in plaintext, the exact leak the wrapper exists
// to prevent. A well-formed hello with no SNI at all passes as-is:
// there is nothing to leak and nothing to replace.
type sniConn struct {
	net.Conn
	fake string
}

func (c *sniConn) Write(p []byte) (int, error) {
	recs, err := parseTLSRecords(p)
	if err != nil || !hasClientHello(recs) {
		return c.Conn.Write(p)
	}
	out := make([]byte, 0, len(p))
	for _, rec := range recs {
		if isClientHelloRecord(rec) {
			rewritten, err := RewriteClientHelloSNI(rec, c.fake)
			if errors.Is(err, errNoServerName) {
				rewritten, err = rec, nil
			}
			if err != nil {
				return 0, errors.New("obfs: ClientHello could not be rewritten with the fake SNI; refusing to send the real SNI")
			}
			rec = rewritten
		}
		out = append(out, rec...)
	}
	if err := writeFull(c.Conn, out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// fragmentConn splits the first TLS handshake record written on the
// connection into chunks, defeating DPI that expects the whole
// ClientHello in one TCP segment. Writes before the first TLS-looking
// one pass through untouched; everything after the fragmented record
// passes through as well.
type fragmentConn struct {
	net.Conn
	sizes []int
	delay time.Duration
	done  atomic.Bool
}

func (c *fragmentConn) Write(b []byte) (int, error) {
	if c.done.Load() {
		return c.Conn.Write(b)
	}
	// Wait for the first TLS-looking write instead of blindly taking the
	// first write: a plaintext preamble (e.g. a proxy CONNECT request)
	// must not disarm the one-shot, or the ClientHello behind a proxy
	// would silently go out whole.
	if tlsRecordEnd(b) <= 0 {
		return c.Conn.Write(b)
	}
	if !c.done.CompareAndSwap(false, true) {
		return c.Conn.Write(b)
	}
	return c.writeFirst(b)
}

// writeFirst fragments the first TLS record found in b. Bytes that do
// not look like a handshake record, or a record header the write does
// not fully contain, are passed through unchanged.
func (c *fragmentConn) writeFirst(b []byte) (int, error) {
	end := tlsRecordEnd(b)
	if end <= 0 {
		return c.Conn.Write(b)
	}
	// Chunk boundaries within the first record; any trailing bytes form
	// the final chunk.
	bounds := make([]int, 0, len(c.sizes)+1)
	off := 0
	for _, size := range c.sizes {
		if off >= end {
			break
		}
		off += size
		if off > end {
			off = end
		}
		bounds = append(bounds, off)
	}
	if off < len(b) {
		bounds = append(bounds, len(b))
	}
	prev := 0
	for i, bound := range bounds {
		if err := writeFull(c.Conn, b[prev:bound]); err != nil {
			return prev, err
		}
		prev = bound
		// Pause between fragments, never after the final write.
		if i < len(bounds)-1 && c.delay > 0 {
			time.Sleep(c.delay)
		}
	}
	return len(b), nil
}

// tlsRecordEnd returns the end offset of the first TLS record in b, or
// -1 when b does not start with a complete handshake record header.
// A short record (fewer bytes than the header declares) is fragmented
// as far as the bytes go.
func tlsRecordEnd(b []byte) int {
	if len(b) < 5 {
		return -1
	}
	// Content type 16 (handshake), major version 3 (TLS 1.x).
	if b[0] != 0x16 || b[1] != 0x03 {
		return -1
	}
	length := int(b[3])<<8 | int(b[4])
	end := 5 + length
	if end > len(b) {
		end = len(b)
	}
	return end
}

func writeFull(conn net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := conn.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
