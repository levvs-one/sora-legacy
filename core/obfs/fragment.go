package obfs

import (
	"net"
	"sync/atomic"
	"time"
)

// WrapConn applies the profile's connection-level obfuscation to conn:
// ClientHello fragmentation. It returns conn unchanged when conn is nil
// or the profile disables fragmentation.
//
// Only the first write is ever touched, and only when it looks like a
// TLS handshake record (content type 0x16, major version 0x03). Anything
// else — plain HTTP, a proxy handshake, a short write — passes through
// untouched, so wrapping a connection that never carries TLS is harmless.
func (p Profile) WrapConn(conn net.Conn) net.Conn {
	if conn == nil || !p.Fragmentation() {
		return conn
	}
	p = p.Clamp()
	return &fragmentConn{
		Conn:  conn,
		sizes: append([]int(nil), p.FragSizes...),
		delay: p.FragDelay,
	}
}

// fragmentConn splits the first TLS record written on the connection
// into chunks, defeating DPI that expects the whole ClientHello in one
// TCP segment. Everything after the first write passes through.
type fragmentConn struct {
	net.Conn
	sizes []int
	delay time.Duration
	done  atomic.Bool
}

func (c *fragmentConn) Write(b []byte) (int, error) {
	if c.done.Swap(true) {
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
