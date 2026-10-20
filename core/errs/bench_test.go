package errs

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
)

// BenchmarkFrom measures classification of typical dial-path errors, as
// encountered when every server of a session fails to connect.
func BenchmarkFrom(b *testing.B) {
	benches := map[string]error{
		"connection-refused": &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED},
		"network-timeout":    &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ETIMEDOUT},
		"deadline":           context.DeadlineExceeded,
		"dns-failure":        &net.DNSError{Err: "no such host", IsNotFound: true},
		"unexpected-eof":     io.ErrUnexpectedEOF,
		"plain":              errors.New("boom"),
	}
	b.ReportAllocs()
	for name, err := range benches {
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if From(err) == nil {
					b.Fatal("nil classification")
				}
			}
		})
	}
}
