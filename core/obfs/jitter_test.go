package obfs

import (
	"net"
	"testing"
	"time"
)

func TestJitterDelayBounds(t *testing.T) {
	rng := newJitterRand()
	const limit = 50 * time.Millisecond
	for i := 0; i < 2000; i++ {
		d := jitterDelay(rng, limit)
		if d < 0 || d > limit {
			t.Fatalf("jitterDelay = %s, out of [0, %s]", d, limit)
		}
	}
	if d := jitterDelay(rng, 0); d != 0 {
		t.Fatalf("jitterDelay(0) = %s, want 0", d)
	}
	if d := jitterDelay(rng, -time.Second); d != 0 {
		t.Fatalf("jitterDelay(negative) = %s, want 0", d)
	}
}

func TestJitterConnPassthrough(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	wrapped := &jitterConn{Conn: client, max: 0, rng: newJitterRand()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 5)
		n, err := server.Read(buf)
		if err != nil || n != 5 || string(buf) != "hello" {
			t.Errorf("read = %q, %v", buf[:n], err)
		}
	}()
	if n, err := wrapped.Write([]byte("hello")); err != nil || n != 5 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	<-done
}

func TestJitterConnDelay(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	const limit = 30 * time.Millisecond
	wrapped := &jitterConn{Conn: client, max: limit, rng: newJitterRand()}
	go func() {
		_, _ = server.Read(make([]byte, 1))
		_ = server.Close()
	}()
	start := time.Now()
	if _, err := wrapped.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 10*limit {
		t.Fatalf("jittered write took %s, want <= %s", elapsed, 10*limit)
	}
}
