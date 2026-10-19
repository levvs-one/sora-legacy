package obfs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestUTLSConfigCopiesEndpointFields(t *testing.T) {
	cert := testCertificate(t)
	base := &tls.Config{
		ServerName:             "example.com",
		InsecureSkipVerify:     true,
		NextProtos:             []string{"h2", "http/1.1"},
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{cert},
		SessionTicketsDisabled: true,
	}
	cfg := Profile{UTLS: UTLSChrome}.UTLSConfig(base)
	if cfg == nil {
		t.Fatal("UTLSConfig() = nil for enabled profile")
	}
	if cfg.ServerName != "example.com" || !cfg.InsecureSkipVerify {
		t.Error("UTLSConfig did not copy ServerName/InsecureSkipVerify")
	}
	if len(cfg.NextProtos) != 2 || cfg.MinVersion != tls.VersionTLS12 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Error("UTLSConfig did not copy NextProtos/versions")
	}
	if len(cfg.Certificates) != 1 || cfg.Certificates[0].Leaf != cert.Leaf {
		t.Error("UTLSConfig did not convert Certificates")
	}
	if !cfg.SessionTicketsDisabled {
		t.Error("UTLSConfig did not copy SessionTicketsDisabled")
	}
}

func TestUTLSConfigDisabledAndNil(t *testing.T) {
	if cfg := (Profile{}).UTLSConfig(&tls.Config{ServerName: "x"}); cfg != nil {
		t.Error("UTLSConfig() != nil for disabled profile")
	}
	if cfg := (Profile{UTLS: UTLSFirefox}).UTLSConfig(nil); cfg == nil {
		t.Error("UTLSConfig(nil) = nil for enabled profile")
	}
}

func TestNewUTLSConnRejectsBadInput(t *testing.T) {
	if _, err := (Profile{}).NewUTLSConn(nil, nil); !errors.Is(err, ErrUTLSDisabled) {
		t.Errorf("NewUTLSConn disabled = %v, want ErrUTLSDisabled", err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer conn.Close()
	if _, err := (Profile{UTLS: UTLSChrome}).NewUTLSConn(nil, nil); err == nil {
		t.Error("NewUTLSConn(nil conn) = nil, want error")
	}
}

func TestDialerRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	d := &Dialer{}
	if _, err := d.DialTLS(ctx, "tcp", "127.0.0.1:1", "example.com", nil); err == nil {
		t.Error("nil RawDial accepted")
	}
	d.RawDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return net.Dial("tcp", address)
	}
	d.Profile = Profile{FragSizes: []int{}}
	if _, err := d.DialTLS(ctx, "tcp", "127.0.0.1:1", "example.com", nil); err == nil {
		t.Error("invalid profile accepted")
	}
	d.Profile = Profile{}
	if _, err := d.DialTLS(ctx, "tcp", "127.0.0.1:1", "", nil); err == nil {
		t.Error("empty server name accepted")
	}
}

// TestDialerHandshake runs real handshakes against a local TLS server:
// once with a uTLS fingerprint plus fragmentation, once with plain
// stdlib TLS. Both must complete and carry data.
func TestDialerHandshake(t *testing.T) {
	for name, profile := range map[string]Profile{
		"utls+fragment": PresetBalanced,
		"stdlib":        {},
	} {
		t.Run(name, func(t *testing.T) {
			cert := testCertificate(t)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Skipf("no loopback: %v", err)
			}
			defer ln.Close()
			serverErr := make(chan error, 1)
			go func() {
				raw, err := ln.Accept()
				if err != nil {
					serverErr <- err
					return
				}
				defer raw.Close()
				srv := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}})
				defer srv.Close()
				if err := srv.Handshake(); err != nil {
					serverErr <- err
					return
				}
				buf := make([]byte, 4)
				if _, err := readFull(srv, buf); err != nil {
					serverErr <- err
					return
				}
				_, err = srv.Write(buf)
				serverErr <- err
			}()
			d := &Dialer{
				Profile: profile,
				RawDial: func(ctx context.Context, network, address string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, address)
				},
				Timeout: 10 * time.Second,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, err := d.DialTLS(ctx, "tcp", ln.Addr().String(), "example.com",
				&tls.Config{InsecureSkipVerify: true})
			if err != nil {
				t.Fatalf("DialTLS() = %v", err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatalf("Write() = %v", err)
			}
			buf := make([]byte, 4)
			if _, err := readFull(conn, buf); err != nil {
				t.Fatalf("Read() = %v", err)
			}
			if string(buf) != "ping" {
				t.Fatalf("echo = %q, want %q", buf, "ping")
			}
			if err := <-serverErr; err != nil {
				t.Fatalf("server side: %v", err)
			}
		})
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}
}
