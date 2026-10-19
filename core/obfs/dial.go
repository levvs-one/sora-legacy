package obfs

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"
)

// Dialer opens TLS connections with the profile's obfuscation applied:
// ClientHello fragmentation at the TCP layer and, when the profile
// selects one, a uTLS ClientHello fingerprint.
//
// Use Dialer for TLS connections the core dials directly. It must not
// back net/http.Transport: the transport owns the TLS handshake and
// cannot drive a uTLS connection (see the package doc).
type Dialer struct {
	// Profile selects the obfuscation. It is clamped and validated on
	// every dial; an invalid profile fails the dial.
	Profile Profile

	// RawDial opens the underlying TCP connection. Required.
	RawDial func(ctx context.Context, network, address string) (net.Conn, error)

	// Timeout bounds the TLS handshake. Zero means no extra bound beyond
	// the context's own deadline.
	Timeout time.Duration
}

// DialTLS dials network/address, wraps the connection in the profile's
// fragmentation, and completes the TLS handshake for serverName.
//
// The returned connection is a *tls.Conn when the profile disables uTLS
// and a *utls.UConn otherwise; both are handshaked before return. The
// caller owns closing it.
func (d *Dialer) DialTLS(ctx context.Context, network, address, serverName string, base *tls.Config) (net.Conn, error) {
	if d.RawDial == nil {
		return nil, errors.New("obfs: Dialer.RawDial is nil")
	}
	p := d.Profile.Clamp()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if serverName == "" {
		return nil, errors.New("obfs: Dialer.DialTLS requires a server name")
	}
	if d.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.Timeout)
		defer cancel()
	}
	raw, err := d.RawDial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	conn := p.WrapConn(raw)
	cfg := &tls.Config{}
	if base != nil {
		cfg = base.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = serverName
	}
	if !p.UTLSEnabled() {
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tc, nil
	}
	uc, err := p.NewUTLSConn(conn, p.UTLSConfig(cfg))
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := uc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return uc, nil
}
