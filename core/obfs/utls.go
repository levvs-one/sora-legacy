package obfs

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

// ErrUTLSDisabled is returned when a uTLS operation is requested on a
// profile that selects no fingerprint ("none" or empty).
var ErrUTLSDisabled = errors.New("obfs: uTLS fingerprint disabled in profile")

// FingerprintID maps a profile fingerprint name to the uTLS
// ClientHelloID used for the handshake. It returns ErrUTLSDisabled for
// "none"/"" and an error for unknown names.
func (p Profile) FingerprintID() (utls.ClientHelloID, error) {
	switch normalizeUTLS(p.UTLS) {
	case UTLSChrome:
		return utls.HelloChrome_Auto, nil
	case UTLSFirefox:
		return utls.HelloFirefox_Auto, nil
	case UTLSSafari:
		return utls.HelloSafari_Auto, nil
	case UTLSRandomized:
		return utls.HelloRandomizedALPN, nil
	case "", UTLSNone:
		return utls.ClientHelloID{}, ErrUTLSDisabled
	default:
		return utls.ClientHelloID{}, fmt.Errorf("obfs: unknown UTLS fingerprint %q", p.UTLS)
	}
}

// UTLSConfig converts a crypto/tls Config into its uTLS equivalent,
// copying the fields that describe the endpoint rather than the
// fingerprint (the fingerprint comes from FingerprintID). It returns nil
// when the profile disables uTLS.
//
// Fingerprint precedence: when the handshake runs, uTLS applies the
// fingerprint's own version range and cipher suites over the config
// (ApplyPreset overwrites MinVersion/MaxVersion), so base MinVersion,
// MaxVersion and CipherSuites are advisory — a chrome fingerprint
// advertises chrome's ranges even if base pins TLS 1.3. CipherSuites are
// therefore not copied at all.
//
// Not carried over (uTLS defines its own callback/chain types, so these
// would need adapters): GetCertificate, GetClientCertificate,
// VerifyPeerCertificate, VerifyConnection and Renegotiation. Callers
// relying on client-certificate selection or custom verification must
// not use the uTLS path until adapters exist.
//
// The caller must ensure base is non-nil; a nil base yields a config with
// only the defaults.
func (p Profile) UTLSConfig(base *tls.Config) *utls.Config {
	if !p.UTLSEnabled() {
		return nil
	}
	out := &utls.Config{}
	if base == nil {
		return out
	}
	out.ServerName = base.ServerName
	out.InsecureSkipVerify = base.InsecureSkipVerify
	out.RootCAs = base.RootCAs
	out.ClientCAs = base.ClientCAs
	out.Certificates = convertCertificates(base.Certificates)
	out.NextProtos = base.NextProtos
	out.MinVersion = base.MinVersion
	out.MaxVersion = base.MaxVersion
	out.SessionTicketsDisabled = base.SessionTicketsDisabled
	// ClientSessionCache is intentionally not copied: crypto/tls and uTLS
	// session states are different types, so resumption cannot cross the
	// boundary. Fresh handshakes also avoid leaking session tickets
	// across fingerprint changes.
	return out
}

// convertCertificates translates client certificates field by field; the
// two packages define their own Certificate type.
func convertCertificates(in []tls.Certificate) []utls.Certificate {
	if len(in) == 0 {
		return nil
	}
	out := make([]utls.Certificate, len(in))
	for i, c := range in {
		out[i] = utls.Certificate{
			Certificate:                  c.Certificate,
			PrivateKey:                   c.PrivateKey,
			Leaf:                         c.Leaf,
			OCSPStaple:                   c.OCSPStaple,
			SignedCertificateTimestamps:  c.SignedCertificateTimestamps,
			SupportedSignatureAlgorithms: nil,
		}
	}
	return out
}

// NewUTLSConn wraps conn in a uTLS client using the profile's fingerprint.
// The returned connection has not handshaked yet; call Handshake (or let
// the first Read/Write trigger it) as with crypto/tls.
//
// The ServerName must be set on cfg (via UTLSConfig from a base that sets
// it); otherwise the handshake cannot build a valid ClientHello.
func (p Profile) NewUTLSConn(conn net.Conn, cfg *utls.Config) (*utls.UConn, error) {
	id, err := p.FingerprintID()
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("obfs: nil conn for uTLS client")
	}
	return utls.UClient(conn, cfg, id), nil
}
