// Package obfs is the obfuscation suite for TLS handshakes the core
// initiates itself (subscription fetches and direct TLS dials).
//
// It provides four independent techniques:
//
//   - uTLS ClientHello fingerprint selection (see utls.go and dial.go)
//     for direct TLS connections dialed through Dialer.
//   - Pure-Go ClientHello fragmentation (see fragment.go), which works
//     at the TCP layer underneath any TLS stack.
//   - Fake-SNI rewriting of the initial ClientHello (see sni.go), and
//     inter-write timing jitter (see jitter.go), both applied by
//     WrapConn on the same write path (ported from sora, W4).
//
// The package deliberately does not try to bend net/http.Transport into
// using uTLS: the transport owns the TLS handshake (it type-asserts the
// connection to *tls.Conn to drive HTTP/2), and its DialTLSContext hook
// cannot be combined with proxying. Applying fragmentation through the
// transport's DialContext hook is safe and keeps proxies, HTTP/2 and
// certificate verification intact, so that is the only obfuscation the
// subscription fetcher uses. The uTLS profiles are available to direct
// TLS dials via Dialer, where the caller owns the whole handshake.
//
// A Profile describes one obfuscation setup. Profiles are validated with
// Validate, normalized with Clamp, and applied with WrapConn (for
// net.Conn) and the uTLS helpers (for TLS handshakes). PresetMax,
// PresetBalanced and PresetFast are ready-made starting points.
//
// Safety rules honored by this package:
//   - Obfuscation is only ever applied to handshakes the core initiates
//     itself, never injected into user traffic.
//   - All delays are clamped to sane maxima so a misconfigured profile
//     can slow a handshake down but never stall it forever.
//   - Fragmentation never mangles non-TLS bytes: if the first write does
//     not look like a TLS handshake record it passes through untouched.
package obfs
