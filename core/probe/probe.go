// Package probe measures TCP reachability and optional TLS handshakes without a
// tunnel, credentials, or application payload. It streams uncached results so
// provider endpoint changes are reflected immediately.
package probe

import (
	"context"
	"crypto/tls"
	"math"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/levvs-one/sora-client/core/errs"
	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
)

// Short default timeouts bound list updates for unreachable endpoints.
const (
	// DefaultTimeout bounds one endpoint.
	DefaultTimeout = 5 * time.Second
	// DefaultConcurrency limits simultaneous sockets for large
	// subscriptions.
	DefaultConcurrency = 8
	// MaxEndpoints bounds one request.
	MaxEndpoints = 256
)

// Config configures a prober.
type Config struct {
	// Timeout bounds one endpoint.
	Timeout time.Duration
	// Concurrency bounds how many endpoints are measured at once.
	Concurrency int
	// TLS requires a certificate-bearing handshake, not just an open TCP
	// socket.
	TLS bool
	// ServerName selects the verified TLS name. Empty uses the endpoint
	// host.
	ServerName string
	// AllowPrivate permits probing private, loopback and link-local
	// targets. Keep it false in production: probing must not become an
	// oracle for the local network. Tests use it for loopback listeners.
	AllowPrivate bool
}

// Prober measures endpoints and streams the results.
type Prober struct {
	timeout      time.Duration
	concurrency  int
	tls          bool
	serverName   string
	allowPrivate bool
	// slots shares the socket budget across all requests; per-request
	// limits would let concurrent calls multiply socket usage.
	slots chan struct{}
	// requests bounds concurrent calls so one-endpoint floods cannot create
	// an unbounded queue.
	requests chan struct{}
}

// MaxConcurrentRequests bounds how many measurements a prober runs at once.
const MaxConcurrentRequests = 4

// New returns a prober with the defaults filled in.
func New(cfg Config) *Prober {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	return &Prober{
		timeout:      cfg.Timeout,
		concurrency:  cfg.Concurrency,
		tls:          cfg.TLS,
		serverName:   cfg.ServerName,
		allowPrivate: cfg.AllowPrivate,
		slots:        make(chan struct{}, cfg.Concurrency),
		requests:     make(chan struct{}, MaxConcurrentRequests),
	}
}

// Probe streams one result per endpoint in completion order, then closes the
// channel. Missing serverIDs produce empty IDs. Socket limits are global to the
// prober; excess requests are rejected instead of queued.
func (p *Prober) Probe(ctx context.Context, endpoints []*corev1.Endpoint, serverIDs []string) (<-chan *corev1.ProbeResult, error) {
	if len(endpoints) == 0 {
		return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyProbeNoEndpoints,
			"probe: the request carries no endpoints")
	}
	if len(endpoints) > MaxEndpoints {
		return nil, errs.Newf(errs.CodeResourceExhausted, errs.KeyProbeTooMany,
			"probe: the request carries %d endpoints, the limit is %d", len(endpoints), MaxEndpoints)
	}
	select {
	case p.requests <- struct{}{}:
	default:
		return nil, errs.Newf(errs.CodeResourceExhausted, errs.KeyProbeTooMany,
			"probe: %d measurements are already running, the limit is %d",
			len(p.requests), MaxConcurrentRequests)
	}
	results := make(chan *corev1.ProbeResult, len(endpoints))
	go func() {
		defer close(results)
		defer func() { <-p.requests }()
		var wg sync.WaitGroup
		for index, endpoint := range endpoints {
			wg.Add(1)
			go func(index int, endpoint *corev1.Endpoint) {
				defer wg.Done()
				select {
				case p.slots <- struct{}{}:
					defer func() { <-p.slots }()
				case <-ctx.Done():
					return
				}
				result := p.measure(ctx, index, endpoint, serverIDs)
				select {
				case results <- result:
				case <-ctx.Done():
				}
			}(index, endpoint)
		}
		wg.Wait()
	}()
	return results, nil
}

// measure always returns a result so failed endpoints remain represented in the
// list.
func (p *Prober) measure(ctx context.Context, index int, endpoint *corev1.Endpoint, serverIDs []string) *corev1.ProbeResult {
	result := &corev1.ProbeResult{}
	if index < len(serverIDs) {
		result.ServerId = serverIDs[index]
	}
	host, port, err := addressOf(endpoint)
	if err != nil {
		result.Error = toWire(err, "")
		return result
	}
	// Probing must not become an oracle for the local network: reject
	// private, loopback and link-local targets like the subscription
	// fetcher does (see subscription.dialChecked), unless the operator
	// explicitly allows them.
	if !p.allowPrivate && isPrivateTarget(ctx, host) {
		result.Error = toWire(errs.Newf(errs.CodePermissionDenied, errs.KeyProbeInvalidEndpoint,
			"probe: private targets are not probed"), "")
		return result
	}
	latency, err := p.dial(ctx, host, port)
	if err != nil {
		result.Error = toWire(err, host)
		return result
	}
	result.Reachable = true
	result.LatencyMs = counter(latency.Milliseconds())
	return result
}

// dial opens the connection, optionally completes a handshake, and reports how
// long the whole thing took.
func (p *Prober) dial(ctx context.Context, host string, port uint32) (time.Duration, error) {
	address := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
	timeout := p.timeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return 0, errs.Newf(errs.CodeDeadlineExceeded, errs.KeyProbeInvalidEndpoint,
			"probe: the request has no time left")
	}
	start := time.Now()
	if !p.tls {
		connection, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
		if err != nil {
			return 0, errs.From(err)
		}
		_ = connection.Close()
		return time.Since(start), nil
	}
	// Include TLS in the measurement to distinguish certificate failures
	// from TCP reachability. The context cancels stalled handshakes.
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    p.tlsConfig(host),
	}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return 0, errs.From(err)
	}
	_ = connection.Close()
	return time.Since(start), nil
}

// isPrivateTarget reports whether host names a private, loopback or
// link-local address, resolving DNS names. A failed lookup is not treated as
// private: the dial itself will fail then.
func isPrivateTarget(ctx context.Context, host string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		return !publicAddr(addr)
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if !publicAddr(addr) {
			return true
		}
	}
	return false
}

// publicAddr mirrors the subscription fetcher's notion of a dialable public
// address, including its special-use blocklist; the two must stay identical.
func publicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, prefix := range specialUse {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// specialUse prefixes are globally reachable per IsGlobalUnicast but never
// name a server on the internet: shared CGNAT space, benchmarking, and the
// documentation pools Sora itself uses for its TUN adapters.
var specialUse = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// EndpointProber defines the interface required by the control plane, keeping
// compatibility checks near the implementation.
type EndpointProber interface {
	Probe(ctx context.Context, endpoints []*corev1.Endpoint, serverIDs []string) (<-chan *corev1.ProbeResult, error)
}

var _ EndpointProber = (*Prober)(nil)

// tlsConfig enables certificate verification so hijacked or untrusted servers
// cannot appear healthy.
func (p *Prober) tlsConfig(host string) *tls.Config {
	name := p.serverName
	if name == "" {
		name = host
	}
	return &tls.Config{
		ServerName: name,
		MinVersion: tls.VersionTLS12,
	}
}

// addressOf reads and checks one endpoint.
func addressOf(endpoint *corev1.Endpoint) (string, uint32, error) {
	if endpoint == nil {
		return "", 0, errs.Newf(errs.CodeInvalidArgument, errs.KeyProbeInvalidEndpoint,
			"probe: the endpoint is missing")
	}
	host := endpoint.GetHost()
	if host == "" {
		return "", 0, errs.Newf(errs.CodeInvalidArgument, errs.KeyProbeInvalidEndpoint,
			"probe: the endpoint has no host")
	}
	port := endpoint.GetPort()
	if port == 0 || port > 0xffff {
		return "", 0, errs.Newf(errs.CodeInvalidArgument, errs.KeyProbeInvalidEndpoint,
			"probe: the port is not a port")
	}
	return host, port, nil
}

// toWire converts probe failures without exposing endpoint addresses to
// clients.
func toWire(err error, host string) *corev1.SoraError {
	classified := errs.From(err)
	detail := classified.Detail()
	if host == "" && detail == "" {
		detail = "the endpoint is not a host and a port"
	}
	return &corev1.SoraError{
		Code:           probeCode(classified.Code()),
		UserMessageKey: string(classified.Key()),
		DetailRedacted: detail,
		Retryable:      classified.Retryable(),
	}
}

// probeCode maps network failures, including refusal, to unavailable probe
// results. Malformed endpoints remain invalid.
func probeCode(code errs.Code) corev1.SoraErrorCode {
	switch code {
	case errs.CodeInvalidArgument:
		return corev1.SoraErrorCode_SORA_ERROR_CODE_INVALID_ARGUMENT
	case errs.CodePermissionDenied:
		return corev1.SoraErrorCode_SORA_ERROR_CODE_PERMISSION_DENIED
	case errs.CodeTimeout, errs.CodeDeadlineExceeded:
		return corev1.SoraErrorCode_SORA_ERROR_CODE_DEADLINE_EXCEEDED
	default:
		return corev1.SoraErrorCode_SORA_ERROR_CODE_UNAVAILABLE
	}
}

// counter converts milliseconds to the wire field without negative values.
func counter(value int64) uint32 {
	if value <= 0 {
		return 0
	}
	if value > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(value) //nolint:gosec // bounded by the check above
}
