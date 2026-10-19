//go:build linux

package guard

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/levvs-one/sora-client/core/errs"
)

// Nftables manages a Linux output-hook table, removing it when the session
// ends.
type Nftables struct {
	mu      sync.Mutex
	uid     int
	bypass  []string
	command string // resolved lazily to an absolute path; empty until first use
	armed   bool
	blocked []netip.Prefix
}

// nftSearchPaths are the well-known locations of the nft binary. Discovery
// never consults PATH: a PATH-planted nft would run with the core's
// privileges and shape the kill switch.
var nftSearchPaths = []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"}

// findNft resolves the nft binary to an absolute path without consulting
// PATH.
func findNft() (string, error) {
	for _, path := range nftSearchPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0 {
			return path, nil
		}
	}
	return "", errs.Newf(errs.CodeNotFound, errs.KeyGuardFirewallFail,
		"guard: nft not found in %s; install nftables", strings.Join(nftSearchPaths, ", "))
}

// NewNftables permits engine traffic owned by uid and the supplied bypass
// networks. Empty bypass uses private ranges to keep local resources reachable.
func NewNftables(uid int, bypass []string) (*Nftables, error) {
	if uid < 0 {
		return nil, errs.Newf(errs.CodeInvalidArgument, errs.KeyGuardFirewallFail,
			"guard: the engine has no user id")
	}
	if len(bypass) == 0 {
		bypass = DefaultBypassNetworks()
	}
	if err := validateBypass(bypass); err != nil {
		return nil, err
	}
	return &Nftables{uid: uid, bypass: bypass}, nil
}

// validateBypass rejects bypass entries that are not valid CIDR prefixes or
// IP addresses before they are interpolated into the nft ruleset.
func validateBypass(bypass []string) error {
	for _, entry := range bypass {
		if _, err := netip.ParsePrefix(entry); err != nil {
			if _, err := netip.ParseAddr(entry); err != nil {
				return errs.Newf(errs.CodeInvalidArgument, errs.KeyGuardFirewallFail,
					"guard: bypass %q is not a CIDR prefix or IP address", entry)
			}
		}
	}
	return nil
}

// SetBlockedNetworks retains session destinations across engine crashes.
func (n *Nftables) SetBlockedNetworks(networks []netip.Prefix) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.blocked = append([]netip.Prefix(nil), networks...)
}

// Arm installs or replaces the table, making repeated calls idempotent.
func (n *Nftables) Arm(ctx context.Context, _ []uint16) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.apply(ctx, NftRuleset(n.uid, n.bypass, n.blocked...)); err != nil {
		return err
	}
	n.armed = true
	return nil
}

// Disarm removes the table and succeeds if already removed.
func (n *Nftables) Disarm(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.apply(ctx, NftRemove()); err != nil {
		return err
	}
	n.armed = false
	return nil
}

// Armed reports whether this process installed the table.
func (n *Nftables) Armed(context.Context) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.armed, nil
}

// Name identifies the implementation in a diagnostics line.
func (n *Nftables) Name() string { return "nftables" }

// nftCommand resolves the nft binary to an absolute path on first use and
// caches it. Resolution is lazy so systems without nftables can still run the
// core; only arming the kill switch requires nft. Callers must hold n.mu.
func (n *Nftables) nftCommand() (string, error) {
	if n.command != "" {
		return n.command, nil
	}
	command, err := findNft()
	if err != nil {
		return "", err
	}
	n.command = command
	return command, nil
}

// apply sends nft rules on stdin to avoid command-line length limits and
// exposing rules in process arguments.
func (n *Nftables) apply(ctx context.Context, ruleset string) error {
	command, err := n.nftCommand()
	if err != nil {
		return err
	}
	process := exec.CommandContext(ctx, command, "-f", "-") //nolint:gosec // command is the nft binary resolved to an absolute path at construction; the ruleset arrives on stdin
	process.Stdin = strings.NewReader(ruleset)
	output, err := process.CombinedOutput()
	if err != nil {
		// nft output names table, chain, or syntax failures and
		// contains no secrets.
		return errs.Newf(errs.CodePermissionDenied, errs.KeyGuardFirewallFail,
			"guard: nft refused the ruleset: %s", FirstLine(string(output)))
	}
	return nil
}

// PlatformFirewall returns the Linux nftables kill switch.
func PlatformFirewall(opts FirewallOptions) (Firewall, error) {
	return NewNftables(opts.EngineUID, opts.Bypass)
}
