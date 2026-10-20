package guard

import (
	"net/netip"
	"strings"

	"github.com/levvs-one/sora-client/core/engine"
)

// nftables owns an atomically installed Linux table. Engine UID, loopback, and
// permitted connection traffic bypass the output drop; the UID exception lets
// engines reach servers without allowing other processes out.
const (
	// nftTable names the owned table with a Sora prefix for identification
	// in nft list ruleset.
	nftTable = "sora"
	// nftChain is the output hook the table installs.
	nftChain = "output"
	// Old fake addresses may remain in application caches after an upgrade.
	legacyFakeIPNetwork = "172.19.0.0/16"
)

// defaultBypassNetworks backs DefaultBypassNetworks and the ruleset render
// when no bypass is configured. It is never mutated: DefaultBypassNetworks
// hands out a clone, and the render only reads it.
var defaultBypassNetworks = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"fc00::/7",
	"fe80::/10",
}

// NftRuleset renders testable kill-switch rules for the engine UID. Bypass
// networks keep local resources reachable; empty uses private and link-local
// ranges.
func NftRuleset(engineUID int, bypass []string, blocked ...netip.Prefix) string {
	networks := bypass
	if len(networks) == 0 {
		networks = defaultBypassNetworks
	}
	// Size the builder for the whole ruleset up front and write the line
	// fragments directly: concatenating each line into one string first
	// allocated a throwaway copy per rule.
	size := 640 + len(blocked)*112
	for _, network := range networks {
		size += len(network) + 80
	}
	var b strings.Builder
	b.Grow(size)
	b.WriteString("table inet " + nftTable + " {\n")
	b.WriteString("\tchain " + nftChain + " {\n")
	b.WriteString("\t\ttype filter hook output priority filter; policy accept;\n")
	b.WriteString("\t\toif lo accept comment \"sora: the local engine is on loopback\"\n")
	// Permit traffic through TUN; block only traffic bypassing it.
	b.WriteString("\t\toifname \"")
	b.WriteString(engine.TunDevice)
	b.WriteString("\" accept comment \"sora: through the tunnel\"\n")
	writeBlocked := func(network netip.Prefix) {
		family := "ip"
		if network.Addr().Is6() {
			family = "ip6"
		}
		b.WriteString("\t\t")
		b.WriteString(family)
		b.WriteString(" daddr ")
		b.WriteString(network.Masked().String())
		b.WriteString(" counter drop comment \"sora: tunnel destination outside the tunnel\"\n")
	}
	writeBlocked(netip.MustParsePrefix(legacyFakeIPNetwork))
	for _, network := range blocked {
		writeBlocked(network)
	}
	b.WriteString("\t\tmeta skuid ")
	b.WriteString(itoa(engineUID))
	b.WriteString(" accept comment \"sora: the engine keeps its own traffic\"\n")
	// Bound resolvers can remain on a physical device even after routing
	// selects TUN. Never let the LAN exception release their queries.
	b.WriteString("\t\tmeta l4proto { tcp, udp } th dport 53 counter drop comment \"sora: DNS outside the tunnel\"\n")
	// Allow replies to inbound connections, but not pre-existing outbound
	// flows that could bypass TUN.
	b.WriteString("\t\tct direction reply ct state established,related accept comment \"sora: replies to incoming connections\"\n")
	for _, network := range networks {
		// Match each network only against its address family; nft
		// rejects cross-family rules.
		family := "ip"
		if prefix, err := netip.ParsePrefix(network); err == nil && prefix.Addr().Is6() {
			family = "ip6"
		} else if addr, err := netip.ParseAddr(network); err == nil && addr.Is6() {
			family = "ip6"
		}
		b.WriteString("\t\t")
		b.WriteString(family)
		b.WriteString(" daddr ")
		b.WriteString(network)
		b.WriteString(" accept comment \"sora: local network bypass\"\n")
	}
	b.WriteString("\t\tcounter drop comment \"sora: kill switch\"\n")
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String()
}

// NftRemove renders table removal. Missing tables are treated as success so
// repeated restores are safe.
func NftRemove() string {
	return "delete table inet " + nftTable + "\n"
}

// DefaultBypassNetworks keeps private, link-local, and loopback destinations
// reachable while armed.
func DefaultBypassNetworks() []string {
	return append([]string(nil), defaultBypassNetworks...)
}

// FirstLine limits external tool details to one line for consistent core error
// formatting.
func FirstLine(text string) string {
	if index := strings.IndexAny(text, "\r\n"); index >= 0 {
		return strings.TrimSpace(text[:index])
	}
	return strings.TrimSpace(text)
}

// itoa formats a small positive number without strconv.
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	if negative {
		index--
		digits[index] = '-'
	}
	return string(digits[index:])
}
