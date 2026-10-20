package guard

import (
	"net/netip"
	"testing"
)

// TestNftRulesetGoldenMixed pins the rendered ruleset byte for byte for a
// mixed input (IPv4/IPv6/garbage bypass entries and blocked prefixes): the
// allocation-lean render must not change a single byte of the output.
func TestNftRulesetGoldenMixed(t *testing.T) {
	got := NftRuleset(65534,
		[]string{"10.0.0.0/8", "fd00::/8", "example", "2001:db8::1", ""},
		netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32"))
	want := "table inet sora {\n\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n\t\toif lo accept comment \"sora: the local engine is on loopback\"\n\t\toifname \"sora0\" accept comment \"sora: through the tunnel\"\n\t\tip daddr 172.19.0.0/16 counter drop comment \"sora: tunnel destination outside the tunnel\"\n\t\tip daddr 203.0.113.0/24 counter drop comment \"sora: tunnel destination outside the tunnel\"\n\t\tip6 daddr 2001:db8::/32 counter drop comment \"sora: tunnel destination outside the tunnel\"\n\t\tmeta skuid 65534 accept comment \"sora: the engine keeps its own traffic\"\n\t\tmeta l4proto { tcp, udp } th dport 53 counter drop comment \"sora: DNS outside the tunnel\"\n\t\tct direction reply ct state established,related accept comment \"sora: replies to incoming connections\"\n\t\tip daddr 10.0.0.0/8 accept comment \"sora: local network bypass\"\n\t\tip6 daddr fd00::/8 accept comment \"sora: local network bypass\"\n\t\tip daddr example accept comment \"sora: local network bypass\"\n\t\tip6 daddr 2001:db8::1 accept comment \"sora: local network bypass\"\n\t\tip daddr  accept comment \"sora: local network bypass\"\n\t\tcounter drop comment \"sora: kill switch\"\n\t}\n}\n"
	if got != want {
		t.Errorf("ruleset drifted")
	}
}
