package guard

import (
	"fmt"
	"testing"
)

// BenchmarkNftRulesetDefault measures the kill-switch ruleset render with
// the default bypass networks.
func BenchmarkNftRulesetDefault(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NftRuleset(1000, nil)
	}
}

// BenchmarkNftRuleset64 measures the render with 64 bypass networks.
func BenchmarkNftRuleset64(b *testing.B) {
	networks := make([]string, 0, 64)
	for i := 0; i < 64; i++ {
		networks = append(networks, fmt.Sprintf("10.%d.0.0/16", i))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NftRuleset(1000, networks)
	}
}
