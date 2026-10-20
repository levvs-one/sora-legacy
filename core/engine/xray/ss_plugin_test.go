package xray

import (
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/enginetest"
)

// TestRenderShadowsocksPluginFailClosed pins SP3b/F4+F6: Xray has no
// SIP002 plugin support and silently ignores unknown config keys, so
// a Shadowsocks outbound carrying a plugin — or the legacy
// simple-obfs mapping — must be refused at render instead of being
// emitted as a plain, unobfuscated config.
func TestRenderShadowsocksPluginFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*engine.Outbound)
	}{
		{"plugin", func(o *engine.Outbound) { o.Plugin = "v2ray-plugin"; o.PluginOpts = "tls;host=example.com" }},
		{"obfs-local plugin", func(o *engine.Outbound) { o.Plugin = "obfs-local"; o.PluginOpts = "obfs=tls;obfs-host=example.com" }},
		{"legacy obfs", func(o *engine.Outbound) { o.Obfs = "tls"; o.ObfsParam = "example.com" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := enginetest.Plan(engine.ProtocolShadowsocks)
			tc.mutate(&p.Outbounds[0])
			if _, err := Render(p, testRuntime, nil); err == nil ||
				!strings.Contains(err.Error(), "does not implement") ||
				!strings.Contains(err.Error(), "unobfuscated") {
				t.Fatalf("Render = %v, want fail-closed error refusing to render unobfuscated", err)
			}
		})
	}
	// A plain Shadowsocks outbound still renders.
	p := enginetest.Plan(engine.ProtocolShadowsocks)
	if _, err := Render(p, testRuntime, nil); err != nil {
		t.Fatalf("plain SS render broke: %v", err)
	}
}
