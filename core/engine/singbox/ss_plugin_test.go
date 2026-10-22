package singbox

import (
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/enginetest"
)

func ssPluginOutbound(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	for _, ob := range cfg["outbounds"].([]any) {
		m := ob.(map[string]any)
		if m["type"] == "shadowsocks" {
			return m
		}
	}
	t.Fatal("no shadowsocks outbound rendered")
	return nil
}

// TestRenderShadowsocksPlugin: an explicit SIP002 plugin renders verbatim
// and wins over the legacy obfs-local mapping; the legacy path must not
// emit an empty obfs-host anymore.
func TestRenderShadowsocksPlugin(t *testing.T) {
	p := enginetest.Plan(engine.ProtocolShadowsocks)
	p.Outbounds[0].ObfsBox().Plugin = "v2ray-plugin"
	p.Outbounds[0].ObfsBox().PluginOpts = "tls;host=example.com"
	p.Outbounds[0].ObfsBox().Type = "tls"
	ob := ssPluginOutbound(t, render(t, p))
	if ob["plugin"] != "v2ray-plugin" || ob["plugin_opts"] != "tls;host=example.com" {
		t.Fatalf("plugin must render verbatim, got %v", ob)
	}

	p = enginetest.Plan(engine.ProtocolShadowsocks)
	p.Outbounds[0].ObfsBox().Type = "tls"
	ob = ssPluginOutbound(t, render(t, p))
	if ob["plugin"] != "obfs-local" || ob["plugin_opts"] != "obfs=tls" {
		t.Fatalf("legacy obfs must not emit an empty obfs-host, got %v", ob)
	}

	p = enginetest.Plan(engine.ProtocolShadowsocks)
	p.Outbounds[0].ObfsBox().Type = "http"
	p.Outbounds[0].ObfsBox().Param = "example.com"
	ob = ssPluginOutbound(t, render(t, p))
	if ob["plugin_opts"] != "obfs=http;obfs-host=example.com" {
		t.Fatalf("obfs-host must survive when set, got %v", ob)
	}

	p = enginetest.Plan(engine.ProtocolShadowsocks)
	p.Outbounds[0].ObfsBox().Plugin = "obfs-local"
	p.Outbounds[0].ObfsBox().PluginOpts = "obfs=tls;obfs-host=example.com"
	ob = ssPluginOutbound(t, render(t, p))
	if ob["plugin"] != "obfs-local" || ob["plugin_opts"] != "obfs=tls;obfs-host=example.com" {
		t.Fatalf("explicit obfs-local plugin must render verbatim, got %v", ob)
	}
}

// TestRenderShadowsocksPluginFailClosed pins SP3b/F3 for sing-box:
// plugins that need an external binary (gost-plugin, shadow-tls) and
// any unknown name are refused at render with the plugin named,
// instead of rendering verbatim into a config the engine would
// reject with a bare FATAL at start.
func TestRenderShadowsocksPluginFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		plugin string
		opts   string
	}{
		{"gost-plugin", "gost-plugin", "host=example.com"},
		{"shadow-tls", "shadow-tls", "host=example.com;password=pw"},
		{"unknown", "unknown-xyz", "foo=bar"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := enginetest.Plan(engine.ProtocolShadowsocks)
			p.Outbounds[0].ObfsBox().Plugin = tc.plugin
			p.Outbounds[0].ObfsBox().PluginOpts = tc.opts
			if _, err := Render(p, testRuntime); err == nil || !strings.Contains(err.Error(), "plugin binary sora does not ship") {
				t.Fatalf("Render = %v, want fail-closed error naming the unshipped plugin binary", err)
			}
		})
	}
}

// TestRenderPluginOptsCanonicalOrder pins SP3b: the same plugin
// option set renders byte-identically however the import spelled it,
// because sing-box renders CanonicalSSPluginOpts (schema order).
func TestRenderPluginOptsCanonicalOrder(t *testing.T) {
	p := enginetest.Plan(engine.ProtocolShadowsocks)
	p.Outbounds[0].ObfsBox().Plugin = "v2ray-plugin"
	p.Outbounds[0].ObfsBox().PluginOpts = "path=/ws;host=example.com;tls"
	ob := ssPluginOutbound(t, render(t, p))
	if ob["plugin_opts"] != "tls;host=example.com;path=/ws" {
		t.Fatalf("plugin_opts = %v, want canonical schema order", ob["plugin_opts"])
	}
}
