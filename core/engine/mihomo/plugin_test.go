package mihomo

import (
	"reflect"
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
)

func TestSSPluginOpts(t *testing.T) {
	cases := []struct {
		name   string
		plugin string
		opts   string
		want   map[string]any
	}{
		{"obfs-local tls", "obfs-local", "obfs=tls;obfs-host=example.com",
			map[string]any{"mode": "tls", "host": "example.com"}},
		{"obfs-local http no host", "obfs-local", "obfs=http",
			map[string]any{"mode": "http"}},
		{"v2ray-plugin tls", "v2ray-plugin", "tls;host=example.com;path=/ws",
			map[string]any{"mode": "websocket", "tls": true, "host": "example.com", "path": "/ws"}},
		{"v2ray-plugin explicit flags", "v2ray-plugin", "tls=1;mux=false;host=h.example",
			map[string]any{"mode": "websocket", "tls": true, "mux": false, "host": "h.example"}},
		{"gost-plugin websocket shape", "gost-plugin", "tls;host=example.com",
			map[string]any{"mode": "websocket", "tls": true, "host": "example.com"}},
		{"gost-plugin bare tls flag is true, not empty", "gost-plugin", "host=example.com;tls",
			map[string]any{"mode": "websocket", "tls": true, "host": "example.com"}},
		{"unrecognized plugin passes through generically (the fail-closed gate lives in buildProxy)", "my-plugin", "foo=bar;flag",
			map[string]any{"foo": "bar", "flag": ""}},
		{"empty opts", "v2ray-plugin", "",
			map[string]any{"mode": "websocket"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ssPluginOpts(tc.plugin, tc.opts); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ssPluginOpts(%q, %q) = %v, want %v", tc.plugin, tc.opts, got, tc.want)
			}
		})
	}
}

func ssTestOutbound() engine.Outbound {
	return engine.Outbound{ID: "ss1", Name: "ss", Protocol: engine.ProtocolShadowsocks,
		Server: "ss.example.com", Port: 8388, Cipher: "aes-256-gcm", Password: "secret"}
}

func TestBuildProxyShadowsocksPlugin(t *testing.T) {
	// Explicit plugin wins over the native obfs mapping.
	o := ssTestOutbound()
	o.ObfsBox().Plugin, o.ObfsBox().PluginOpts = "v2ray-plugin", "tls;host=example.com"
	o.ObfsBox().Type, o.ObfsBox().Param = "tls", "example.com"
	px, err := buildProxy(o)
	if err != nil {
		t.Fatal(err)
	}
	if px.SSPlugin != "v2ray-plugin" {
		t.Errorf("plugin = %q, want v2ray-plugin", px.SSPlugin)
	}
	want := map[string]any{"mode": "websocket", "tls": true, "host": "example.com"}
	if !reflect.DeepEqual(px.SSPluginOpts, want) {
		t.Errorf("plugin-opts = %v, want %v", px.SSPluginOpts, want)
	}
	if px.Obfs != "" {
		t.Errorf("native obfs must stay empty when a plugin is set, got %q", px.Obfs)
	}

	// Explicit obfs-local plugin goes through the plugin path too,
	// under mihomo's own spelling: the adapter matches "obfs" and
	// silently ignores the SIP002 binary name "obfs-local" (SP3b/F1).
	o = ssTestOutbound()
	o.ObfsBox().Plugin, o.ObfsBox().PluginOpts = "obfs-local", "obfs=tls;obfs-host=example.com"
	px, err = buildProxy(o)
	if err != nil {
		t.Fatal(err)
	}
	want = map[string]any{"mode": "tls", "host": "example.com"}
	if px.SSPlugin != "obfs" || !reflect.DeepEqual(px.SSPluginOpts, want) {
		t.Errorf("obfs-local plugin mapping broken: plugin=%q opts=%v", px.SSPlugin, px.SSPluginOpts)
	}

	// Legacy path unchanged: native simple-obfs fields.
	o = ssTestOutbound()
	o.ObfsBox().Type, o.ObfsBox().Param = "tls", "example.com"
	px, err = buildProxy(o)
	if err != nil {
		t.Fatal(err)
	}
	if px.SSPlugin != "" || px.Obfs != "tls" || px.ObfsParam != "example.com" {
		t.Errorf("legacy obfs mapping broken: %+v", px)
	}

	// Neither set: no plugin keys at all.
	px, err = buildProxy(ssTestOutbound())
	if err != nil {
		t.Fatal(err)
	}
	if px.SSPlugin != "" || px.SSPluginOpts != nil || px.Obfs != "" {
		t.Errorf("plain SS must not carry plugin keys: %+v", px)
	}
}

// TestBuildProxyPluginNameTranslation pins SP3b/F1+F3 for mihomo:
// plugin names are translated to the spellings mihomo's adapter
// actually matches, and an unknown plugin fails closed at render
// instead of reaching the config, where the adapter would silently
// ignore it and run the plan unobfuscated.
func TestBuildProxyPluginNameTranslation(t *testing.T) {
	for _, tc := range []struct {
		plugin, opts, wantName string
	}{
		{"obfs-local", "obfs=tls;obfs-host=example.com", "obfs"},
		{"v2ray-plugin", "tls;host=example.com", "v2ray-plugin"},
		{"gost-plugin", "host=example.com", "gost-plugin"},
		{"shadow-tls", "host=example.com;password=pw", "shadow-tls"},
		{"restls-plugin", "host=example.com;password=pw", "restls"},
		{"jls-plugin", "host=example.com;username=u;password=p", "jls"},
		{"kcptun", "key=k", "kcptun"},
	} {
		o := ssTestOutbound()
		o.ObfsBox().Plugin, o.ObfsBox().PluginOpts = tc.plugin, tc.opts
		px, err := buildProxy(o)
		if err != nil {
			t.Fatalf("%s: %v", tc.plugin, err)
		}
		if px.SSPlugin != tc.wantName {
			t.Errorf("plugin %s rendered as %q, want mihomo name %q", tc.plugin, px.SSPlugin, tc.wantName)
		}
	}
	// Unknown plugins fail closed at render.
	o := ssTestOutbound()
	o.ObfsBox().Plugin = "unknown-xyz"
	if _, err := buildProxy(o); err == nil || !strings.Contains(err.Error(), "does not implement") {
		t.Fatalf("unknown plugin must fail closed, got %v", err)
	}
}

// TestSSPluginOptsGostShape pins SP3b/F2: gost-plugin options get the
// websocket shape its mihomo adapter requires (mode is mandatory
// there), like v2ray-plugin's, instead of the generic passthrough
// that produced a broken map with no mode and an empty tls string.
func TestSSPluginOptsGostShape(t *testing.T) {
	got := ssPluginOpts("gost-plugin", "tls;host=example.com")
	want := map[string]any{"mode": "websocket", "tls": true, "host": "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ssPluginOpts(gost-plugin) = %v, want %v", got, want)
	}
}
