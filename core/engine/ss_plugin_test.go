package engine

import (
	"strings"
	"testing"
)

// SP3b: the SS plugin catalog and its gates, ported from sora
// (CENSOR-P4). The plugin facts are measured data (see ss_plugin.go);
// these tests pin the data so a silent edit of the tables fails
// loudly, and pin the fail-closed behaviour at selection and at plan
// validation.

func ssPluginPlan(plugin, opts string) *Plan {
	p := &Plan{SessionID: "sp3b", Outbounds: []Outbound{
		{ID: "ss", Name: "ss", Protocol: ProtocolShadowsocks,
			Server: "ss.example.com", Port: 4433, Cipher: "aes-256-gcm",
			Password: "a-long-enough-password", Obfs: &ObfsSettings{Plugin: plugin, PluginOpts: opts}},
	}}
	return p
}

func TestSSPluginSelectionMatrix(t *testing.T) {
	cases := []struct {
		name  string
		plan  *Plan
		carry map[Kind]bool
	}{
		{"v2ray-plugin", ssPluginPlan("v2ray-plugin", "tls;host=example.com"), map[Kind]bool{KindSingBox: true, KindMihomo: true}},
		{"obfs-local", ssPluginPlan("obfs-local", "obfs=tls;obfs-host=example.com"), map[Kind]bool{KindSingBox: true, KindMihomo: true}},
		{"gost-plugin", ssPluginPlan("gost-plugin", "host=example.com"), map[Kind]bool{KindMihomo: true}},
		{"shadow-tls", ssPluginPlan("shadow-tls", "host=example.com;password=pw"), map[Kind]bool{KindMihomo: true}},
		{"unknown", ssPluginPlan("unknown-xyz", ""), map[Kind]bool{}},
	}
	for _, tc := range cases {
		for _, kind := range []Kind{KindSingBox, KindXray, KindMihomo} {
			missing := Catalog[kind].Missing(tc.plan)
			has := false
			for _, m := range missing {
				if strings.Contains(m, "shadowsocks plugin") {
					has = true
				}
			}
			if has == tc.carry[kind] {
				t.Errorf("plugin %s on %s: plugin-missing=%v, want carry=%v (missing=%v)",
					tc.name, kind, has, tc.carry[kind], missing)
			}
		}
	}
	// Legacy obfs: Xray must report it missing; the carriers must not.
	p := ssPluginPlan("", "")
	p.Outbounds[0].ObfsBox().Type, p.Outbounds[0].ObfsBox().Param = "tls", "example.com"
	if m := Catalog[KindXray].Missing(p); !strings.Contains(strings.Join(m, ","), "shadowsocks obfs") {
		t.Errorf("xray must miss legacy SS obfs, missing=%v", m)
	}
	for _, kind := range []Kind{KindSingBox, KindMihomo} {
		for _, m := range Catalog[kind].Missing(p) {
			if strings.Contains(m, "obfs") {
				t.Errorf("%s must carry legacy SS obfs, missing=%v", kind, m)
			}
		}
	}
}

func TestValidateShadowsocksPluginFailsClosed(t *testing.T) {
	mk := func() Outbound { return ssPluginPlan("", "").Outbounds[0] }
	for _, tc := range []struct {
		name   string
		mutate func(*Outbound)
		want   string // substring; "" means valid
	}{
		{"known plugin ok", func(o *Outbound) {
			o.ObfsBox().Plugin, o.ObfsBox().PluginOpts = "v2ray-plugin", "tls;host=example.com;path=/ws"
		}, ""},
		{"obfs-local ok", func(o *Outbound) {
			o.ObfsBox().Plugin, o.ObfsBox().PluginOpts = "obfs-local", "obfs=tls;obfs-host=example.com"
		}, ""},
		{"unknown plugin", func(o *Outbound) { o.ObfsBox().Plugin = "nosuch-plugin" }, "unknown shadowsocks plugin"},
		{"opts without plugin", func(o *Outbound) { o.ObfsBox().PluginOpts = "tls" }, "without a plugin"},
		{"unknown option", func(o *Outbound) { o.ObfsBox().Plugin, o.ObfsBox().PluginOpts = "v2ray-plugin", "bogus=1" }, "unknown option"},
		{"duplicate option", func(o *Outbound) {
			o.ObfsBox().Plugin, o.ObfsBox().PluginOpts = "v2ray-plugin", "host=a.com;host=b.com"
		}, "set twice"},
		{"bad flag", func(o *Outbound) { o.ObfsBox().Plugin, o.ObfsBox().PluginOpts = "v2ray-plugin", "tls=maybe" }, "boolean"},
		{"bad host", func(o *Outbound) { o.ObfsBox().Plugin, o.ObfsBox().PluginOpts = "v2ray-plugin", "host=exa mple.com" }, "not a valid host"},
		{"bad path", func(o *Outbound) { o.ObfsBox().Plugin, o.ObfsBox().PluginOpts = "v2ray-plugin", "path=ws" }, "absolute path"},
		{"bad obfs mode", func(o *Outbound) { o.ObfsBox().Plugin, o.ObfsBox().PluginOpts = "obfs-local", "obfs=salamander" }, "http or tls"},
		{"stray segment", func(o *Outbound) { o.ObfsBox().Plugin, o.ObfsBox().PluginOpts = "v2ray-plugin", "tls;;host=a.com" }, "empty option segment"},
		{"legacy obfs ok", func(o *Outbound) { o.ObfsBox().Type, o.ObfsBox().Param = "tls", "example.com" }, ""},
		{"legacy obfs bad mode", func(o *Outbound) { o.ObfsBox().Type = "salamander" }, "simple-obfs mode"},
		{"legacy obfs bad host", func(o *Outbound) { o.ObfsBox().Type, o.ObfsBox().Param = "http", "not a host" }, "not valid"},
		{"obfs-host injection", func(o *Outbound) { o.ObfsBox().Type, o.ObfsBox().Param = "tls", "a.com;obfs=http" }, "separator"},
		{"dead obfs-host", func(o *Outbound) { o.ObfsBox().Param = "example.com" }, "without an obfs mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := mk()
			tc.mutate(&o)
			err := o.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want error containing %q", err, tc.want)
			}
		})
	}
	// Plugin fields on a non-Shadowsocks outbound are refused, not dropped.
	o := Outbound{ID: "v", Name: "v", Protocol: ProtocolVLESS, Server: "v.example.com", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Obfs: &ObfsSettings{Plugin: "v2ray-plugin"}}
	if err := o.Validate(); err == nil || !strings.Contains(err.Error(), "plugins belong to shadowsocks") {
		t.Fatalf("plugin on vless: Validate = %v", err)
	}
}

// Plugin option strings are deterministic: the same option set
// renders the same string in any input order.
func TestCanonicalSSPluginOpts(t *testing.T) {
	cases := []struct{ plugin, in, want string }{
		{"v2ray-plugin", "tls;host=example.com", "tls;host=example.com"},
		{"v2ray-plugin", "host=example.com;tls", "tls;host=example.com"},
		{"v2ray-plugin", "path=/ws;host=example.com;mux;tls", "tls;mux;host=example.com;path=/ws"},
		{"obfs-local", "obfs-host=example.com;obfs=tls", "obfs=tls;obfs-host=example.com"},
		{"shadow-tls", "password=pw;host=example.com;version=3", "host=example.com;password=pw;version=3"},
		{"nosuch-plugin", "b=2;a=1", "b=2;a=1"}, // unknown passes through; validation owns rejection
	}
	for _, tc := range cases {
		if got := CanonicalSSPluginOpts(tc.plugin, tc.in); got != tc.want {
			t.Errorf("CanonicalSSPluginOpts(%q, %q) = %q, want %q", tc.plugin, tc.in, got, tc.want)
		}
	}
}

// A plugin password that exists only inside PluginOpts is registered
// as a secret on its own, so a log line quoting just the value is
// masked even though the whole option string is masked too.
func TestSecretsCoverPluginSecretValues(t *testing.T) {
	o := Outbound{ID: "ss", Name: "ss", Protocol: ProtocolShadowsocks,
		Server: "ss.example.com", Port: 4433, Cipher: "aes-256-gcm",
		Password: "a-long-enough-password",
		Obfs:     &ObfsSettings{Plugin: "shadow-tls", PluginOpts: "host=example.com;password=" + "plugin-secret-value"}}
	secrets := o.Secrets()
	for _, want := range []string{"plugin-secret-value", o.ObfsOrZero().PluginOpts} {
		found := false
		for _, s := range secrets {
			if s == want {
				found = true
			}
		}
		if !found {
			t.Errorf("Secrets() must contain %q, got %v", want, secrets)
		}
	}
}
