package mobileapi

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const (
	testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
	testPBK  = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"
)

// importOne imports one link and returns its single Server.
func importOne(t *testing.T, link string) Server {
	t.Helper()
	raw, err := ImportLinks(link)
	if err != nil {
		t.Fatalf("ImportLinks: %v", err)
	}
	var servers []Server
	if err := json.Unmarshal([]byte(raw), &servers); err != nil {
		t.Fatalf("ImportLinks did not return a JSON array: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("ImportLinks returned %d servers, want 1: %s", len(servers), raw)
	}
	return servers[0]
}

// TestImportLinksFamilies imports one real link of every share-link
// family the legacy parser carries, then builds a plan and renders a
// sing-box configuration from the import, end to end.
func TestImportLinksFamilies(t *testing.T) {
	vmessDoc := `{"v":"2","ps":"VMess","add":"vmess.example.com","port":"24444","id":"` + testUUID +
		`","aid":"0","scy":"aes-128-gcm","net":"ws","type":"none","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"vmess.example.com"}`
	families := map[string]string{
		"vless":       "vless://" + testUUID + "@edge.example.com:443?type=ws&security=reality&pbk=" + testPBK + "&sid=6ba85179e30d4fc2&sni=www.example.com&fp=chrome&path=%2Fws&host=cdn.example.com#VLESS",
		"vmess":       "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessDoc)),
		"trojan":      "trojan://s3cret@example.com:443?sni=example.com#Trojan",
		"shadowsocks": "ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388#SS",
		"hysteria2":   "hysteria2://secret@example.com:443?sni=example.com#H2",
		"tuic":        "tuic://" + testUUID + ":pass@example.com:443#TUIC",
		"socks5":      "socks5://user:pass@example.com:1080#SOCKS",
		// No "http" share link here: a bare http:// payload is a
		// subscription reference to the parser, by design; the http
		// protocol itself is imported from documents below.
	}
	for protocol, link := range families {
		t.Run(protocol, func(t *testing.T) {
			server := importOne(t, link)
			if server.Protocol != protocol {
				t.Fatalf("protocol = %q, want %q", server.Protocol, protocol)
			}
			if server.ID == "" || server.Server == "" || server.Port == 0 {
				t.Fatalf("server identity is incomplete: %+v", server)
			}
			raw, err := ImportLinks(link)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := BuildPlan(raw); err != nil {
				t.Fatalf("BuildPlan: %v", err)
			}
			cfg, err := RenderSingBoxConfig(raw)
			if err != nil {
				t.Fatalf("RenderSingBoxConfig: %v", err)
			}
			var rendered map[string]any
			if err := json.Unmarshal([]byte(cfg), &rendered); err != nil {
				t.Fatalf("rendered config is not JSON: %v", err)
			}
			outbounds, _ := rendered["outbounds"].([]any)
			endpoints, _ := rendered["endpoints"].([]any)
			if len(outbounds)+len(endpoints) == 0 {
				t.Fatalf("rendered config carries no outbound: %s", cfg)
			}
		})
	}
}

// TestImportWireGuardConf imports a wg-conf document and renders it:
// WireGuard must land in sing-box endpoints, not outbounds.
func TestImportWireGuardConf(t *testing.T) {
	conf := "[Interface]\nPrivateKey = cKE7LmCF61IhqqABGhvJ44jWXp8fKymcMAEVAzLDYVk=\nAddress = 10.7.0.2/32\n" +
		"[Peer]\nPublicKey = " + testPBK + "=\nEndpoint = 198.51.100.7:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
	server := importOne(t, conf)
	if server.Protocol != "wireguard" {
		t.Fatalf("protocol = %q, want wireguard", server.Protocol)
	}
	raw, err := ImportLinks(conf)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := RenderSingBoxConfig(raw)
	if err != nil {
		t.Fatalf("RenderSingBoxConfig: %v", err)
	}
	if !strings.Contains(cfg, `"type":"wireguard"`) {
		t.Fatalf("rendered config has no wireguard endpoint: %s", cfg)
	}
}

// TestParseSubscriptionShapes parses the subscription body shapes:
// a base64 list, a Clash document with anytls (a protocol with no
// share-link form) and a SIP008 document.
func TestParseSubscriptionShapes(t *testing.T) {
	list := "trojan://s3cret@example.com:443?sni=example.com#T\nss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388#SS"
	raw, err := ParseSubscription([]byte(base64.StdEncoding.EncodeToString([]byte(list))))
	if err != nil {
		t.Fatalf("ParseSubscription(base64): %v", err)
	}
	var servers []Server
	if err := json.Unmarshal([]byte(raw), &servers); err != nil || len(servers) != 2 {
		t.Fatalf("base64 subscription = %d servers, %v", len(servers), err)
	}

	clash := "proxies:\n  - name: anytls-one\n    type: anytls\n    server: example.com\n    port: 443\n    password: secret\n    sni: example.com\n"
	raw, err = ParseSubscription([]byte(clash))
	if err != nil {
		t.Fatalf("ParseSubscription(clash): %v", err)
	}
	servers = nil
	if err := json.Unmarshal([]byte(raw), &servers); err != nil || len(servers) != 1 || servers[0].Protocol != "anytls" {
		t.Fatalf("clash subscription = %+v, %v", servers, err)
	}
	if _, err := RenderSingBoxConfig(raw); err != nil {
		t.Fatalf("RenderSingBoxConfig(anytls): %v", err)
	}

	clashHTTP := "proxies:\n  - name: http-one\n    type: http\n    server: example.com\n    port: 8080\n    username: user\n    password: pass\n"
	raw, err = ParseSubscription([]byte(clashHTTP))
	if err != nil {
		t.Fatalf("ParseSubscription(clash http): %v", err)
	}
	servers = nil
	if err := json.Unmarshal([]byte(raw), &servers); err != nil || len(servers) != 1 || servers[0].Protocol != "http" {
		t.Fatalf("clash http subscription = %+v, %v", servers, err)
	}
	if _, err := RenderSingBoxConfig(raw); err != nil {
		t.Fatalf("RenderSingBoxConfig(http): %v", err)
	}

	sip008 := `{"servers":[{"server":"example.com","server_port":8388,"password":"pass","method":"aes-256-gcm","remarks":"sip"}]}`
	raw, err = ParseSubscription([]byte(sip008))
	if err != nil {
		t.Fatalf("ParseSubscription(sip008): %v", err)
	}
	servers = nil
	if err := json.Unmarshal([]byte(raw), &servers); err != nil || len(servers) != 1 || servers[0].Protocol != "shadowsocks" {
		t.Fatalf("sip008 subscription = %+v, %v", servers, err)
	}
}

// TestOLCRTCImportsButPlanRefuses pins the honest olcrtc split: the
// parser imports the link and the credential document carries it, but
// no engine carries the protocol yet, so BuildPlan refuses it the
// same way plan validation does on the desktop path.
func TestOLCRTCImportsButPlanRefuses(t *testing.T) {
	link := "olcrtc://wbstream?datachannel@room-01#" +
		"d823fa01cb3e0609b67322f7cf984c4ee2e4ce2e294936fc24ef38c9e59f4799" + "$RU / olc free sub"
	server := importOne(t, link)
	if server.Protocol != "olcrtc" {
		t.Fatalf("protocol = %q, want olcrtc", server.Protocol)
	}
	if server.Credentials["olcrtc_provider"] != "wbstream" {
		t.Fatalf("olcrtc credential document lost the provider: %v", server.Credentials)
	}
	raw, err := ImportLinks(link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPlan(raw); err == nil || !strings.Contains(err.Error(), "olcrtc") {
		t.Fatalf("BuildPlan(olcrtc) = %v, want a refusal naming olcrtc", err)
	}
}

// TestRenderSingBoxConfigShape checks the rendered defaults: the
// local mixed proxy on DefaultLocalPort and the Proxy group as the
// route final.
func TestRenderSingBoxConfigShape(t *testing.T) {
	raw, err := ImportLinks("vless://" + testUUID + "@edge.example.com:443?security=reality&pbk=" + testPBK + "&sid=6ba85179e30d4fc2&sni=www.example.com&fp=chrome#VLESS")
	if err != nil {
		t.Fatal(err)
	}
	planRaw, err := BuildPlan(raw)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	var plan Plan
	if err := json.Unmarshal([]byte(planRaw), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Groups) != 1 || plan.Groups[0].Name != "Proxy" || len(plan.Rules) != 1 || plan.Rules[0].Target != "Proxy" {
		t.Fatalf("normalized plan lacks the Proxy group / match-all rule: %+v", plan)
	}
	cfg, err := RenderSingBoxConfig(raw)
	if err != nil {
		t.Fatalf("RenderSingBoxConfig: %v", err)
	}
	var rendered map[string]any
	if err := json.Unmarshal([]byte(cfg), &rendered); err != nil {
		t.Fatal(err)
	}
	route := rendered["route"].(map[string]any)
	if route["final"] != "Proxy" {
		t.Fatalf("route.final = %v, want Proxy", route["final"])
	}
	found := false
	for _, inbound := range rendered["inbounds"].([]any) {
		in := inbound.(map[string]any)
		if in["type"] == "mixed" && in["listen_port"] == float64(DefaultLocalPort) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no mixed inbound on %d: %s", DefaultLocalPort, cfg)
	}
}

// TestRenderRefusesXrayProfileForSingBox: an Xray profile imports and
// builds a plan, but the static sing-box catalog does not carry the
// protocol, so the render refuses it by name.
func TestRenderRefusesXrayProfileForSingBox(t *testing.T) {
	doc := `{"remarks":"P","outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"edge.example.com","port":443,` +
		`"users":[{"id":"` + testUUID + `","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls"}}]}`
	raw, err := ParseSubscription([]byte(doc))
	if err != nil {
		t.Fatalf("ParseSubscription(xray profile): %v", err)
	}
	if _, err := BuildPlan(raw); err != nil {
		t.Fatalf("BuildPlan(xray profile): %v", err)
	}
	if _, err := RenderSingBoxConfig(raw); err == nil || !strings.Contains(err.Error(), "xray-profile") {
		t.Fatalf("RenderSingBoxConfig(xray profile) = %v, want a refusal naming xray-profile", err)
	}
}

// TestRefusals covers the fail-closed edges: empty and garbage input,
// a link family the parser itself refuses, and a hand-made document
// with an out-of-range port.
func TestRefusals(t *testing.T) {
	if _, err := ImportLinks(""); err == nil {
		t.Fatal("ImportLinks(empty) must fail")
	}
	if _, err := ParseSubscription([]byte("not a subscription at all")); err == nil {
		t.Fatal("ParseSubscription(garbage) must fail")
	}
	if _, err := ImportLinks("hysteria2://secret@example.com:443?pinSHA256=abcd#H"); err == nil {
		t.Fatal("a pinSHA256 hy2 link must be refused, as the parser refuses it")
	}
	if _, err := BuildPlan(`{"servers":[{"id":"x","protocol":"vless","server":"example.com","port":70000}]}`); err == nil {
		t.Fatal("BuildPlan must refuse an out-of-range port")
	}
	if _, err := BuildPlan(""); err == nil {
		t.Fatal("BuildPlan(empty) must fail")
	}
}

// TestEngineInfo checks the catalog JSON carries all three engines
// with versions, protocols and the default preference.
func TestEngineInfo(t *testing.T) {
	raw := EngineInfo()
	var info struct {
		Engines []struct {
			Kind       string   `json:"kind"`
			MinVersion string   `json:"min_version"`
			Protocols  []string `json:"protocols"`
			Features   []string `json:"features"`
		} `json:"engines"`
		DefaultPreference []string `json:"default_preference"`
	}
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		t.Fatalf("EngineInfo is not JSON: %v", err)
	}
	if len(info.Engines) != 3 {
		t.Fatalf("engines = %d, want 3: %s", len(info.Engines), raw)
	}
	for _, entry := range info.Engines {
		if entry.MinVersion == "" || len(entry.Protocols) == 0 || len(entry.Features) == 0 {
			t.Fatalf("engine entry is incomplete: %+v", entry)
		}
	}
	if len(info.DefaultPreference) == 0 || info.DefaultPreference[0] != "sing-box" {
		t.Fatalf("default_preference = %v", info.DefaultPreference)
	}
}
