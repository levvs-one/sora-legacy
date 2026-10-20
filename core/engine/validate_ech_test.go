package engine

import (
	"slices"
	"strings"
	"testing"
)

// The tests in this file are ported from sora's validate_ech_test.go
// (S5-SP5), with one deliberate inversion, marked at
// TestECHPlanRequiresFeatureECH: sora's engines all render ECH and
// claim FeatureECH, legacy's render none of it and claim nothing —
// the gate must therefore refuse an ECH plan everywhere here.
// TestValidateKeyShare comes from sora's reality_test.go, which
// legacy does not have as a file.
//
// ECH honesty rules: ECH must never silently degrade into leaking
// the very name it is supposed to hide.

func echOutbound() Outbound {
	return Outbound{
		ID:       "ech1",
		Protocol: ProtocolVLESS,
		Server:   "203.0.113.7",
		Port:     443,
		TLS: TLS{
			Enabled:    true,
			ServerName: "example.com",
			ECH:        ECHConfig{Enabled: true},
		},
	}
}

func TestValidateRejectsECHWithoutTLS(t *testing.T) {
	o := echOutbound()
	o.TLS.Enabled = false
	if err := o.Validate(); err == nil || !strings.Contains(err.Error(), "ECH is enabled but TLS is not") {
		t.Errorf("Validate = %v, want ECH-without-TLS error", err)
	}
}

func TestValidateRejectsECHWithReality(t *testing.T) {
	o := echOutbound()
	o.TLS.Reality = true
	if err := o.Validate(); err == nil || !strings.Contains(err.Error(), "incompatible") {
		t.Errorf("Validate = %v, want ECH+REALITY incompatibility error", err)
	}
}

func TestValidateRejectsGarbagePinnedECHConfig(t *testing.T) {
	// A pinned list validation cannot decode must fail here, not as
	// an engine startup refusal or a silently unparseable config.
	o := echOutbound()
	o.TLS.ECH.Config = []string{"!!! not a config !!!"}
	if err := o.Validate(); err == nil || !strings.Contains(err.Error(), "ech:") {
		t.Errorf("Validate = %v, want an ech decode error", err)
	}
}

func TestValidateAcceptsECHQueryServerName(t *testing.T) {
	// QueryServerName is not rejected: it is plan data for the ECH
	// DNS query. What keeps an ECH plan off engines that cannot
	// honour it is the FeatureECH gate below, not validation.
	o := echOutbound()
	o.TLS.ECH.QueryServerName = "ech.example.com"
	if err := o.Validate(); err != nil {
		t.Errorf("Validate = %v, want nil for a query_server_name", err)
	}
}

func TestECHPlanRequiresFeatureECH(t *testing.T) {
	// An ECH plan must route only to engines whose renderer emits
	// ECH. No legacy renderer does, so — inverted from sora, whose
	// pins all claim the feature — every legacy catalog entry must
	// report it missing: the plan fails selection instead of sending
	// the SNI in the clear.
	p := &Plan{SessionID: "s1", Outbounds: []Outbound{echOutbound()}}
	if !p.RequiredFeatures()[FeatureECH] {
		t.Fatal("an ECH-enabled plan must require feature ech")
	}
	for _, kind := range []Kind{KindSingBox, KindMihomo, KindXray} {
		if missing := Catalog[kind].Missing(p); !slices.Contains(missing, "feature "+string(FeatureECH)) {
			t.Errorf("%s must not carry an ECH plan (no renderer emits ECH), got missing %v", kind, missing)
		}
	}
}

func TestValidateRejectsECHBootstrapOverPlaintextDNS(t *testing.T) {
	p := &Plan{
		SessionID: "s1",
		Outbounds: []Outbound{echOutbound()},
		DNS: DNS{
			Enabled: true,
			Servers: []DNSServer{{Tag: "dns-1", Transport: DNSPlain, Address: "8.8.8.8", Port: 53}},
		},
	}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "no encrypted DNS transport") {
		t.Errorf("Validate = %v, want encrypted-DNS bootstrap error", err)
	}
}

func TestValidateRejectsECHBootstrapWithoutDNS(t *testing.T) {
	p := &Plan{SessionID: "s1", Outbounds: []Outbound{echOutbound()}}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "no encrypted DNS transport") {
		t.Errorf("Validate = %v, want encrypted-DNS bootstrap error", err)
	}
}

func TestValidateAcceptsECHWithEncryptedDNS(t *testing.T) {
	p := &Plan{
		SessionID: "s1",
		Outbounds: []Outbound{echOutbound()},
		DNS: DNS{
			Enabled: true,
			Servers: []DNSServer{{Tag: "dns-1", Transport: DNSHTTPS, Address: "1.1.1.1"}},
		},
	}
	if err := p.Validate(); err != nil {
		t.Errorf("Validate = %v, want nil for ECH with DoH", err)
	}
}

func TestValidateAcceptsECHWithPinnedConfig(t *testing.T) {
	// A pinned ECHConfigList skips the DNS lookup entirely, so plaintext
	// DNS is irrelevant.
	o := echOutbound()
	// A complete (if tiny) pinned list: armor plus a base64 body.
	// Validation decodes the pin, so a bare BEGIN line is honestly
	// rejected as undecodable (see TestValidateRejectsGarbagePinnedECHConfig).
	o.TLS.ECH.Config = []string{"-----BEGIN ECHCONFIG-----", "QUJD", "-----END ECHCONFIG-----"}
	p := &Plan{
		SessionID: "s1",
		Outbounds: []Outbound{o},
		DNS: DNS{
			Enabled: true,
			Servers: []DNSServer{{Tag: "dns-1", Transport: DNSPlain, Address: "8.8.8.8", Port: 53}},
		},
	}
	if err := p.Validate(); err != nil {
		t.Errorf("Validate = %v, want nil for ECH with pinned config", err)
	}
}

func TestValidateAcceptsDisabledECH(t *testing.T) {
	o := echOutbound()
	o.TLS.ECH = ECHConfig{}
	p := &Plan{
		SessionID: "s1",
		Outbounds: []Outbound{o},
		DNS: DNS{
			Enabled: true,
			Servers: []DNSServer{{Tag: "dns-1", Transport: DNSPlain, Address: "8.8.8.8", Port: 53}},
		},
	}
	if err := p.Validate(); err != nil {
		t.Errorf("Validate = %v, want nil when ECH is off", err)
	}
}

// keyShareRealityOutbound is a valid REALITY outbound for the
// KeyShare vectors (the same 32-byte base64url key the S5 parity
// vectors use).
func keyShareRealityOutbound() Outbound {
	o := Outbound{ID: "r1", Protocol: ProtocolVLESS, Server: "r.example.com", Port: 443}
	o.TLS.Enabled = true
	o.TLS.Reality = true
	o.TLS.RealityPublicKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	o.TLS.RealityShortID = "ab12"
	o.TLS.ServerName = "cdn.example.com"
	o.Transport.Type = "tcp"
	return o
}

// TestValidateKeyShare pins the plan knob: only "classical"/"hybrid",
// and only on a REALITY outbound.
func TestValidateKeyShare(t *testing.T) {
	for _, ks := range []string{"", "classical", "hybrid"} {
		o := keyShareRealityOutbound()
		o.TLS.KeyShare = ks
		if err := o.Validate(); err != nil {
			t.Errorf("KeyShare %q on REALITY: Validate = %v, want nil", ks, err)
		}
	}
	o := keyShareRealityOutbound()
	o.TLS.KeyShare = "post-quantum-ish"
	if err := o.Validate(); err == nil || !strings.Contains(err.Error(), "key_share") {
		t.Errorf("unknown KeyShare: Validate = %v, want a key_share error", err)
	}
	o = keyShareRealityOutbound()
	o.TLS.Reality = false
	o.TLS.KeyShare = "hybrid"
	if err := o.Validate(); err == nil || !strings.Contains(err.Error(), "key_share needs REALITY") {
		t.Errorf("KeyShare without REALITY: Validate = %v, want a key_share error", err)
	}
	// A KeyShare plan must also fail engine selection everywhere:
	// no legacy renderer spells the knob.
	p := &Plan{SessionID: "s1", Outbounds: []Outbound{keyShareRealityOutbound()}}
	p.Outbounds[0].TLS.KeyShare = "hybrid"
	if !p.RequiredFeatures()[FeatureRealityKeyShare] {
		t.Fatal("a KeyShare plan must require feature reality-key-share")
	}
	for _, kind := range []Kind{KindSingBox, KindMihomo, KindXray} {
		if missing := Catalog[kind].Missing(p); !slices.Contains(missing, "feature "+string(FeatureRealityKeyShare)) {
			t.Errorf("%s must not carry a KeyShare plan (no renderer spells it), got missing %v", kind, missing)
		}
	}
}
