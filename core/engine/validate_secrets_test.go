package engine

import (
	"slices"
	"strings"
	"testing"
)

// REVIEW-SP45 §6: the redactor seeds were incomplete in two places
// the reference (sora) covers. Identifiers missed the transport's
// fronting Host and gRPC Service — the same class of infrastructure
// identifier as the download address SP4 added. Secrets missed the
// transport Path and the custom header values entirely — the
// providers' "secret path" bearer pattern (CENSOR-LEAK in sora).
// Both lists are ported to the reference's composition here; the
// fields the reference has and legacy's types do not (Outbound.Token,
// TLS.RealityMLDSA65Verify, Transport.GRPCAuthority,
// Amnezia.HeaderProtectionKey) are generational and stay absent.

func TestIdentifiersCoverTransportHostAndService(t *testing.T) {
	o := Outbound{
		ID: "o", Name: "O", Protocol: ProtocolVLESS,
		Server: "edge.example.com", Port: 443,
		Transport: Transport{
			Type:    "grpc",
			Host:    "secret-cdn-host.example.com",
			Service: "secret-grpc-service",
		},
	}
	ids := o.Identifiers()
	for _, want := range []string{"secret-cdn-host.example.com", "secret-grpc-service"} {
		if !slices.Contains(ids, want) {
			t.Errorf("Identifiers() must contain %q, got %v", want, ids)
		}
	}
	// The reference's order: after the name, before the download
	// address — the seed order redactor registration observes.
	name := slices.Index(ids, "O")
	host := slices.Index(ids, "secret-cdn-host.example.com")
	service := slices.Index(ids, "secret-grpc-service")
	if !(name >= 0 && name < host && host < service) {
		t.Errorf("Identifiers() order = %v, want name < host < service", ids)
	}
}

func TestSecretsCoverTransportPathAndHeaders(t *testing.T) {
	o := Outbound{
		ID: "o", Name: "O", Protocol: ProtocolVLESS,
		Server: "edge.example.com", Port: 443,
		Transport: Transport{
			Type: "ws",
			Path: "/secret-path-token",
			Headers: map[string]string{
				"Host":       "cdn.example.com",
				"X-Auth":     "header-secret-value",
				"User-Agent": "agent-string-value",
			},
		},
	}
	secrets := o.Secrets()
	for _, want := range []string{"/secret-path-token", "header-secret-value", "agent-string-value", "cdn.example.com"} {
		if !slices.Contains(secrets, want) {
			t.Errorf("Secrets() must contain %q, got %v", want, secrets)
		}
	}
	// Deterministic across runs even though Headers is a map: the
	// values join in sorted key order.
	for i := 0; i < 5; i++ {
		if again := o.Secrets(); !slices.Equal(again, secrets) {
			t.Fatalf("Secrets() is not deterministic: %v vs %v", again, secrets)
		}
	}
}

// TestRedactorMasksTransportSeeds is the through-probe the review
// asked for: a plan whose outbound carries the fields above, seeded
// into a redactor exactly the way Supervisor.Apply seeds it
// (Secrets + Identifiers), must mask a log line quoting any of them.
func TestRedactorMasksTransportSeeds(t *testing.T) {
	plan := validPlan()
	plan.Outbounds[0].Transport = Transport{
		Type:    "grpc",
		Path:    "/secret-path-token",
		Host:    "secret-cdn-host.example.com",
		Service: "secret-grpc-service",
		Headers: map[string]string{"X-Auth": "header-secret-value"},
	}
	redactor := NewRedactor()
	redactor.Add(plan.Secrets()...)
	redactor.Add(plan.Identifiers()...)
	line := "dial grpc secret-grpc-service via secret-cdn-host.example.com path=/secret-path-token auth=header-secret-value"
	masked := redactor.String(line)
	for _, leak := range []string{"secret-grpc-service", "secret-cdn-host.example.com", "/secret-path-token", "header-secret-value"} {
		if strings.Contains(masked, leak) {
			t.Errorf("%q survived redaction: %q", leak, masked)
		}
	}
}

// The profile half of the composition port: profile credential keys
// are matched in normalized form (the reference's CENSOR-LEAK fix),
// so spelling variants and fields the old exact-spelling map never
// listed (token, uuid, access_token) are extracted, and the
// profile's own server identifiers join Identifiers.
func TestProfileSeedsCoverVariantSpellingsAndIdentifiers(t *testing.T) {
	o := Outbound{ID: "p", Protocol: ProtocolXrayProfile, Profile: []byte(
		`{"outbounds":[{"settings":{"vnext":[{"address":"profile-edge.example.com","users":[{"id":"9f1c2d3e-aaaa-bbbb-cccc-0123456789ab","access_token":"profile-token-value"}]}]},` +
			`"streamSettings":{"security":"reality","realitySettings":{"dest":"profile-dest.example.com:443","serverNames":["profile-sni.example.com"]}}}]}`)}
	secrets := o.Secrets()
	for _, want := range []string{"9f1c2d3e-aaaa-bbbb-cccc-0123456789ab", "profile-token-value"} {
		if !slices.Contains(secrets, want) {
			t.Errorf("Secrets() must contain the profile value %q, got %v", want, secrets)
		}
	}
	ids := o.Identifiers()
	for _, want := range []string{"profile-edge.example.com", "profile-dest.example.com:443", "profile-sni.example.com"} {
		if !slices.Contains(ids, want) {
			t.Errorf("Identifiers() must contain the profile value %q, got %v", want, ids)
		}
	}
	for i := 0; i < 5; i++ {
		if again := o.Secrets(); !slices.Equal(again, secrets) {
			t.Fatalf("profile Secrets() is not deterministic: %v vs %v", again, secrets)
		}
		if again := o.Identifiers(); !slices.Equal(again, ids) {
			t.Fatalf("profile Identifiers() is not deterministic: %v vs %v", again, ids)
		}
	}
}
