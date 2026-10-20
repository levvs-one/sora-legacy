package control

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
	"github.com/levvs-one/sora-client/core/secret"
	"github.com/levvs-one/sora-client/core/session"
)

// BenchmarkPlanFromProto200 measures the Connect admit path for a large
// plan: 200 outbounds and 200 routing rules through planFromProto.
func BenchmarkPlanFromProto200(b *testing.B) {
	in := &corev1.SessionPlan{
		TunnelMode: corev1.TunnelMode_TUNNEL_MODE_SYSTEM,
	}
	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("srv-%d", i)
		in.Outbounds = append(in.Outbounds, &corev1.OutboundSpec{Id: id, Protocol: "direct"})
		in.Routes = append(in.Routes, &corev1.RoutingRule{
			Destination: fmt.Sprintf("domain:host-%d.example.org", i),
			OutboundId:  id,
		})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plan, err := planFromProto(in, "bench", nil)
		if err != nil {
			b.Fatal(err)
		}
		if len(plan.Outbounds) != 200 || len(plan.Rules) < 200 {
			b.Fatalf("plan = %d outbounds, %d rules", len(plan.Outbounds), len(plan.Rules))
		}
	}
}

// BenchmarkParseImport200 measures the import path end to end: 200 trojan
// links parsed and stored through ParseImport.
func BenchmarkParseImport200(b *testing.B) {
	names := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		names = append(names, fmt.Sprintf("srv-%d", i))
	}
	payload := []byte(servers(names...))
	store, err := secret.Open(b.TempDir(), secret.Options{Protector: secret.FileProtector{}})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.Close() })
	auth, err := NewAuthenticator(make([]byte, TokenLen))
	if err != nil {
		b.Fatal(err)
	}
	sessions := session.NewManager(session.ManagerConfig{
		TunUp: func(context.Context, string) error { return nil },
		Factory: func(context.Context, *engine.Plan) (engine.Engine, error) {
			return nil, errors.New("bench starts no session")
		},
	})
	srv, err := New(Config{Authenticator: auth, Secrets: store, Sessions: sessions})
	if err != nil {
		b.Fatal(err)
	}
	req := &corev1.ParseImportRequest{Payload: payload, ApiVersion: srv.apiVersion()}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := srv.ParseImport(context.Background(), req)
		if err != nil || resp.GetError() != nil || len(resp.GetSessionPlan().GetOutbounds()) != 200 {
			b.Fatalf("import = %v, %v", resp, err)
		}
	}
}
