package control

import (
	"context"
	"strings"
	"sync"
	"testing"

	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
	"github.com/levvs-one/sora-client/core/subscription"
)

// fallbackPanel records the FetchOptions of every fetch and answers
// like a fetcher that fell back: UsedFallback set, fallback body.
type fallbackPanel struct {
	mu       sync.Mutex
	lastOpts subscription.FetchOptions
	calls    int
}

func (p *fallbackPanel) Fetch(_ context.Context, _ string, opts subscription.FetchOptions) (subscription.Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	p.lastOpts = opts
	return subscription.Result{Body: []byte(servers("backup")), UsedFallback: opts.FallbackURL != ""}, nil
}

// W2 wiring: a link's #fallback-url fragment is split at save time,
// stored beside the primary, handed to the fetcher on refresh, and
// round-tripped by GetSubscriptionLink — all through the existing
// contract, no new RPC.
func TestSubscriptionFallbackLinkPartsAndRefresh(t *testing.T) {
	primary, fallback, err := subscriptionLinkParts(
		"https://panel.example/sub/abc#fallback-url=https%3A%2F%2Fbackup.example%2Fsub%2Fxyz")
	if err != nil {
		t.Fatal(err)
	}
	if primary != "https://panel.example/sub/abc" || fallback != "https://backup.example/sub/xyz" {
		t.Fatalf("parts = %q / %q", primary, fallback)
	}
	// A fallback over plain HTTP is refused at save time, like a primary.
	if _, _, err := subscriptionLinkParts(
		"https://panel.example/sub/abc#fallback-url=http://backup.example/sub/xyz"); err == nil {
		t.Fatal("plain-HTTP fallback must be refused")
	}

	p := &fallbackPanel{}
	srv, _ := bookServer(t, t.TempDir(), p)
	state := saveAndWait(t, srv.subs, &corev1.SubscriptionSettings{
		Url: "https://panel.example/sub/abc#fallback-url=https://backup.example/sub/xyz",
	})
	id := state.GetSettings().GetId()
	rec := srv.subs.records[id]
	if rec.URL != "https://panel.example/sub/abc" || rec.FallbackURL != "https://backup.example/sub/xyz" {
		t.Fatalf("record = %q / %q", rec.URL, rec.FallbackURL)
	}
	if got := rec.storedLink(); got != "https://panel.example/sub/abc#fallback-url=https%3A%2F%2Fbackup.example%2Fsub%2Fxyz" {
		t.Fatalf("storedLink = %q, want the pasted form back", got)
	}
	if p.lastOpts.FallbackURL != "https://backup.example/sub/xyz" {
		t.Fatalf("fetcher options = %+v, want the stored fallback", p.lastOpts)
	}
	if len(state.GetOutbounds()) != 1 || !strings.Contains(state.GetOutbounds()[0].GetDisplayName(), "backup") {
		t.Fatalf("state = %v, want the fallback body servers", state.GetOutbounds())
	}
}
