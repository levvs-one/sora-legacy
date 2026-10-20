package control

import (
	"testing"
	"time"

	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
	"github.com/levvs-one/sora-client/core/subscription"
)

// W2 wiring: a stored override file (the form the sora RPC writes and
// a future legacy RPC will write) is applied to the subscription
// state the existing contract already serves, and deleting the
// subscription removes the file.
func TestSubscriptionStateAppliesStoredOverride(t *testing.T) {
	dir := t.TempDir()
	const id = "0123456789abcdef"
	store := subscription.NewOverrideStore(dir)
	if err := store.Save(id, &subscription.Override{
		Renames: map[string]string{"s1": "Home"},
		Hidden:  []string{"s2"},
	}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{dataDir: dir}
	b := &subscriptionBook{
		srv:       srv,
		now:       time.Now,
		overrides: store,
		records: map[string]*subscriptionRecord{
			id: {ID: id, URL: "https://panel.example.com/sub", Created: time.Now()},
		},
		lists: map[string][]*corev1.OutboundSpec{
			id: {{Id: "s1", DisplayName: "One"}, {Id: "s2", DisplayName: "Two"}},
		},
		updating: map[string]bool{},
		watchers: map[chan *corev1.SubscriptionState]struct{}{},
		wake:     make(chan struct{}, 1),
	}
	state := b.stateLocked(id)
	if len(state.GetOutbounds()) != 1 || state.GetOutbounds()[0].GetDisplayName() != "Home" {
		t.Fatalf("state outbounds = %v, want one renamed Home", state.GetOutbounds())
	}
}
