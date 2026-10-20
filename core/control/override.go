package control

// User overrides on top of subscriptions. Overrides re-apply after every
// refresh so renames, hidden servers and pinned order survive provider
// updates. A corrupt override file is logged and ignored: the update must
// never fail because of user edits.
//
// Ported from sora (snapshot 142397c5) without the Save/Get RPC
// handlers: the legacy proto contract has no SaveSubscriptionOverride/
// GetSubscriptionOverride messages (generational gap, see
// reports/legacy-up/W-SPECS.md). The store and the application side
// live here; the write path arrives with the RPC when the contract
// grows it.

import (
	"errors"

	"google.golang.org/protobuf/proto"

	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
	"github.com/levvs-one/sora-client/core/logs"
	"github.com/levvs-one/sora-client/core/subscription"
)

// applySubscriptionOverride returns the specs with the override applied:
// hidden servers removed, renames set as display names, pinned servers
// first (stable: the rest keeps relative order). Nil override is a no-op.
func applySubscriptionOverride(specs []*corev1.OutboundSpec, o *subscription.Override) []*corev1.OutboundSpec {
	if o == nil {
		return specs
	}
	// An override with nothing in it (the common case: most subscriptions
	// carry no user edits, and a missing override file loads as an empty
	// override) changes nothing, so the shared list goes back as is
	// instead of paying a per-state copy of every spec pointer plus an
	// empty hidden map: stateLocked builds a state on every refresh,
	// save and watch broadcast. Callers treat the result as read-only.
	if len(o.Hidden) == 0 && len(o.Renames) == 0 && len(o.PinnedOrder) == 0 {
		return specs
	}
	hidden := make(map[string]bool, len(o.Hidden))
	for _, id := range o.Hidden {
		hidden[id] = true
	}
	// Copy: the input slice is shared with the stored list, filtering must
	// not rewrite its backing array.
	kept := make([]*corev1.OutboundSpec, 0, len(specs))
	for _, spec := range specs {
		id := spec.GetId()
		if hidden[id] {
			continue
		}
		if name, ok := o.Renames[id]; ok && name != "" {
			// Clone before renaming: the stored spec keeps the provider
			// name so clearing the rename restores it.
			c, ok := proto.Clone(spec).(*corev1.OutboundSpec)
			if !ok {
				continue
			}
			c.DisplayName = name
			spec = c
		}
		kept = append(kept, spec)
	}
	if len(o.PinnedOrder) == 0 {
		return kept
	}
	pinned := map[string]bool{}
	for _, id := range o.PinnedOrder {
		pinned[id] = true
	}
	out := make([]*corev1.OutboundSpec, 0, len(kept))
	for _, id := range o.PinnedOrder {
		for _, spec := range kept {
			if spec.GetId() == id {
				out = append(out, spec)
				break
			}
		}
	}
	for _, spec := range kept {
		if !pinned[spec.GetId()] {
			out = append(out, spec)
		}
	}
	return out
}

// loadOverride returns the stored override for id, logging corruption and
// continuing with an empty override.
func (b *subscriptionBook) loadOverride(id string) *subscription.Override {
	if b.overrides == nil {
		return &subscription.Override{}
	}
	o, err := b.overrides.Load(id)
	if err != nil {
		if errors.Is(err, subscription.ErrOverrideCorrupt) && b.srv.logs != nil {
			b.srv.logs.Write(b.now(), logs.LevelWarning, logs.SourceSubscription,
				"subscription overrides ignored: file is corrupt id="+id)
		}
		return &subscription.Override{}
	}
	return o
}
