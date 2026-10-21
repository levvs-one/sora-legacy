package control

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/parser"
)

// TestOlcrtcVaultSurvivesRestart is the legacy form of sora's vault
// round-trip: a link is imported, its credential document is stored,
// and everything the link carried — provider, room, transport, key,
// every non-default transport parameter — must still be in the
// document after a restart. Before this fix the document held only
// the key and "security", the same loss sora's import review found
// (IMPORT-REVIEW Z-7): outboundToProto has no proto field for the
// provider or the parameters, so the vault is the only place they
// can survive.
func TestOlcrtcVaultSurvivesRestart(t *testing.T) {
	links := []string{
		`olcrtc://wbstream?seichannel<fps=60&batch=64&frag=900&ack-ms=2000>@room-01#d823fa01cb3e0609b67322f7cf984c4ee2e4ce2e294936fc24ef38c9e59f4799$DE / olc free sub`,
		`olcrtc://jitsi?datachannel@https://meet.example.org/myroom#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa$RU`,
		`olcrtc://telemost?videochannel<video-w=1080&video-h=1080&video-fps=60&video-codec=tile&video-tile-module=4&video-tile-rs=20>@room-9#0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef$MIMO`,
		`olcrtc://wbstream?vp8channel<vp8-fps=25&vp8-batch=1>@room-2#` + strings.Repeat("b", 64),
		`olcrtc://wbstream?seichannel<fps=60&future-x=7>@room-01#d823fa01cb3e0609b67322f7cf984c4ee2e4ce2e294936fc24ef38c9e59f4799`,
	}
	for _, link := range links {
		t.Run(link[:24], func(t *testing.T) {
			result, err := parser.LinkParser{}.Parse([]byte(link))
			if err != nil || len(result.Servers) != 1 {
				t.Fatalf("parse: %v (%d servers)", err, len(result.Servers))
			}
			spec := result.Servers[0]
			doc, err := credentialDocument(spec)
			if err != nil {
				t.Fatal(err)
			}
			var values map[string]string
			if err := json.Unmarshal(doc, &values); err != nil {
				t.Fatal(err)
			}
			if values["olcrtc_provider"] != spec.Options["olcrtc_provider"] ||
				values["olcrtc_room"] != spec.Options["olcrtc_room"] ||
				values["olcrtc_transport"] != spec.Transport ||
				values["password"] != spec.Password {
				t.Fatalf("document lost identity fields: %s", doc)
			}
			// Every transport parameter of the link rides as one
			// JSON document, exactly the non-olcrtc_* options.
			params := map[string]string{}
			for k, v := range spec.Options {
				if strings.HasPrefix(k, "olcrtc_") {
					continue
				}
				params[k] = v
			}
			if len(params) == 0 {
				if values["olcrtc_params"] != "" {
					t.Errorf("params document for a parameterless link: %s", values["olcrtc_params"])
				}
			} else {
				var stored map[string]string
				if err := json.Unmarshal([]byte(values["olcrtc_params"]), &stored); err != nil {
					t.Fatalf("params not stored as JSON: %v (doc %s)", err, doc)
				}
				if !reflect.DeepEqual(stored, params) {
					t.Errorf("stored params = %v, want %v", stored, params)
				}
			}
			// The document must pass the vault's own gate: every
			// olcrtc_* key is in the credentialKeys allowlist, so
			// parseCredential accepts it instead of dropping fields.
			if _, err := parseCredential(doc); err != nil {
				t.Fatalf("stored document rejected by parseCredential: %v", err)
			}
			// The document is deterministic: rebuilding it from the
			// same spec is byte-identical.
			if doc2, err := credentialDocument(spec); err != nil || string(doc2) != string(doc) {
				t.Fatalf("document not deterministic: %v", err)
			}
			// Identity survives: the same reference is derived, so a
			// re-import after restart overwrites instead of
			// duplicating the entry.
			reference, err := referenceOf(spec)
			if err != nil {
				t.Fatal(err)
			}
			if again, err := referenceOf(spec); err != nil || again != reference {
				t.Fatalf("reference drifted: %q vs %q (%v)", again, reference, err)
			}
		})
	}
}

// TestOlcrtcVaultKeepsSubscriptionMeta: the ## block of a
// subscription (name/icon/usage) rides the document too, so the
// metadata an import attached to the server is not dropped by the
// vault even though no engine reads it today.
func TestOlcrtcVaultKeepsSubscriptionMeta(t *testing.T) {
	body := "#name: Free\n\nolcrtc://wbstream?datachannel@abc123xyz#" + strings.Repeat("a", 64) + "$DE\n##name: DE-Backup\n##icon: flag\n##used: 500mb/10gb\n"
	result, err := parser.LinkParser{}.Parse([]byte(body))
	if err != nil || len(result.Servers) != 1 {
		t.Fatalf("parse: %v (%d servers)", err, len(result.Servers))
	}
	doc, err := credentialDocument(result.Servers[0])
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]string
	if err := json.Unmarshal(doc, &values); err != nil {
		t.Fatal(err)
	}
	var meta map[string]string
	if err := json.Unmarshal([]byte(values["olcrtc_meta"]), &meta); err != nil {
		t.Fatalf("meta not stored as JSON: %v (doc %s)", err, doc)
	}
	if meta["icon"] != "flag" || meta["used"] != "500mb/10gb" {
		t.Fatalf("meta = %v", meta)
	}
}

// TestOlcrtcLaunchIsRefusedHonestly pins the transport boundary of
// the parity work: legacy has no olcrtc transport, so an imported
// olcrtc server must fail at plan validation with a clear
// unknown-protocol error — never silently run, never panic. The
// mechanism is the existing one (engine validProtocols whitelist,
// reached from planFromProto via Plan.Validate), not a new marker.
func TestOlcrtcLaunchIsRefusedHonestly(t *testing.T) {
	link := `olcrtc://wbstream?seichannel<fps=60>@room-01#d823fa01cb3e0609b67322f7cf984c4ee2e4ce2e294936fc24ef38c9e59f4799$DE`
	result, err := parser.LinkParser{}.Parse([]byte(link))
	if err != nil || len(result.Servers) != 1 {
		t.Fatalf("parse: %v (%d servers)", err, len(result.Servers))
	}
	spec := result.Servers[0]
	doc, err := credentialDocument(spec)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := referenceOf(spec)
	if err != nil {
		t.Fatal(err)
	}
	secrets := mapResolver{data: map[string][]byte{reference: doc}}
	outbound, err := outboundFromProto(0, outboundToProto(spec, reference), secrets)
	if err != nil {
		t.Fatal(err)
	}
	if outbound.Protocol != engine.Protocol("olcrtc") {
		t.Fatalf("protocol = %q, want olcrtc carried through to validation", outbound.Protocol)
	}
	err = outbound.Validate()
	if err == nil || !strings.Contains(err.Error(), `unknown protocol "olcrtc"`) {
		t.Fatalf("outbound validation = %v, want a clear unknown-protocol refusal", err)
	}
	plan := &engine.Plan{SessionID: "s", Outbounds: []engine.Outbound{outbound}}
	if err := plan.Validate(); err == nil || !strings.Contains(err.Error(), `unknown protocol "olcrtc"`) {
		t.Fatalf("plan validation = %v, want the same refusal at plan level", err)
	}
}
