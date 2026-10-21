package control

import (
	"fmt"

	"github.com/levvs-one/sora-client/core/engine"
	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
	"github.com/levvs-one/sora-client/core/parser"
)

// This file is the additive, exported seam the mobile facade
// (core/mobileapi) builds on. It wraps the exact unexported import ->
// credential document -> plan pipeline ParseImport and planFromProto
// run, so a gomobile consumer reuses this package's blob resolution,
// credential packing and plan validation instead of reimplementing
// them (and drifting from them) in a second place. Nothing here
// changes the behaviour of the existing callers.

// CredentialDocument serializes one parsed server into the flat
// credential document credentialDocument writes to the vault: only
// known keys, only non-empty values, with sing-box/Clash option blobs
// resolved onto the typed fields first (S5-SP6) and WireGuard and
// olcrtc material packed in its documented shapes.
func CredentialDocument(spec parser.OutboundSpec) ([]byte, error) {
	return credentialDocument(spec)
}

// ReferenceFor returns the stable vault reference referenceOf derives
// from a server's identity. Re-imports of the same server produce the
// same reference.
func ReferenceFor(spec parser.OutboundSpec) (string, error) {
	return referenceOf(spec)
}

// OutboundWireSpec converts a parsed server to its control-plane
// wire form (outboundToProto): the endpoint, protocol, transport and
// security a client sees, plus the credential reference it resolves
// credentials through when a plan is built.
func OutboundWireSpec(spec parser.OutboundSpec, reference string) *corev1.OutboundSpec {
	return outboundToProto(spec, reference)
}

// MapDocuments adapts an in-memory reference -> credential document
// map to the resolver planFromProto consumes. Hosts that keep
// credentials in the vault pass the secret store instead; the mobile
// facade has no vault, so its documents travel with the request.
type MapDocuments map[string][]byte

// Get returns the document stored under reference.
func (m MapDocuments) Get(reference string) ([]byte, error) {
	document, ok := m[reference]
	if !ok {
		return nil, fmt.Errorf("control: no credential document for reference %q", reference)
	}
	return document, nil
}

// BuildEnginePlan validates a session plan and resolves its
// credential references from documents, exactly as the Connect path
// does through planFromProto. The returned plan is engine-native and
// carries the resolved credentials; it is never serialized back to a
// client by this package.
func BuildEnginePlan(in *corev1.SessionPlan, sessionID string, documents map[string][]byte) (*engine.Plan, error) {
	return planFromProto(in, sessionID, MapDocuments(documents))
}
