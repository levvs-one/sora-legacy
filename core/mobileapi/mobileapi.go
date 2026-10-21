// Package mobileapi is the gomobile-facing facade over the legacy
// core's import, plan and sing-box render pipeline.
//
// It exists so an Android (gomobile) or iOS client can do the three
// things the desktop core does through gRPC — import servers, build a
// validated plan, render a sing-box configuration — without protobuf
// types, a vault, or a running daemon. Every public signature uses
// only string, []byte, int64, bool and error, the types gomobile can
// bind; all richer types stay inside this package.
//
// The pipeline is deliberately the desktop one, not a reimplementation:
// imports go through core/parser, credential documents are produced by
// core/control (its exported CredentialDocument wrapper, so sing-box /
// Clash option blobs, WireGuard material and olcrtc packing resolve
// exactly as in the vault), plans are built and validated by
// core/control.BuildEnginePlan (planFromProto), and rendering is
// core/engine/singbox.Render gated by the static core/engine catalog.
// No engine binary is probed or started here.
package mobileapi

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/levvs-one/sora-client/core/control"
	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/singbox"
	"github.com/levvs-one/sora-client/core/engine/supervise"
	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
	"github.com/levvs-one/sora-client/core/parser"
)

// DefaultLocalPort is the loopback mixed (HTTP+SOCKS5) port rendered
// into a sing-box configuration when the plan document does not name
// one. Mobile clients own the TUN (Android VpnService, Apple
// PacketTunnel); the rendered configuration only opens this local
// proxy inbound.
const DefaultLocalPort = 7890

// defaultControlAddr is the loopback Clash API address rendered into
// the configuration, mirroring the supervisor's loopback controller.
const defaultControlAddr = "127.0.0.1:9090"

// Server is one imported server in the JSON shape this package
// exchanges with mobile clients. Credentials holds the flat credential
// document exactly as core/control writes it to the vault (known keys
// only: uuid, password, method, user, flow, public_key, short_id,
// server_name, fingerprint, spider_x, mode, path, host_header,
// service_name, headers, alpn, security, encryption, obfs, obfs_param,
// ss_plugin, ss_plugin_opts, private_key, addresses, peers, insecure,
// xray_profile, amneziawg, the hy2/tuic tuning keys and the olcrtc_*
// keys). It is credential material: clients must store it like a
// password and never log it.
type Server struct {
	ID            string            `json:"id"`
	Name          string            `json:"name,omitempty"`
	Protocol      string            `json:"protocol"`
	Server        string            `json:"server"`
	Port          int64             `json:"port"`
	Transport     string            `json:"transport,omitempty"`
	Security      string            `json:"security,omitempty"`
	CredentialRef string            `json:"credential_ref,omitempty"`
	Credentials   map[string]string `json:"credentials,omitempty"`
}

// Plan is the JSON document BuildPlan returns and RenderSingBoxConfig
// accepts: the imported servers, the default select group "Proxy"
// holding all of them, and one match-all rule routing to it. The same
// document is the input of BuildPlan, so ImportLinks and
// ParseSubscription output (a bare JSON array of Server) can be fed
// straight back in, and a single bare Server object is accepted too.
type Plan struct {
	SessionID string   `json:"session_id,omitempty"`
	LocalPort int64    `json:"local_port,omitempty"`
	Servers   []Server `json:"servers"`
	Groups    []Group  `json:"groups,omitempty"`
	Rules     []Rule   `json:"rules,omitempty"`
}

// Group is one selectable group of the plan document.
type Group struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Members []string `json:"members"`
}

// Rule is one routing rule of the plan document.
type Rule struct {
	Type   string `json:"type"`
	Value  string `json:"value,omitempty"`
	Target string `json:"target"`
}

// ImportLinks parses share links (one per line, or any payload
// core/parser detects: base64 lists, sing-box/Xray JSON, Clash YAML,
// SIP008, WireGuard configs) and returns the servers as a JSON array
// of Server. Items the parser skips (duplicates, invalid or
// unsupported entries, e.g. a Hysteria2 pinSHA256 link or a pre-AEAD
// VMess alterId) are omitted; when nothing usable remains the import
// fails with the parser's counts instead of returning an empty array.
func ImportLinks(text string) (string, error) {
	result, err := (parser.LinkParser{}).Parse([]byte(text))
	if err != nil {
		return "", err
	}
	return serversJSON(result)
}

// ParseSubscription parses a subscription body — the bytes a provider
// answered, in any shape core/parser detects (base64 list, plain
// list, Clash YAML, sing-box JSON, SIP008, olcrtc documents) — and
// returns the servers as a JSON array of Server, in the same shape as
// ImportLinks. Fetching the subscription stays the client's job (or
// core/subscription's); this function never touches the network.
func ParseSubscription(body []byte) (string, error) {
	if _, err := (parser.ImportDetector{}).Detect(body); err != nil {
		return "", err
	}
	result, err := (parser.LinkParser{}).Parse(body)
	if err != nil {
		return "", err
	}
	return serversJSON(result)
}

// serversJSON converts a parser result into this package's Server
// array, deriving each credential document and vault reference
// through core/control so the mobile pipeline stores exactly what
// the desktop vault stores.
func serversJSON(result parser.ImportResult) (string, error) {
	if len(result.Servers) == 0 {
		return "", fmt.Errorf("mobileapi: no usable server (imported %d, invalid %d, unsupported %d, duplicates %d)",
			result.Report.Imported, result.Report.Invalid, result.Report.Unsupported, result.Report.SkippedDuplicates)
	}
	servers := make([]Server, 0, len(result.Servers))
	for _, spec := range result.Servers {
		document, err := control.CredentialDocument(spec)
		if err != nil {
			return "", err
		}
		reference, err := control.ReferenceFor(spec)
		if err != nil {
			return "", err
		}
		wire := control.OutboundWireSpec(spec, reference)
		server := Server{
			ID:        wire.GetId(),
			Name:      wire.GetDisplayName(),
			Protocol:  wire.GetProtocol(),
			Server:    wire.GetEndpoint().GetHost(),
			Port:      int64(wire.GetEndpoint().GetPort()),
			Transport: wire.GetTransport(),
			Security:  wire.GetSecurity(),
		}
		var credentials map[string]string
		if err := json.Unmarshal(document, &credentials); err != nil {
			return "", fmt.Errorf("mobileapi: credential document is not a document: %w", err)
		}
		if len(credentials) > 0 {
			server.CredentialRef = reference
			server.Credentials = credentials
		}
		servers = append(servers, server)
	}
	raw, err := json.Marshal(servers)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// parsePlanDocument accepts the three input shapes (a Plan document,
// a bare array of Server as ImportLinks returns, or one bare Server)
// and returns the normalized Plan with the default Proxy group and
// match-all rule filled in.
func parsePlanDocument(credentialJSON string) (Plan, error) {
	trimmed := strings.TrimSpace(credentialJSON)
	if trimmed == "" {
		return Plan{}, fmt.Errorf("mobileapi: empty credential document")
	}
	var plan Plan
	switch {
	case strings.HasPrefix(trimmed, "["):
		var servers []Server
		if err := json.Unmarshal([]byte(trimmed), &servers); err != nil {
			return Plan{}, fmt.Errorf("mobileapi: server array is not readable: %w", err)
		}
		plan.Servers = servers
	case strings.Contains(trimmed, "\"servers\""):
		if err := json.Unmarshal([]byte(trimmed), &plan); err != nil {
			return Plan{}, fmt.Errorf("mobileapi: plan document is not readable: %w", err)
		}
	default:
		var server Server
		if err := json.Unmarshal([]byte(trimmed), &server); err != nil {
			return Plan{}, fmt.Errorf("mobileapi: credential document is not readable: %w", err)
		}
		plan.Servers = []Server{server}
	}
	if len(plan.Servers) == 0 {
		return Plan{}, fmt.Errorf("mobileapi: the document carries no servers")
	}
	if plan.SessionID == "" {
		plan.SessionID = "mobile"
	}
	if plan.LocalPort == 0 {
		plan.LocalPort = DefaultLocalPort
	}
	if plan.LocalPort < 1 || plan.LocalPort > 65535 {
		return Plan{}, fmt.Errorf("mobileapi: local_port %d is not a port", plan.LocalPort)
	}
	for _, server := range plan.Servers {
		if server.ID == "" {
			return Plan{}, fmt.Errorf("mobileapi: a server has no id; build documents with ImportLinks or ParseSubscription")
		}
		if server.Port < 0 || server.Port > 65535 {
			return Plan{}, fmt.Errorf("mobileapi: server %q has port %d, which is not a port", server.ID, server.Port)
		}
	}
	return plan, nil
}

// buildEnginePlan turns a plan document into a validated engine plan
// through core/control, then attaches the default Proxy group and
// match-all rule and validates the whole again. The plan is an
// application-mode plan: no TUN (the mobile OS owns it) and the local
// mixed proxy enabled, as planFromProto derives for that mode.
func buildEnginePlan(credentialJSON string) (Plan, *engine.Plan, error) {
	doc, err := parsePlanDocument(credentialJSON)
	if err != nil {
		return Plan{}, nil, err
	}
	documents := make(map[string][]byte, len(doc.Servers))
	wire := &corev1.SessionPlan{
		TunnelMode: corev1.TunnelMode_TUNNEL_MODE_APPLICATION,
		// The rendered configuration carries a loopback Clash API
		// the owning mobile client controls, so the plan does not
		// demand the desktop daemon's private (socket-only) control
		// channel; without this, planFromProto marks every plan
		// PrivateControl and the sing-box catalog — which claims no
		// private control — refuses all of them.
		NetworkControlAllowed: true,
	}
	for _, server := range doc.Servers {
		// The transport passes through verbatim: the parser spells
		// a WireGuard spec's transport "udp", which is not a plan
		// transport, and control.BuildEnginePlan (outboundFromProto)
		// normalizes the WireGuard producer spellings to the plan's
		// empty transport — the canonical fix lives there, so this
		// facade needs no local normalization of its own.
		spec := &corev1.OutboundSpec{
			Id:          server.ID,
			DisplayName: server.Name,
			Protocol:    server.Protocol,
			Transport:   server.Transport,
			Security:    server.Security,
			Endpoint:    &corev1.Endpoint{Host: server.Server, Port: uint32(server.Port)}, //nolint:gosec // parsePlanDocument bounds Port to 0-65535
		}
		if len(server.Credentials) > 0 {
			reference := server.CredentialRef
			if reference == "" {
				reference = "mobile:" + server.ID
			}
			raw, err := json.Marshal(server.Credentials)
			if err != nil {
				return Plan{}, nil, err
			}
			documents[reference] = raw
			spec.Credentials = &corev1.CredentialsRef{Reference: reference}
		}
		wire.Outbounds = append(wire.Outbounds, spec)
	}
	plan, err := control.BuildEnginePlan(wire, doc.SessionID, documents)
	if err != nil {
		return Plan{}, nil, err
	}
	ids := make([]string, 0, len(plan.Outbounds))
	profile := false
	for _, outbound := range plan.Outbounds {
		ids = append(ids, outbound.ID)
		if outbound.Protocol == engine.ProtocolXrayProfile {
			profile = true
		}
	}
	if profile {
		// An Xray profile runs alone: plan validation refuses groups
		// or rules beside it, and its own routing decides the final
		// outbound, so the document carries neither.
		doc.Groups, doc.Rules = nil, nil
	} else {
		plan.Groups = []engine.Group{{Name: "Proxy", Type: engine.GroupSelect, Outbounds: ids}}
		plan.Rules = []engine.Rule{{Type: engine.RuleMatchAll, Target: "Proxy"}}
		doc.Groups = []Group{{Name: "Proxy", Type: "select", Members: ids}}
		doc.Rules = []Rule{{Type: "all", Target: "Proxy"}}
	}
	if err := plan.Validate(); err != nil {
		return Plan{}, nil, err
	}
	return doc, plan, nil
}

// BuildPlan validates a credential document (see Plan for the shape)
// and returns it normalized: session and local-port defaults applied,
// the Proxy group and match-all rule filled in. A document that the
// control plane would refuse — an unknown protocol such as olcrtc
// (imported honestly, but no engine carries it yet), a REALITY
// outbound without its public key, a malformed credential document —
// fails here with that refusal, not later on the device.
func BuildPlan(credentialJSON string) (string, error) {
	doc, _, err := buildEnginePlan(credentialJSON)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// RenderSingBoxConfig builds the plan of BuildPlan and renders the
// ready sing-box JSON configuration for it. The static sing-box
// catalog gates the render: a plan the shipped upstream sing-box
// cannot carry (an Xray profile, an XHTTP split, AmneziaWG
// parameters) is refused with the missing capabilities named, instead
// of producing a configuration the engine would drop or reject —
// the lx fork's extra claims are build-time facts (engine.
// BuildCapabilities) and are not assumed here. No engine binary is
// probed or executed.
func RenderSingBoxConfig(credentialJSON string) (string, error) {
	doc, plan, err := buildEnginePlan(credentialJSON)
	if err != nil {
		return "", err
	}
	caps := engine.Catalog[engine.KindSingBox]
	if missing := caps.Missing(plan); len(missing) > 0 {
		return "", fmt.Errorf("mobileapi: sing-box cannot carry this plan: %s", strings.Join(missing, ", "))
	}
	raw, err := singbox.Render(plan, supervise.Runtime{
		LocalPort:   int(doc.LocalPort),
		ControlAddr: defaultControlAddr,
		ProbeURL:    engine.TestURLProduction,
	})
	if err != nil {
		return "", err
	}
	var check map[string]any
	if err := json.Unmarshal(raw, &check); err != nil {
		return "", fmt.Errorf("mobileapi: rendered configuration is not JSON: %w", err)
	}
	return string(raw), nil
}

// EngineInfo returns the static engine catalog as JSON: for every
// engine, its kind, minimum version, protocols and features from
// core/engine.Catalog, plus the core's default preference order.
// It reports capabilities the catalog claims for the shipped pins;
// it does not probe for installed binaries.
func EngineInfo() string {
	kinds := make([]string, 0, len(engine.Catalog))
	for kind := range engine.Catalog {
		kinds = append(kinds, string(kind))
	}
	sort.Strings(kinds)
	type engineInfo struct {
		Kind       string   `json:"kind"`
		MinVersion string   `json:"min_version"`
		Protocols  []string `json:"protocols"`
		Features   []string `json:"features"`
	}
	info := struct {
		Engines           []engineInfo `json:"engines"`
		DefaultPreference []string     `json:"default_preference"`
	}{}
	for _, name := range kinds {
		caps := engine.Catalog[engine.Kind(name)]
		entry := engineInfo{Kind: name, MinVersion: caps.MinVersion}
		for protocol := range caps.Protocols {
			entry.Protocols = append(entry.Protocols, string(protocol))
		}
		for feature := range caps.Features {
			entry.Features = append(entry.Features, string(feature))
		}
		sort.Strings(entry.Protocols)
		sort.Strings(entry.Features)
		info.Engines = append(info.Engines, entry)
	}
	for _, kind := range engine.DefaultPreference {
		info.DefaultPreference = append(info.DefaultPreference, string(kind))
	}
	raw, err := json.Marshal(info)
	if err != nil {
		return "{}"
	}
	return string(raw)
}
