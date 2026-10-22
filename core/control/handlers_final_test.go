package control_test

// Handler-level tests for the three contract RPCs that previously had no
// handler coverage at all: RunDiagnostics, GetRoutingPresets and
// SetKillSwitch (pass-1 debt, closed by the final quality stage). Each test
// drives the real Server handler with the real session manager, the real
// routing preset catalog and the real diagnostics collector; only the
// engine and the platform guard are test doubles, exactly as in the rest
// of this package's suite.

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/levvs-one/sora-client/core/control"
	"github.com/levvs-one/sora-client/core/diagnostics"
	"github.com/levvs-one/sora-client/core/engine"
	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
	"github.com/levvs-one/sora-client/core/routing"
	"github.com/levvs-one/sora-client/core/secret"
	"github.com/levvs-one/sora-client/core/session"
)

// recordingGuard is a session.Guard that remembers the last settings it was
// asked to apply, so a test can prove the handler's toggle reached the
// guard layer and not only the session's bookkeeping.
type recordingGuard struct {
	mu      sync.Mutex
	current session.Settings
	applies int
}

func (g *recordingGuard) Apply(_ context.Context, s session.Settings) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.current = s
	g.applies++
	return nil
}

func (g *recordingGuard) Restore(context.Context) error { return nil }

func (g *recordingGuard) Current() session.Settings {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.current
}

func (g *recordingGuard) Name() string { return "recording" }

func (g *recordingGuard) applyCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.applies
}

// managerSource feeds the real diagnostics collector from the real session
// manager, mirroring how cmd/sora-core wires its own source: the status is
// read live from the manager on every report.
type managerSource struct {
	manager *session.Manager
}

func (s managerSource) Status() session.Status { return s.manager.Status() }

func (s managerSource) RecentEvents(int) []session.Event { return nil }

func (s managerSource) EngineLines() []string {
	return []string{"engine: stub (handler test)"}
}

// newHandlerTestServer builds a control plane like newTestServer, but keeps
// the session manager and guard reachable and attaches the real diagnostics
// collector unless withDiagnostics is false.
func newHandlerTestServer(t *testing.T, withDiagnostics bool) (*control.Server, *secret.Store, *session.Manager, *recordingGuard) {
	t.Helper()
	store, err := secret.Open(t.TempDir(), secret.Options{Protector: secret.FileProtector{}})
	if err != nil {
		t.Fatalf("opening the secret store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	auth, err := control.NewAuthenticator(testToken)
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	guard := &recordingGuard{}
	manager := session.NewManager(session.ManagerConfig{
		TunUp: noAdapter,
		Guard: guard,
		Factory: func(context.Context, *engine.Plan) (engine.Engine, error) {
			return newStubEngine(), nil
		},
	})
	cfg := control.Config{
		Version:       control.Version{Major: 1, Minor: 2, MinSupportedMinor: 1},
		Authenticator: auth,
		Sessions:      manager,
		Secrets:       store,
	}
	if withDiagnostics {
		collector, err := diagnostics.New(diagnostics.Options{
			Source:   managerSource{manager: manager},
			Redactor: engine.NewRedactor(),
		})
		if err != nil {
			t.Fatalf("diagnostics.New() error = %v", err)
		}
		cfg.Diagnostics = collector
	}
	server, err := control.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return server, store, manager, guard
}

// connectForHandlerTest starts a session through the real Connect handler
// and returns its session id.
func connectForHandlerTest(t *testing.T, server *control.Server, store *secret.Store) string {
	t.Helper()
	response, err := server.Connect(context.Background(), &corev1.ConnectRequest{
		ApiVersion:           clientVersion(),
		RequestId:            "req-handler",
		SessionPlan:          validPlan(t, store),
		ControlAuthenticator: testToken,
	})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if response.GetError() != nil {
		t.Fatalf("Connect() failed with %v", response.GetError())
	}
	id := response.GetStatus().GetConnection().GetSessionId()
	if id == "" {
		t.Fatal("Connect() did not name the session it started")
	}
	t.Cleanup(func() {
		_, _ = server.Disconnect(context.Background(), &corev1.DisconnectRequest{
			ApiVersion:           clientVersion(),
			ControlAuthenticator: testToken,
		})
	})
	return id
}

func TestHandlerGetRoutingPresetsServesTheRealCatalog(t *testing.T) {
	server, _, _, _ := newHandlerTestServer(t, false)

	response, err := server.GetRoutingPresets(context.Background(), &corev1.GetRoutingPresetsRequest{
		ApiVersion: clientVersion(),
	})
	if err != nil {
		t.Fatalf("GetRoutingPresets() error = %v", err)
	}
	if response.GetError() != nil {
		t.Fatalf("GetRoutingPresets() failed with %v", response.GetError())
	}

	// The handler must serve the routing package's real catalog, in the
	// catalog's order, with every direct rule rendered in plan syntax.
	want := routing.Presets()
	if len(response.GetPresets()) != len(want) {
		t.Fatalf("handler returned %d presets, the catalog has %d",
			len(response.GetPresets()), len(want))
	}
	for i, preset := range want {
		got := response.GetPresets()[i]
		if got.GetId() != preset.ID {
			t.Errorf("preset %d: id = %q, want the catalog's %q", i, got.GetId(), preset.ID)
		}
		if len(got.GetDirect()) != len(preset.Direct) {
			t.Fatalf("preset %q: handler returned %d direct rules, the catalog has %d",
				preset.ID, len(got.GetDirect()), len(preset.Direct))
		}
		for j, rule := range preset.Direct {
			rendered := string(rule.Type) + ":" + rule.Value
			if got.GetDirect()[j] != rendered {
				t.Errorf("preset %q rule %d = %q, want %q",
					preset.ID, j, got.GetDirect()[j], rendered)
			}
		}
	}

	// Spot-pin the catalog facts clients rely on: every preset bypasses
	// private destinations first, and the ru preset sends Russian
	// destinations direct.
	for _, preset := range response.GetPresets() {
		if len(preset.GetDirect()) == 0 || preset.GetDirect()[0] != "geoip:private" {
			t.Errorf("preset %q does not start with geoip:private: %v",
				preset.GetId(), preset.GetDirect())
		}
		if preset.GetId() == "ru" {
			found := false
			for _, direct := range preset.GetDirect() {
				if direct == "geoip:ru" {
					found = true
				}
			}
			if !found {
				t.Errorf("the ru preset lost geoip:ru: %v", preset.GetDirect())
			}
		}
	}
}

func TestHandlerRunDiagnosticsReturnsTheStructuredReport(t *testing.T) {
	server, store, _, _ := newHandlerTestServer(t, true)
	sessionID := connectForHandlerTest(t, server, store)

	response, err := server.RunDiagnostics(context.Background(), &corev1.RunDiagnosticsRequest{
		ApiVersion: clientVersion(),
		RequestId:  "req-diag",
		SessionId:  sessionID,
	})
	if err != nil {
		t.Fatalf("RunDiagnostics() error = %v", err)
	}
	if response.GetError() != nil {
		t.Fatalf("RunDiagnostics() failed with %v", response.GetError())
	}
	report := response.GetReport()
	if report == nil {
		t.Fatal("RunDiagnostics() returned no report for a running session")
	}
	lines := report.GetLines()
	if len(lines) == 0 {
		t.Fatal("the diagnostics report is empty")
	}
	// The report is the real collector's structured output for the live
	// session: fixed header, the session section naming this session, and
	// the kill-switch state line.
	if lines[0] != "Sora diagnostics" {
		t.Errorf("first report line = %q, want the collector header", lines[0])
	}
	joined := "\n" + strings.Join(lines, "\n") + "\n"
	for _, want := range []string{
		"\n[session]\n",
		"\nid: " + sessionID + "\n",
		"\nkill_switch: false\n",
		"\n[engine]\n",
		"\nengine: stub (handler test)\n",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the report does not contain %q; lines:\n%s", want, joined)
		}
	}

	// A session the core is not running gets an in-band error and no
	// report, not somebody else's diagnostics.
	refused, err := server.RunDiagnostics(context.Background(), &corev1.RunDiagnosticsRequest{
		ApiVersion: clientVersion(),
		SessionId:  "not-the-running-session",
	})
	if err != nil {
		t.Fatalf("RunDiagnostics() with a foreign session error = %v", err)
	}
	if refused.GetError() == nil {
		t.Error("RunDiagnostics() answered a foreign session with a report")
	}
	if refused.GetReport() != nil {
		t.Error("RunDiagnostics() attached a report to its refusal")
	}
}

func TestHandlerRunDiagnosticsWithoutACollectorRefusesInBand(t *testing.T) {
	server, store, _, _ := newHandlerTestServer(t, false)
	sessionID := connectForHandlerTest(t, server, store)

	response, err := server.RunDiagnostics(context.Background(), &corev1.RunDiagnosticsRequest{
		ApiVersion: clientVersion(),
		SessionId:  sessionID,
	})
	if err != nil {
		t.Fatalf("RunDiagnostics() error = %v", err)
	}
	if response.GetError() == nil {
		t.Fatal("a core without a diagnostics collector answered with a report")
	}
	if response.GetReport() != nil {
		t.Error("the refusal carried a report")
	}
}

func TestHandlerSetKillSwitchTogglesAndReadsBack(t *testing.T) {
	server, store, manager, guard := newHandlerTestServer(t, true)
	sessionID := connectForHandlerTest(t, server, store)

	if manager.Status().KillSwitch {
		t.Fatal("the session started with the kill switch already armed")
	}
	appliesBefore := guard.applyCount()

	// Arm it through the handler.
	armed, err := server.SetKillSwitch(context.Background(), &corev1.SetKillSwitchRequest{
		ApiVersion: clientVersion(),
		RequestId:  "req-ks-arm",
		SessionId:  sessionID,
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("SetKillSwitch(true) error = %v", err)
	}
	if armed.GetError() != nil {
		t.Fatalf("SetKillSwitch(true) failed with %v", armed.GetError())
	}
	if !armed.GetEnabled() {
		t.Error("SetKillSwitch(true) answered enabled=false")
	}
	// Read back through the session status — the same state GetStatus and
	// the diagnostics report are rendered from.
	if !manager.Status().KillSwitch {
		t.Error("after SetKillSwitch(true) the session status still reports the kill switch off")
	}
	if !guard.Current().KillSwitch {
		t.Error("the guard layer never saw the armed kill switch")
	}
	if guard.applyCount() <= appliesBefore {
		t.Error("arming the kill switch never reached the guard's Apply")
	}

	// The diagnostics report is the wire-visible readback: it must now say
	// the switch is on.
	report, err := server.RunDiagnostics(context.Background(), &corev1.RunDiagnosticsRequest{
		ApiVersion: clientVersion(),
		SessionId:  sessionID,
	})
	if err != nil {
		t.Fatalf("RunDiagnostics() error = %v", err)
	}
	if !strings.Contains(strings.Join(report.GetReport().GetLines(), "\n"), "kill_switch: true") {
		t.Error("the diagnostics report does not read back kill_switch: true after arming")
	}

	// Disarm it again and read the toggle back once more.
	disarmed, err := server.SetKillSwitch(context.Background(), &corev1.SetKillSwitchRequest{
		ApiVersion: clientVersion(),
		RequestId:  "req-ks-disarm",
		SessionId:  sessionID,
		Enabled:    false,
	})
	if err != nil {
		t.Fatalf("SetKillSwitch(false) error = %v", err)
	}
	if disarmed.GetError() != nil {
		t.Fatalf("SetKillSwitch(false) failed with %v", disarmed.GetError())
	}
	if disarmed.GetEnabled() {
		t.Error("SetKillSwitch(false) answered enabled=true")
	}
	if manager.Status().KillSwitch {
		t.Error("after SetKillSwitch(false) the session status still reports the kill switch on")
	}
	if guard.Current().KillSwitch {
		t.Error("the guard layer still holds the armed kill switch after disarming")
	}

	// Naming a session that is not running is refused in band and changes
	// nothing.
	refused, err := server.SetKillSwitch(context.Background(), &corev1.SetKillSwitchRequest{
		ApiVersion: clientVersion(),
		SessionId:  "not-the-running-session",
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("SetKillSwitch() with a foreign session error = %v", err)
	}
	if refused.GetError() == nil {
		t.Error("SetKillSwitch() armed a session that is not running")
	}
	if manager.Status().KillSwitch {
		t.Error("the refused SetKillSwitch() changed the running session")
	}
}
