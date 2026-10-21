package main

// Integration tests: the helper's commands against a real daemon
// stack — core/ipc unix socket, core/legacycontrol JSON-RPC server,
// core/control plane — with only the engine stubbed out. They run on
// Linux; the same helper binary cross-builds for darwin (the socket
// path and peer rules are the platform parts, both in core/ipc).

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/levvs-one/sora-client/core/control"
	"github.com/levvs-one/sora-client/core/engine"
	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
	"github.com/levvs-one/sora-client/core/ipc"
	"github.com/levvs-one/sora-client/core/legacycontrol"
	"github.com/levvs-one/sora-client/core/secret"
	"github.com/levvs-one/sora-client/core/session"
)

func startDaemon(t *testing.T) (socket, stateDir string) {
	t.Helper()
	token := make([]byte, control.TokenLen)
	if _, err := rand.Read(token); err != nil {
		t.Fatal(err)
	}
	auth, err := control.NewAuthenticator(token)
	if err != nil {
		t.Fatal(err)
	}
	store, err := secret.Open(t.TempDir(), secret.Options{Protector: secret.FileProtector{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	manager := session.NewManager(session.ManagerConfig{Factory: func(context.Context, *engine.Plan) (engine.Engine, error) {
		return nil, errors.New("test daemon installs no engine")
	}})
	plane, err := control.New(control.Config{
		Version:       control.Version{Major: 1, Minor: 7, MinSupportedMinor: 1},
		Authenticator: auth, Sessions: manager, Secrets: store,
		About: func() *corev1.About {
			return &corev1.About{CoreVersion: "test", Platform: "linux/amd64"}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	socket = filepath.Join(t.TempDir(), "core.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	listener, err := ipc.Listen(ctx, ipc.Options{Address: socket})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = legacycontrol.Serve(ctx, listener, plane) }()
	// The listener is bound before Serve accepts; a short settle keeps
	// the first Dial from racing the accept loop on a loaded machine.
	time.Sleep(50 * time.Millisecond)
	return socket, t.TempDir()
}

func runCmd(t *testing.T, socket, stateDir, stdin string, args ...string) (string, string, int) {
	t.Helper()
	defer setStdin(stdin)()
	full := append([]string{"--socket", socket, "--state-dir", stateDir}, args...)
	var out, errBuf bytes.Buffer
	code := run(full, &out, &errBuf)
	return out.String(), errBuf.String(), code
}

// setStdin replaces the package stdin for one test and returns the
// restore function.
func setStdin(s string) func() {
	old := stdin
	stdin = strings.NewReader(s)
	return func() { stdin = old }
}

func decode(t *testing.T, raw string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("output is not one JSON object: %v\n%s", err, raw)
	}
	return doc
}

func TestStatusImportServersSelectDisconnect(t *testing.T) {
	socket, stateDir := startDaemon(t)

	out, errOut, code := runCmd(t, socket, stateDir, "", "status")
	if code != 0 {
		t.Fatalf("status exit %d: %s", code, errOut)
	}
	if got := decode(t, out)["state"]; got != "DISCONNECTED" {
		t.Fatalf("status state = %v", got)
	}
	if got := decode(t, out)["core_version"]; got != "test" {
		t.Fatalf("status core_version = %v (About did not flow through)", got)
	}

	out, errOut, code = runCmd(t, socket, stateDir, "socks5://user:secret@127.0.0.1:1080#Local", "import")
	if code != 0 {
		t.Fatalf("import exit %d: %s", code, errOut)
	}
	doc := decode(t, out)
	servers, _ := doc["servers"].([]any)
	if len(servers) != 1 {
		t.Fatalf("import servers = %v", doc["servers"])
	}
	id, _ := servers[0].(map[string]any)["id"].(string)
	if id == "" {
		t.Fatal("imported server has no id")
	}
	// The state file must carry references, never the password.
	raw, err := os.ReadFile(filepath.Join(stateDir, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret") {
		t.Fatalf("state file leaks credential material: %s", raw)
	}

	out, _, code = runCmd(t, socket, stateDir, "", "servers")
	if code != 0 || len(decode(t, out)["servers"].([]any)) != 1 {
		t.Fatalf("servers: %d %s", code, out)
	}

	out, _, code = runCmd(t, socket, stateDir, "", "select", id)
	if code != 0 || decode(t, out)["selected"] != id {
		t.Fatalf("select: %d %s", code, out)
	}
	if _, _, code = runCmd(t, socket, stateDir, "", "select", "no-such-id"); code == 0 {
		t.Fatal("select of an unknown id succeeded")
	}

	// Connect reaches the daemon and is honestly refused by the stub
	// engine (no engine is installed in the test): a refusal with a
	// core error key, not a helper crash or a fake success.
	_, errOut, code = runCmd(t, socket, stateDir, "", "connect", "--mode", "proxy")
	if code == 0 {
		t.Fatal("connect succeeded against a daemon with no engine")
	}
	if !strings.Contains(errOut, "connect refused") {
		t.Fatalf("connect error = %s", errOut)
	}

	out, errOut, code = runCmd(t, socket, stateDir, "", "disconnect")
	if code != 0 {
		t.Fatalf("disconnect exit %d: %s", code, errOut)
	}
	if got := decode(t, out)["state"]; got != "DISCONNECTED" {
		t.Fatalf("disconnect state = %v", got)
	}
}

func TestImportLocalNeedsNoDaemon(t *testing.T) {
	defer setStdin("socks5://user:secret@127.0.0.1:1080#Local")()
	var out, errBuf bytes.Buffer
	code := run([]string{"--socket", filepath.Join(t.TempDir(), "absent.sock"),
		"--state-dir", t.TempDir(), "import", "--local"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("local import exit %d: %s", code, errBuf.String())
	}
	doc := decode(t, out.String())
	if doc["source"] != "local" {
		t.Fatalf("source = %v", doc["source"])
	}
	servers, _ := doc["servers"].([]any)
	if len(servers) != 1 {
		t.Fatalf("local servers = %v", doc["servers"])
	}
}

func TestEngineInfoIsCatalogData(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"engineinfo"}, &out, &errBuf); code != 0 {
		t.Fatalf("engineinfo exit %d: %s", code, errBuf.String())
	}
	doc := decode(t, out.String())
	engines, _ := doc["engines"].([]any)
	if len(engines) == 0 {
		t.Fatal("engineinfo lists no engines")
	}
	kinds := map[string]bool{}
	for _, e := range engines {
		kinds[e.(map[string]any)["kind"].(string)] = true
	}
	for _, want := range []string{"sing-box", "xray", "mihomo"} {
		if !kinds[want] {
			t.Fatalf("engineinfo misses %s: %v", want, kinds)
		}
	}
}

func TestUnreachableDaemonIsAnErrorNotAPanic(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--socket", filepath.Join(t.TempDir(), "absent.sock"), "status"}, &out, &errBuf)
	if code != 1 || !strings.Contains(errBuf.String(), "not reachable") {
		t.Fatalf("code %d, stderr %s", code, errBuf.String())
	}
}
