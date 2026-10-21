// Command sora-ctl is the thin control helper of the macOS client.
//
// The Swift app never speaks the core's wire protocol itself: it runs
// this helper and reads one JSON document from its stdout. Commands:
//
//	status       daemon status + About (engines as the daemon reports)
//	about        GetAbout only
//	engineinfo   static engine catalog from core/mobileapi (no daemon
//	             needed; capabilities are data, never UI hardcode)
//	servers      servers of the imported plan kept in the state file
//	import       import links/subscription body (stdin, --file or URL
//	             with import-url) through the daemon's ParseImport —
//	             credentials go to the daemon vault, the state file
//	             keeps only the plan (credential references, no
//	             secrets). --local parses via core/mobileapi instead
//	             and touches neither daemon nor state (preview only).
//	connect      connect the selected server (--id, default: the
//	             selection stored at import or by select)
//	select       store the default server id for connect
//	disconnect   disconnect the running session
//
// Global flags: --socket (default: ipc.ListenAddress()), --state-dir
// (default: <user config dir>/sora-legacy), --timeout (default 60s).
//
// Every command prints exactly one JSON object to stdout. Failures
// print {"error": "..."} to stderr and exit 1 (2 for usage errors).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	corev1 "github.com/levvs-one/sora-client/core/gen/sora/core/v1"
	"github.com/levvs-one/sora-client/core/ipc"
	"github.com/levvs-one/sora-client/core/mobileapi"
)

type options struct {
	socket   string
	stateDir string
	timeout  time.Duration
}

// stdin is indirect so tests can feed import payloads.
var stdin io.Reader = os.Stdin

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sora-ctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var opts options
	fs.StringVar(&opts.socket, "socket", ipc.ListenAddress(), "core control socket")
	fs.StringVar(&opts.stateDir, "state-dir", "", "helper state directory (default: user config dir / sora-legacy)")
	fs.DurationVar(&opts.timeout, "timeout", 60*time.Second, "overall command timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(stderr, `{"error":"usage: sora-ctl [--socket PATH] [--state-dir DIR] <status|about|engineinfo|servers|import|import-url|connect|select|disconnect>"}`)
		return 2
	}
	if opts.stateDir == "" {
		dir, err := defaultStateDir()
		if err != nil {
			return fail(stderr, err)
		}
		opts.stateDir = dir
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	var err error
	switch rest[0] {
	case "status":
		err = cmdStatus(ctx, &opts, stdout)
	case "about":
		err = cmdAbout(ctx, &opts, stdout)
	case "engineinfo":
		err = emit(stdout, json.RawMessage(mobileapi.EngineInfo()))
	case "servers":
		err = cmdServers(&opts, stdout)
	case "import":
		err = cmdImport(ctx, &opts, rest[1:], stdin, stdout)
	case "import-url":
		err = cmdImportURL(ctx, &opts, rest[1:], stdout)
	case "connect":
		err = cmdConnect(ctx, &opts, rest[1:], stdout)
	case "select":
		err = cmdSelect(&opts, rest[1:], stdout)
	case "disconnect":
		err = cmdDisconnect(ctx, &opts, stdout)
	default:
		fmt.Fprintf(stderr, "{\"error\":\"unknown command %q\"}\n", rest[0])
		return 2
	}
	if err != nil {
		return fail(stderr, err)
	}
	return 0
}

func fail(stderr io.Writer, err error) int {
	raw, _ := json.Marshal(map[string]string{"error": err.Error()})
	fmt.Fprintln(stderr, string(raw))
	return 1
}

func emit(stdout io.Writer, value any) error {
	var raw []byte
	var err error
	switch v := value.(type) {
	case json.RawMessage:
		raw = v
	default:
		raw, err = json.Marshal(value)
		if err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(stdout, string(raw))
	return err
}

func defaultStateDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	// On darwin UserConfigDir is ~/Library/Application Support.
	return filepath.Join(dir, "sora-legacy"), nil
}

// ---- state file -----------------------------------------------------

// state is the helper's on-disk record: the last imported plan in
// protojson plus the selected outbound id. The plan carries credential
// references only — ParseImport put the material itself into the
// daemon's encrypted vault — so this file holds no secrets. It is
// still written 0600: it lists the user's servers.
type state struct {
	Plan     json.RawMessage `json:"plan"`
	Selected string          `json:"selected,omitempty"`
}

func statePath(opts *options) string { return filepath.Join(opts.stateDir, "plan.json") }

func loadState(opts *options) (*state, error) {
	raw, err := os.ReadFile(statePath(opts))
	if err != nil {
		return nil, fmt.Errorf("sora-ctl: no imported servers yet (run import first): %w", err)
	}
	var st state
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("sora-ctl: state file is unreadable: %w", err)
	}
	return &st, nil
}

func (st *state) plan() (*corev1.SessionPlan, error) {
	plan := &corev1.SessionPlan{}
	if err := protojson.Unmarshal(st.Plan, plan); err != nil {
		return nil, fmt.Errorf("sora-ctl: stored plan is unreadable: %w", err)
	}
	return plan, nil
}

func saveState(opts *options, st *state) error {
	if err := os.MkdirAll(opts.stateDir, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return os.WriteFile(statePath(opts), raw, 0o600)
}

// serverJSON is the helper's display shape of one outbound.
type serverJSON struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     uint32 `json:"port"`
}

func serversOf(plan *corev1.SessionPlan) []serverJSON {
	out := make([]serverJSON, 0, len(plan.GetOutbounds()))
	for _, ob := range plan.GetOutbounds() {
		out = append(out, serverJSON{
			ID: ob.GetId(), Name: ob.GetDisplayName(), Protocol: ob.GetProtocol(),
			Host: ob.GetEndpoint().GetHost(), Port: ob.GetEndpoint().GetPort(),
		})
	}
	return out
}

// ---- commands -------------------------------------------------------

func cmdStatus(ctx context.Context, opts *options, stdout io.Writer) error {
	c, err := dial(ctx, opts.socket)
	if err != nil {
		return err
	}
	defer c.close()
	status := &corev1.GetStatusResponse{}
	if err := c.call(ctx, "GetStatus", &corev1.GetStatusRequest{ApiVersion: c.version}, status); err != nil {
		return err
	}
	about := &corev1.GetAboutResponse{}
	if err := c.call(ctx, "GetAbout", &corev1.GetAboutRequest{ApiVersion: c.version}, about); err != nil {
		return err
	}
	return emit(stdout, statusJSON(status, about.GetAbout()))
}

func cmdAbout(ctx context.Context, opts *options, stdout io.Writer) error {
	c, err := dial(ctx, opts.socket)
	if err != nil {
		return err
	}
	defer c.close()
	about := &corev1.GetAboutResponse{}
	if err := c.call(ctx, "GetAbout", &corev1.GetAboutRequest{ApiVersion: c.version}, about); err != nil {
		return err
	}
	raw, err := protojson.Marshal(about.GetAbout())
	if err != nil {
		return err
	}
	return emit(stdout, json.RawMessage(raw))
}

// statusJSON flattens the wire types into the shape the Swift client
// decodes; engine data comes from the daemon's About (installed /
// version per engine), never from strings baked into any client.
func statusJSON(status *corev1.GetStatusResponse, about *corev1.About) map[string]any {
	conn := status.GetStatus().GetConnection()
	out := map[string]any{
		"state":     strings.TrimPrefix(conn.GetValue().String(), "CONNECTION_STATE_VALUE_"),
		"session_id": conn.GetSessionId(),
	}
	if about != nil {
		out["core_version"] = about.GetCoreVersion()
		out["platform"] = about.GetPlatform()
		if lp := about.GetLocalProxy(); lp != nil {
			out["local_proxy"] = map[string]any{"host": lp.GetHost(), "port": lp.GetPort()}
		}
		engines := make([]map[string]any, 0, len(about.GetEngines()))
		for _, e := range about.GetEngines() {
			engines = append(engines, map[string]any{
				"kind": e.GetKind(), "installed": e.GetInstalled(), "version": e.GetVersion(),
			})
		}
		out["engines"] = engines
	}
	if e := status.GetError(); e != nil {
		out["error_key"] = e.GetUserMessageKey()
	}
	return out
}

func cmdServers(opts *options, stdout io.Writer) error {
	st, err := loadState(opts)
	if err != nil {
		return err
	}
	plan, err := st.plan()
	if err != nil {
		return err
	}
	return emit(stdout, map[string]any{"servers": serversOf(plan), "selected": st.Selected})
}

func cmdImport(ctx context.Context, opts *options, args []string, stdin io.Reader, stdout io.Writer) error {
	local := false
	file := ""
	var positional []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--local":
			local = true
		case args[i] == "--file" && i+1 < len(args):
			i++
			file = args[i]
		default:
			positional = append(positional, args[i])
		}
	}
	var payload []byte
	var err error
	switch {
	case file != "":
		payload, err = os.ReadFile(file) //nolint:gosec // operator-chosen import file
	case len(positional) > 0:
		payload = []byte(strings.Join(positional, " "))
	default:
		payload, err = io.ReadAll(io.LimitReader(stdin, 16<<20))
	}
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(payload))) == 0 {
		return fmt.Errorf("sora-ctl: import payload is empty")
	}
	if local {
		parsed, err := mobileapi.ImportLinks(string(payload))
		if err != nil {
			// A payload that is not a link list may be a subscription
			// body; mobileapi distinguishes the two.
			if _, derr := mobileapi.ParseSubscription(payload); derr == nil {
				parsed, err = mobileapi.ParseSubscription(payload)
			}
		}
		if err != nil {
			return err
		}
		return emit(stdout, map[string]any{"source": "local", "servers": json.RawMessage(parsed)})
	}
	return importViaDaemon(ctx, opts, payload, stdout)
}

// importViaDaemon runs ParseImport: the daemon parses, stores the
// credentials in its vault, and returns a plan of references. The
// helper persists that plan as its state.
func importViaDaemon(ctx context.Context, opts *options, payload []byte, stdout io.Writer) error {
	c, err := dial(ctx, opts.socket)
	if err != nil {
		return err
	}
	defer c.close()
	resp := &corev1.ParseImportResponse{}
	req := &corev1.ParseImportRequest{ApiVersion: c.version, RequestId: requestID(), Payload: payload}
	if err := c.call(ctx, "ParseImport", req, resp); err != nil {
		return err
	}
	if resp.GetError() != nil {
		return fmt.Errorf("sora-ctl: import refused: %s", resp.GetError().GetUserMessageKey())
	}
	plan := resp.GetSessionPlan()
	raw, err := protojson.Marshal(plan)
	if err != nil {
		return err
	}
	st := &state{Plan: raw}
	if servers := serversOf(plan); len(servers) > 0 {
		st.Selected = servers[0].ID
	}
	if err := saveState(opts, st); err != nil {
		return err
	}
	return emit(stdout, map[string]any{"source": "daemon", "servers": serversOf(plan), "selected": st.Selected})
}

func cmdImportURL(ctx context.Context, opts *options, args []string, stdout io.Writer) error {
	if len(args) != 1 || !strings.HasPrefix(args[0], "https://") {
		return fmt.Errorf("sora-ctl: import-url needs one https:// URL")
	}
	// Plain fetch by the helper process. The daemon's own subscription
	// machinery (core/subscription, with its obfs fetch profile and
	// SaveSubscription bookkeeping) is the richer path; this command is
	// the simple one-shot import and says so in its output.
	httpClient := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, args[0], nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "sora-legacy-macos/1.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sora-ctl: subscription fetch failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sora-ctl: subscription fetch answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	return importViaDaemon(ctx, opts, body, stdout)
}

func cmdSelect(opts *options, args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return fmt.Errorf("sora-ctl: select needs a server id")
	}
	st, err := loadState(opts)
	if err != nil {
		return err
	}
	plan, err := st.plan()
	if err != nil {
		return err
	}
	for _, s := range serversOf(plan) {
		if s.ID == args[0] {
			st.Selected = args[0]
			if err := saveState(opts, st); err != nil {
				return err
			}
			return emit(stdout, map[string]any{"selected": st.Selected})
		}
	}
	return fmt.Errorf("sora-ctl: no server with id %q in the imported plan", args[0])
}

func cmdConnect(ctx context.Context, opts *options, args []string, stdout io.Writer) error {
	mode := "tun"
	id := ""
	killSwitch := false
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--mode" && i+1 < len(args):
			i++
			mode = args[i]
		case args[i] == "--id" && i+1 < len(args):
			i++
			id = args[i]
		case args[i] == "--kill-switch":
			killSwitch = true
		default:
			return fmt.Errorf("sora-ctl: unknown connect argument %q", args[i])
		}
	}
	st, err := loadState(opts)
	if err != nil {
		return err
	}
	plan, err := st.plan()
	if err != nil {
		return err
	}
	if id == "" {
		id = st.Selected
	}
	// A session connects one selected server: keep only its outbound,
	// so the daemon's plan validation and engine choice stay the
	// single-server case the other legacy clients exercise.
	var chosen *corev1.OutboundSpec
	for _, ob := range plan.GetOutbounds() {
		if ob.GetId() == id {
			chosen = ob
		}
	}
	if chosen == nil {
		return fmt.Errorf("sora-ctl: no server with id %q in the imported plan", id)
	}
	connectPlan := &corev1.SessionPlan{Outbounds: []*corev1.OutboundSpec{chosen}}
	switch mode {
	case "tun":
		connectPlan.TunnelMode = corev1.TunnelMode_TUNNEL_MODE_SYSTEM
	case "proxy":
		// No TUN: the daemon opens its loopback local proxy and the
		// user-session UI points the macOS system proxy at it (the
		// system proxy belongs to the signed-in user — core/guard).
		connectPlan.TunnelMode = corev1.TunnelMode_TUNNEL_MODE_APPLICATION
		connectPlan.LocalProxy = &corev1.LocalProxy{Enabled: true}
	default:
		return fmt.Errorf("sora-ctl: --mode must be tun or proxy")
	}
	c, err := dial(ctx, opts.socket)
	if err != nil {
		return err
	}
	defer c.close()
	resp := &corev1.ConnectResponse{}
	req := &corev1.ConnectRequest{
		ApiVersion: c.version, RequestId: requestID(), SessionPlan: connectPlan,
		ControlAuthenticator: c.token, KillSwitch: killSwitch,
	}
	if err := c.call(ctx, "Connect", req, resp); err != nil {
		return err
	}
	if resp.GetError() != nil {
		return fmt.Errorf("sora-ctl: connect refused: %s", resp.GetError().GetUserMessageKey())
	}
	out := statusJSON(&corev1.GetStatusResponse{Status: resp.GetStatus()}, nil)
	out["mode"] = mode
	out["server_id"] = id
	// Honest capability note: on darwin the core's firewall is the
	// Noop implementation (core/guard), so a requested kill switch is
	// recorded by the core but not enforced by a packet filter. The UI
	// must show exactly that, never "protected".
	out["kill_switch_requested"] = killSwitch
	out["kill_switch_enforced"] = false
	return emit(stdout, out)
}

func cmdDisconnect(ctx context.Context, opts *options, stdout io.Writer) error {
	c, err := dial(ctx, opts.socket)
	if err != nil {
		return err
	}
	defer c.close()
	resp := &corev1.DisconnectResponse{}
	req := &corev1.DisconnectRequest{
		ApiVersion: c.version, RequestId: requestID(), ControlAuthenticator: c.token,
	}
	if err := c.call(ctx, "Disconnect", req, resp); err != nil {
		return err
	}
	if resp.GetError() != nil {
		return fmt.Errorf("sora-ctl: disconnect refused: %s", resp.GetError().GetUserMessageKey())
	}
	return emit(stdout, statusJSON(&corev1.GetStatusResponse{Status: resp.GetStatus()}, nil))
}

var requestCounter int

func requestID() string {
	requestCounter++
	return fmt.Sprintf("sora-ctl-%d-%d", os.Getpid(), requestCounter)
}
