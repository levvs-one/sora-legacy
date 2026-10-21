package singbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/enginetest"
)

// TestBinaryECHQueryServerNameMatchesGate ties the catalog gate to
// the real binary, in the style of TestCensorP1BinaryAcceptsKeyShareRender:
// ech.query_server_name exists only since sing-box 1.13, so the
// shipped payload build 1.12.12 refuses the rendered config at load
// (`unknown field "query_server_name"`, probed — LEGACY-PLAT-OBFS)
// while 1.13+ builds accept it. For whichever binary the existing
// discovery mechanism names, the binary's verdict on the render
// must agree with BuildCapabilities for its probed version: a
// build the gate would route the plan to must accept the config,
// and a build the gate refuses must refuse it too.
func TestBinaryECHQueryServerNameMatchesGate(t *testing.T) {
	bin := os.Getenv("SORA_SINGBOX_BIN")
	if bin == "" {
		dir := os.Getenv("SORA_ENGINES_DIR")
		if dir == "" {
			t.Skip("set SORA_ENGINES_DIR or SORA_SINGBOX_BIN to check the render with sing-box")
		}
		bin = filepath.Join(dir, "sing-box")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	binary, err := Prober.Probe(ctx, bin)
	if err != nil {
		t.Fatal(err)
	}
	p := enginetest.Plan(engine.ProtocolTrojan)
	p.Outbounds[0].TLS.ECH = engine.ECHConfig{Enabled: true, QueryServerName: "ech-query.example.com"}
	raw, err := Render(p, testRuntime)
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfg, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out, checkErr := exec.CommandContext(ctx, bin, "check", "-c", cfg).CombinedOutput()

	caps := engine.BuildCapabilities(engine.KindSingBox, binary.Version, binary.BuildTags)
	gated := slices.Contains(caps.Missing(p), "feature "+string(engine.FeatureECHQueryServerName))
	if gated && checkErr == nil {
		t.Fatalf("sing-box %s: the gate refuses a query_server_name plan for this build, but the binary accepted the render", binary.Version)
	}
	if !gated && checkErr != nil {
		t.Fatalf("sing-box %s: the gate routes a query_server_name plan to this build, but the binary refused the render: %v\n%s", binary.Version, checkErr, out)
	}
}
