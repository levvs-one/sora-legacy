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

// TestBinaryHy2SingBox114MatchesGate ties the 1.14 catalog gates to
// the real binary, in the style of
// TestBinaryECHQueryServerNameMatchesGate: hop_interval_max,
// bbr_profile and the gecko obfs type exist only since sing-box
// 1.14, so builds below the floor refuse the rendered configs at
// load (`unknown field "hop_interval_max"`, `unknown field
// "bbr_profile"`, `unknown obfs type: gecko` — probed on the
// 1.12.12 and 1.13.21 release binaries) while 1.14.3 accepts them.
// For whichever binary the existing discovery mechanism names, the
// binary's verdict on each render must agree with
// BuildCapabilities for its probed version: a build the gate would
// route a plan to must accept the config, and a build the gate
// refuses must refuse it too.
func TestBinaryHy2SingBox114MatchesGate(t *testing.T) {
	bin := os.Getenv("SORA_SINGBOX_BIN")
	if bin == "" {
		dir := os.Getenv("SORA_ENGINES_DIR")
		if dir == "" {
			t.Skip("set SORA_ENGINES_DIR or SORA_SINGBOX_BIN to check the render with sing-box")
		}
		bin = filepath.Join(dir, "sing-box")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	binary, err := Prober.Probe(ctx, bin)
	if err != nil {
		t.Fatal(err)
	}
	caps := engine.BuildCapabilities(engine.KindSingBox, binary.Version, binary.BuildTags)

	plans := map[string]func(*engine.Outbound){
		"hop_interval_max": func(o *engine.Outbound) {
			o.HopPorts, o.HopInterval, o.HopIntervalMax = "20000-30000", 30, 90
		},
		"bbr_profile": func(o *engine.Outbound) {
			o.BBRProfile = "conservative"
		},
		"gecko obfs": func(o *engine.Outbound) {
			o.Obfs, o.ObfsParam = "gecko", "gecko-secret"
		},
		"all 1.14 fields": func(o *engine.Outbound) {
			o.HopPorts, o.HopInterval, o.HopIntervalMax = "20000-30000", 30, 90
			o.BBRProfile = "conservative"
			o.Obfs, o.ObfsParam = "gecko", "gecko-secret"
		},
	}
	features := map[string][]engine.Feature{
		"hop_interval_max": {engine.FeatureHy2HopIntervalMax},
		"bbr_profile":      {engine.FeatureHy2BBRProfile},
		"gecko obfs":       {engine.FeatureHy2ObfsGecko},
		"all 1.14 fields":  {engine.FeatureHy2HopIntervalMax, engine.FeatureHy2BBRProfile, engine.FeatureHy2ObfsGecko},
	}
	for name, mut := range plans {
		t.Run(name, func(t *testing.T) {
			p := enginetest.Plan(engine.ProtocolHysteria2)
			mut(&p.Outbounds[0])
			raw, err := Render(p, testRuntime)
			if err != nil {
				t.Fatal(err)
			}
			cfg := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(cfg, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			out, checkErr := exec.CommandContext(ctx, bin, "check", "-c", cfg).CombinedOutput()

			missing := caps.Missing(p)
			gated := false
			for _, f := range features[name] {
				if slices.Contains(missing, "feature "+string(f)) {
					gated = true
				}
			}
			if gated && checkErr == nil {
				t.Fatalf("sing-box %s: the gate refuses a %s plan for this build, but the binary accepted the render", binary.Version, name)
			}
			if !gated && checkErr != nil {
				t.Fatalf("sing-box %s: the gate routes a %s plan to this build, but the binary refused the render: %v\n%s", binary.Version, name, checkErr, out)
			}
		})
	}
}
