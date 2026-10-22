package xray

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/enginetest"
)

// W1 (ported from sora snapshot 142397c5): Xray renders the Hysteria2
// bandwidth hints into hysteriaSettings (Brutal congestion control);
// port hopping and obfs have no Xray spelling and are kept off Xray
// by the FeatureHy2PortHop/FeatureHy2Obfs gates instead.
func TestRenderPassesHysteria2BandwidthToBrutal(t *testing.T) {
	p := hysteriaWithoutObfs(enginetest.Plan(engine.ProtocolHysteria2))
	p.Outbounds[0].QUICBox().UpMbps, p.Outbounds[0].QUICBox().DownMbps = 100, 500
	raw, err := Render(p, testRuntime, nil)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Outbounds []struct {
			StreamSettings struct {
				HysteriaSettings map[string]any `json:"hysteriaSettings"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	hy := cfg.Outbounds[0].StreamSettings.HysteriaSettings
	if hy["up_mbps"] != float64(100) || hy["down_mbps"] != float64(500) {
		t.Errorf("hysteriaSettings = %v, want up_mbps=100 down_mbps=500 (brutal CC)", hy)
	}

	// Zero caps must stay absent: an explicit 0 would pin brutal to
	// nothing; the engine default (BBR) applies instead.
	p = hysteriaWithoutObfs(enginetest.Plan(engine.ProtocolHysteria2))
	raw, err = Render(p, testRuntime, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "up_mbps") || strings.Contains(string(raw), "down_mbps") {
		t.Errorf("zero bandwidth caps must not render: %s", raw)
	}
}
