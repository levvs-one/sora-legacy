package singbox

import (
	"fmt"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/engine/enginetest"
)

// plan200 builds a 200-outbound plan reusing the shared enginetest shape
// (groups, rules, DNS) so Render exercises its real path.
func plan200() *engine.Plan {
	p := enginetest.Plan(engine.ProtocolVLESS)
	p.Outbounds = p.Outbounds[:0]
	ids := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		o := enginetest.Outbound(engine.ProtocolVLESS)
		o.ID = fmt.Sprintf("vless-%d", i)
		o.Name = fmt.Sprintf("Server %d", i)
		o.Server = fmt.Sprintf("node%d.example.com", i)
		p.Outbounds = append(p.Outbounds, o)
		ids = append(ids, o.ID)
	}
	p.Groups = []engine.Group{
		{Name: "Auto", Type: engine.GroupURLTest, Outbounds: ids, Interval: 300, Tolerance: 50},
		{Name: "Proxy", Type: engine.GroupSelect, Outbounds: append([]string{"Auto"}, ids...)},
	}
	return p
}

// BenchmarkRender200Outbounds measures config rendering for a plan with 200
// servers, the render freshly computed on each session start and every
// subscription-driven plan change.
func BenchmarkRender200Outbounds(b *testing.B) {
	p := plan200()
	if _, err := Render(p, testRuntime); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Render(p, testRuntime); err != nil {
			b.Fatal(err)
		}
	}
}
