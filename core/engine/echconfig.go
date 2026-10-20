package engine

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// ECHConfigList handling as data (S5-SP5, ported from sora).
//
// A plan pins ECH as PEM lines (TLS.ECH.Config) — the shape sing-box
// takes upstream. Only the decoder is ported: TLS.validate uses it to
// refuse a pinned list no renderer could decode, here at plan time
// instead of at engine startup. The render-side spellings (one
// canonical base64 string, canonical PEM armor) are not ported
// because no legacy renderer emits ECH yet; they belong with the
// renderer that first spells it.
//
// The decoder accepts any armor label and bare base64 lines, and
// fails closed on data that is not a single ECHConfigList: two PEM
// blocks are two lists, and concatenating them is not a list.

// ECHConfigListBytes decodes a plan's pinned ECH config (PEM lines or
// bare base64) to the raw ECHConfigList bytes.
func ECHConfigListBytes(lines []string) ([]byte, error) {
	if len(lines) == 0 {
		return nil, nil
	}
	blocks, ends := 0, 0
	var body strings.Builder
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(ln, "-----BEGIN"):
			blocks++
		case strings.HasPrefix(ln, "-----END"):
			ends++
		case ln == "":
			// Blank line: no payload.
		default:
			body.WriteString(ln)
		}
	}
	if blocks > 1 {
		return nil, fmt.Errorf("ech: %d pinned ECH configs cannot be merged into one ECHConfigList", blocks)
	}
	if blocks != ends {
		return nil, fmt.Errorf("ech: the pinned ECH config has unterminated PEM armor (%d BEGIN, %d END)", blocks, ends)
	}
	raw, err := base64.StdEncoding.DecodeString(body.String())
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("ech: the pinned ECH config is not PEM/base64 ECHConfigList data")
	}
	return raw, nil
}
