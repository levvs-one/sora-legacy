package control

import (
	"net/url"
	"testing"

	"github.com/levvs-one/sora-client/core/engine"
	"github.com/levvs-one/sora-client/core/parser"
)

// TestXHTTPTuningSurvivesTheVault is ported from sora (S5-SP4): it pins
// the credential-document leg of the extra= xmux/padding import — what
// the parser read from the link must reach engine.Transport unchanged
// when the stored server is resolved into a plan outbound.
func TestXHTTPTuningSurvivesTheVault(t *testing.T) {
	extra := url.QueryEscape(`{"xmux":{"maxConcurrency":16,"cMaxReuseTimes":10},"xPaddingBytes":"100-1000"}`)
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@edge.example.com:443?security=tls" +
		"&type=xhttp&mode=stream-up&extra=" + extra + "#X"
	result, err := parser.LinkParser{}.Parse([]byte(link))
	if err != nil || len(result.Servers) != 1 {
		t.Fatalf("Parse = %+v, %v", result, err)
	}
	document, err := credentialDocument(result.Servers[0])
	if err != nil {
		t.Fatal(err)
	}
	values, err := parseCredential(document)
	if err != nil {
		t.Fatal(err)
	}
	var o engine.Outbound
	if err := applyCredential(&o, values); err != nil {
		t.Fatal(err)
	}
	tr := o.Transport
	if tr.XHTTPOrZero().XmuxMaxConcurrency != 16 || tr.XHTTPOrZero().XmuxMaxReuseTimes != 10 || tr.XHTTPOrZero().XPaddingBytes != "100-1000" {
		t.Errorf("XHTTP tuning lost on the way to the engine: %+v", tr)
	}
}

// TestXHTTPDownloadSplitSurvivesTheVault pins the same leg for the
// up/down split: downloadSettings from the link's extra= must reach
// engine.Transport through the credential document.
func TestXHTTPDownloadSplitSurvivesTheVault(t *testing.T) {
	extra := url.QueryEscape(`{"downloadSettings":{"address":"down.example.com","port":8443}}`)
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@edge.example.com:443?security=tls" +
		"&type=xhttp&mode=stream-up&extra=" + extra + "#X"
	result, err := parser.LinkParser{}.Parse([]byte(link))
	if err != nil || len(result.Servers) != 1 {
		t.Fatalf("Parse = %+v, %v", result, err)
	}
	document, err := credentialDocument(result.Servers[0])
	if err != nil {
		t.Fatal(err)
	}
	values, err := parseCredential(document)
	if err != nil {
		t.Fatal(err)
	}
	var o engine.Outbound
	if err := applyCredential(&o, values); err != nil {
		t.Fatal(err)
	}
	tr := o.Transport
	if tr.XHTTPOrZero().DownloadAddress != "down.example.com" || tr.XHTTPOrZero().DownloadPort != 8443 {
		t.Errorf("XHTTP download split lost on the way to the engine: %+v", tr)
	}
}
