package subscription

import (
	"context"
	"testing"
	"time"
)

func TestAFetchFromTheInternetNeverReachesALocalAddress(t *testing.T) {
	for _, address := range []string{"127.0.0.1:443", "[::1]:443", "10.0.0.5:443", "192.168.1.1:443", "169.254.169.254:80", "[fe80::1]:443", "0.0.0.0:443",
		// Special-use ranges that IsGlobalUnicast accepts but that never host
		// a server: CGNAT, benchmarking, and the documentation pools Sora
		// uses for its own TUN adapters.
		"100.64.0.5:443", "192.0.2.1:443", "198.51.100.7:443", "203.0.113.9:443",
		"198.18.0.4:443", "[2001:db8::1]:443"} {
		if checkDial(false, address) == nil {
			t.Errorf("%s was dialled for a subscription on the internet", address)
		}
	}
	if err := checkDial(false, "93.184.216.34:443"); err != nil {
		t.Errorf("a public address was refused: %v", err)
	}
	if err := checkDial(true, "192.168.1.1:443"); err != nil {
		t.Errorf("a subscription on the local network could not reach it: %v", err)
	}
}

func TestALocalSubscriptionIsRecognised(t *testing.T) {
	ctx := t.Context()
	for host, want := range map[string]bool{"127.0.0.1": true, "192.168.0.10": true, "localhost": true, "93.184.216.34": false} {
		if got := isPrivateHost(ctx, host); got != want {
			t.Errorf("isPrivateHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestTheDialerHonoursTheFetcherTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{time.Second, 42 * time.Second} {
		if got := checkedDialer(timeout, false).Timeout; got != timeout {
			t.Errorf("checkedDialer(%v).Timeout = %v", timeout, got)
		}
	}
}

func TestADialIsBoundByTheFetcherTimeout(t *testing.T) {
	// 10.255.255.1 never answers: the dial must die on the 300ms budget,
	// not on the old fixed 30s dial timeout.
	dial := dialChecked(300 * time.Millisecond)
	ctx := context.WithValue(t.Context(), privateKey{}, true)
	start := time.Now()
	_, _ = dial(ctx, "tcp", "10.255.255.1:443")
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("a dial with a 300ms budget took %v", elapsed)
	}
}
