package probe

import "testing"

// TestCheckDialTargetClosesTheRebindingWindow is the regression test for
// R5-LG-1-2: isPrivateTarget resolves once and the dial resolves again, so
// a hostile resolver could swap a public answer for a private one between
// the two. The dial's Control hook re-checks the address actually dialled.
func TestCheckDialTargetClosesTheRebindingWindow(t *testing.T) {
	for _, address := range []string{"10.0.0.5:443", "192.168.1.1:443", "169.254.169.254:80", "[::1]:443",
		"100.64.0.5:443", "192.0.2.1:443", "198.18.0.4:443", "[2001:db8::1]:443",
		"0.0.0.1:443", "0.1.2.3:443", "240.0.0.1:443", "240.255.255.255:443"} {
		if err := checkDialTarget(false, address); err == nil {
			t.Errorf("checkDialTarget(false, %q) = nil, want a rejection", address)
		}
	}
	if err := checkDialTarget(false, "93.184.216.34:443"); err != nil {
		t.Errorf("checkDialTarget(false, public) = %v, want nil", err)
	}
	if err := checkDialTarget(true, "10.0.0.5:443"); err != nil {
		t.Errorf("checkDialTarget(true, private) = %v, want nil", err)
	}
}
