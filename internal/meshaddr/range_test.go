package meshaddr

import (
	"net/netip"
	"testing"
)

func TestIsDevice(t *testing.T) {
	for _, tc := range []struct {
		address string
		want    bool
	}{
		{"100.96.0.1", true},
		{"::ffff:100.96.0.1", true},
		{"2606:4700:cf1:1000::1", true},
		{"2606:4700:cf1:2000::1", false}, // the WARP client's own address
		{"2606:4700:cf1:1000::1%eth0", false},
		{"100.64.0.1", false},
		{"127.0.0.1", false},
		{"1.1.1.1", false},
		{"::1", false},
	} {
		if got := IsDevice(netip.MustParseAddr(tc.address)); got != tc.want {
			t.Errorf("IsDevice(%s) = %v", tc.address, got)
		}
	}
}
