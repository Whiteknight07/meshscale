package rules

import (
	"net/netip"
	"strings"
	"testing"
)

func TestCompileSecure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy *Policy
		ips    []string
		want   int
		bad    bool
	}{
		{"no policy", nil, []string{"100.96.0.1", "100.96.0.2"}, 0, false},
		{"no peers", &Policy{}, nil, 1, false},
		{"one peer", &Policy{}, []string{"100.96.0.1"}, 1, false},
		{"two peers", &Policy{}, []string{"100.96.0.1", "100.96.0.2"}, 2, false},
		{"public endpoint", &Policy{}, []string{"1.1.1.1", "100.96.0.2"}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ips []netip.Addr
			for _, s := range tc.ips {
				ips = append(ips, netip.MustParseAddr(s))
			}
			got, err := CompileSecure(tc.policy, nil, ips)
			if (err != nil) != tc.bad {
				t.Fatalf("error=%v", err)
			}
			if tc.bad {
				return
			}
			if len(got) != tc.want {
				t.Fatalf("rules=%+v", got)
			}
			if len(got) == 2 && (Owner(got[0]) != "secure-wireguard" || got[0].Action != "allow" || !strings.Contains(got[0].Traffic, "net.ip.proto == 17 and net.dst.port == 51821") || Owner(got[1]) != "default-deny") {
				t.Fatalf("incorrect order/carrier: %+v", got)
			}
		})
	}
}
