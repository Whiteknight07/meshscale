package rules

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
	"github.com/Whiteknight07/meshscale/internal/secure"
)

// CompileSecure places the authenticated overlay's UDP carrier before Mesh's
// default deny. Gateway cannot enforce inner port rules on encrypted payloads;
// SSH still enforces its local identity/user policy. No exception is emitted
// without an explicit rules file or without two enabled, active secure peers.
func CompileSecure(p *Policy, participants []Participant, meshIPs []netip.Addr) ([]cfapi.GatewayRule, error) {
	base, err := Compile(p, participants)
	if err != nil || p == nil {
		return base, err
	}
	var ips []string
	for _, ip := range meshIPs {
		if !meshaddr.IsIPv4(ip) {
			return nil, fmt.Errorf("secure carrier requires Mesh IPv4 endpoints")
		}
		ips = append(ips, netip.PrefixFrom(ip, 32).String())
	}
	ips = unique(ips)
	sort.Strings(ips)
	if len(ips) < 2 {
		return base, nil
	}
	carrier := networkRule("secure-wireguard", "allow", ipExpression("src", ips)+" and "+ipExpression("dst", ips)+fmt.Sprintf(" and net.ip.proto == 17 and net.dst.port == %d", secure.Port))
	if len(carrier.Traffic) > 140000 {
		return nil, fmt.Errorf("secure carrier exceeds Gateway expression limit")
	}
	return append([]cfapi.GatewayRule{carrier}, base...), nil
}
