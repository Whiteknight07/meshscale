// Package routes plans Mesh subnet advertisements without changing host routes.
package routes

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

const marker = "meshscale route: "

func Owned(r cfapi.Route) bool { return r.Comment == marker+r.Network && r.DeletedAt == nil }

// Parse canonicalizes networks and rejects addresses, default routes and
// duplicates. Subnet advertisement must not replace the Mesh device ranges.
func Parse(value string) ([]netip.Prefix, error) {
	var result []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, s := range strings.Split(value, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil || p.Bits() == 0 || p.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid subnet CIDR %q (default routes and mapped IPv6 are unsupported)", s)
		}
		p = p.Masked()
		for _, reserved := range []netip.Prefix{meshaddr.IPv4Range, netip.MustParsePrefix("2606:4700:cf1::/48")} {
			if p.Overlaps(reserved) {
				return nil, fmt.Errorf("subnet %s overlaps the Mesh range %s", p, reserved)
			}
		}
		if seen[p] {
			return nil, fmt.Errorf("duplicate subnet %s", p)
		}
		seen[p] = true
		result = append(result, p)
	}
	return result, nil
}

// Plan validates the entire request before returning any creates. Exact route
// collisions in any virtual network require review; we never adopt them.
func Plan(prefixes []netip.Prefix, node string, existing []cfapi.Route) ([]cfapi.CreateRouteParams, error) {
	if node == "" {
		return nil, fmt.Errorf("a Mesh node ID is required")
	}
	var creates []cfapi.CreateRouteParams
	for _, p := range prefixes {
		found := false
		for _, r := range existing {
			if r.DeletedAt != nil {
				continue
			}
			network, err := netip.ParsePrefix(r.Network)
			if err != nil {
				return nil, fmt.Errorf("existing route %q has an invalid CIDR", r.ID)
			}
			if network.Masked() != p {
				continue
			}
			if r.TunnelID != node || !Owned(r) {
				return nil, fmt.Errorf("route %s already exists and is not owned on this node; review it with routes list", p)
			}
			found = true
		}
		if !found {
			creates = append(creates, cfapi.CreateRouteParams{Network: p.String(), TunnelID: node, Comment: marker + p.String()})
		}
	}
	return creates, nil
}

func Removal(prefix netip.Prefix, existing []cfapi.Route) (cfapi.Route, error) {
	var found []cfapi.Route
	for _, r := range existing {
		if r.DeletedAt != nil {
			continue
		}
		p, err := netip.ParsePrefix(r.Network)
		if err != nil || p.Masked() != prefix {
			continue
		}
		found = append(found, r)
	}
	if len(found) != 1 {
		return cfapi.Route{}, fmt.Errorf("expected one active route for %s, found %d; review routes list", prefix, len(found))
	}
	if !Owned(found[0]) || found[0].ID == "" {
		return cfapi.Route{}, fmt.Errorf("refusing to remove unowned or unidentified route %s", prefix)
	}
	return found[0], nil
}
