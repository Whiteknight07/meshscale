package secureroute

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// overlay mirrors secure.OverlayRange, which this package cannot import.
var overlay = &net.IPNet{IP: net.ParseIP("fd6d:6573:6873::"), Mask: net.CIDRMask(48, 128)}

// errNoLink means there is no kernel secure link: secure mode is off or runs
// in a private userspace netstack.
var errNoLink = errors.New("no kernel secure link")

// routeReader returns the secure overlay route as "present", "congctl <algo>",
// or "" when the link exists but the route is missing.
type routeReader func(context.Context) (string, error)

func netlinkSecureRoute(context.Context) (string, error) {
	link, err := netlink.LinkByName("meshsecure0")
	if _, missing := err.(netlink.LinkNotFoundError); missing {
		return "", errNoLink
	}
	if err != nil {
		return "", err
	}
	routes, err := netlink.RouteListFiltered(unix.AF_INET6, &netlink.Route{LinkIndex: link.Attrs().Index, Dst: overlay}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_DST)
	if err != nil {
		return "", err
	}
	if len(routes) == 0 {
		return "", nil
	}
	if routes[0].Congctl != "" {
		return "congctl " + routes[0].Congctl, nil
	}
	return "present", nil
}

// Status reports the installed route rather than merely module availability.
// This is a control-plane query, never part of TCP forwarding or packet lookup.
func Status() string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return status(ctx, netlinkSecureRoute)
}

func status(ctx context.Context, read routeReader) string {
	out, err := read(ctx)
	switch {
	case errors.Is(err, errNoLink):
		return "not applicable (no kernel secure link)"
	case err != nil:
		return "unknown (secure route query unavailable)"
	}
	return describe(out)
}

func describe(route string) string {
	if strings.TrimSpace(route) == "" {
		return "route missing"
	}
	fields := strings.Fields(route)
	for i, field := range fields {
		if field == "congctl" && i+1 < len(fields) {
			return fields[i+1] + " (secure routes only)"
		}
	}
	return "kernel default (per-route BBR unavailable)"
}
