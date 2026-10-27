package main

import (
	"context"
	"net/netip"
	"time"

	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
	"github.com/Whiteknight07/meshscale/internal/reachability"
	"github.com/Whiteknight07/meshscale/internal/service"
)

func staleDevice(d meshDevice, now time.Time) bool {
	return !d.Online && !recentlySeen(d.LastSeenAt, now) && !(d.ThisMachine && d.Backend != "")
}

func statusProbeIPs(devices []meshDevice, now time.Time) []netip.Addr {
	var ips []netip.Addr
	seen := make(map[netip.Addr]bool)
	for _, d := range devices {
		if !staleDevice(d, now) {
			continue
		}
		for _, address := range []string{d.IPv4, d.IPv6} {
			ip, err := netip.ParseAddr(address)
			if err == nil && meshaddr.IsDevice(ip) && !seen[ip] {
				ips = append(ips, ip)
				seen[ip] = true
			}
		}
	}
	return ips
}

// Prefer the daemon's shared cache. Older or absent daemons fall back to a
// bounded local check. The caller overlaps this work with other status API reads.
func statusReachability(ctx context.Context, ips []netip.Addr) map[string]bool {
	if len(ips) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	ips = ips[:min(len(ips), service.MaxReachabilityAddresses)]
	if dir, err := config.ServiceDir(); err == nil {
		addresses := make([]string, len(ips))
		for i, ip := range ips {
			addresses[i] = ip.String()
		}
		var results map[string]bool
		if err := service.Request(ctx, dir, "POST", "/reachability", addresses, &results); err == nil {
			return results
		}
	}
	return reachability.New(reachability.Network{}).Check(ctx, ips)
}

func applyProbeResults(devices []meshDevice, results map[string]bool, now time.Time) {
	for i := range devices {
		d := &devices[i]
		if staleDevice(*d, now) && (results[d.IPv4] || results[d.IPv6]) {
			d.Online, d.OnlineSource = true, "probe"
		}
	}
}
