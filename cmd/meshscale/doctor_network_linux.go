//go:build linux

package main

import (
	"context"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
)

func doctorWARPInterface(context.Context) (string, error) {
	_, err := net.InterfaceByName("CloudflareWARP")
	return "CloudflareWARP", err
}
func doctorMeshRoute(ctx context.Context, d *doctorInputs) doctorCheck {
	name := "CloudflareWARP"
	if b, err := d.local.get(ctx); err == nil && b.settings.Backend == "native" {
		name = "meshscale0"
	}
	s, err := d.network.get(ctx)
	if err != nil {
		return doctorResult("warn", "netlink route/rule snapshot unavailable", "inspect ip -4 rule and ip -4 route show table all")
	}
	found := false
	for _, route := range s.V4.Routes {
		if route.Dev == name && route.Dst == "100.96.0.0/12" && (route.Type == "" || route.Type == "unicast") {
			found = true
		}
	}
	if !found {
		return doctorResult("fail", "no 100.96.0.0/12 route on "+name, "check the selected backend's connection and Mesh routes")
	}
	routes, err := netlink.RouteGet(net.ParseIP("100.96.0.1"))
	if err != nil || len(routes) == 0 {
		return doctorResult("fail", "effective route lookup for 100.96.0.1 unavailable", "inspect policy routing for the Mesh prefix")
	}
	iface, err := net.InterfaceByIndex(routes[0].LinkIndex)
	if err != nil || iface.Name != name {
		return doctorResult("fail", "Mesh prefix route exists but sample 100.96.0.1 is captured elsewhere", "inspect earlier policy rules and competing VPN routes")
	}
	return doctorResult("ok", "100.96.0.0/12 installed on "+name+"; sample 100.96.0.1 selects "+name, "check a specific peer route separately if addresses overlap")
}
func doctorOverlap(ctx context.Context, d *doctorInputs) doctorCheck {
	s, err := d.network.get(ctx)
	if err != nil {
		return doctorResult("warn", "coexistence snapshot unavailable", "inspect ip -4 rule and iptables -S ts-input with existing read permission")
	}
	result := doctorOverlapRule(s)
	if !doctorHasLink(s, "tailscale0") || result.Status == "fail" {
		return result
	}
	out, err := doctorCommand(ctx, "iptables", "-w", "1", "-S", "ts-input")
	if err != nil {
		if strings.Contains(string(out), "No chain/target/match") || strings.Contains(string(out), "does not exist") {
			result.Detail += "; no iptables ts-input chain"
			return result
		}
		if result.Status == "ok" {
			result.Status = "warn"
		}
		result.Detail += "; ingress rule unreadable with current permissions"
		result.Hint = "inspect ts-input using an account that already has read permission"
		return result
	}
	if !doctorFirstIngressRule(string(out)) {
		return doctorResult("fail", result.Detail+"; narrow WARP ingress RETURN is not first", "inspect the daemon's coexistence error and ts-input rule order")
	}
	result.Detail += "; narrow WARP ingress RETURN is first"
	return result
}
