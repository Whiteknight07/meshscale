package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/exitnode"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

func isDoctorMeshIP(ip netip.Addr) bool { return meshaddr.IsDevice(ip) }
func (d *doctorInputs) checkRoute(ctx context.Context) doctorCheck {
	if b, err := d.local.get(ctx); err == nil && b.settings.Backend == "native" && b.settings.Userspace {
		return doctorResult("warn", "native userspace routes live in a private stack; kernel route check is not applicable", "use meshscale ping to test the native transport")
	}
	return doctorMeshRoute(ctx, d)
}
func (d *doctorInputs) checkOverlap(ctx context.Context) doctorCheck { return doctorOverlap(ctx, d) }
func (d *doctorInputs) checkMTU(ctx context.Context) doctorCheck {
	name := ""
	b, err := d.local.get(ctx)
	if err == nil && b.settings.Backend == "native" {
		if b.settings.Userspace {
			return doctorResult("warn", "native userspace MTU lives in a private stack; no host tunnel interface", "test the intended service through meshscale ping or ssh")
		}
		name = "meshscale0"
	} else {
		name, err = doctorWARPInterface(ctx)
	}
	if err != nil {
		return doctorResult("warn", "WARP interface unavailable", "connect the official client and inspect its interface")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return doctorResult("fail", name+" interface details unavailable", "inspect the selected backend's tunnel interface")
	}
	level := "ok"
	if iface.MTU < 1280 || iface.MTU > 1500 {
		level = "warn"
	}
	return doctorResult(level, fmt.Sprintf("%s MTU %d; path MTU untested", name, iface.MTU), "investigate MTU if small connects work but larger transfers stall")
}
func doctorHasLink(s exitnode.Snapshot, name string) bool {
	for _, link := range s.Links {
		if link.Name == name {
			return true
		}
	}
	return false
}
func doctorWarpTables(s exitnode.Snapshot) map[string]bool {
	tables := map[string]bool{}
	for _, r := range s.V4.Routes {
		if r.Dev == "CloudflareWARP" && r.Dst == meshaddr.IPv4Range.String() && (r.Type == "" || r.Type == "unicast") {
			tables[fmt.Sprint(r.Table)] = true
		}
	}
	return tables
}
func doctorOverlapRule(s exitnode.Snapshot) doctorCheck {
	hint := "inspect meshscale service status and the Mesh/Tailscale overlap rule"
	if !doctorHasLink(s, "tailscale0") {
		return doctorResult("ok", "tailscale0 absent; overlap exception unnecessary", "recheck coexistence after connecting Tailscale")
	}
	tables := doctorWarpTables(s)
	priority := 0
	for _, rule := range s.V4.Rules {
		inverted := string(rule.Not) == "true"
		if tables[fmt.Sprint(rule.Table)] && inverted && rule.FWMark != "" && rule.Priority > 1 && (priority == 0 || rule.Priority < priority) {
			priority = rule.Priority
		}
	}
	for _, route := range s.V4.Routes {
		if fmt.Sprint(route.Table) == "52" && (route.Dst == "default" || route.Dst == "0.0.0.0/0" || route.Dst == "0.0.0.0/1" || route.Dst == "128.0.0.0/1") {
			return doctorResult("warn", "Tailscale table 52 has an exit/default route; overlap exception is unsafe", "disable one exit selection before relying on simultaneous Mesh routing")
		}
	}
	if priority == 0 {
		return doctorResult("warn", "no inverted marked WARP lookup found; overlap order unverified", hint)
	}
	for _, rule := range s.V4.Rules {
		if fmt.Sprint(rule.Table) == "52" && rule.Dst == "100.96.0.0" && rule.DstLen == 12 && rule.Priority < priority && rule.Priority > 0 && rule.FWMark == "" && len(rule.Not) == 0 {
			return doctorResult("ok", fmt.Sprintf("Mesh prefix checks table 52 at %d before WARP at %d", rule.Priority, priority), "retain the narrow overlap rule while both clients run")
		}
	}
	return doctorResult("fail", fmt.Sprintf("no Mesh-prefix table-52 exception before WARP priority %d", priority), hint)
}
func doctorFirstIngressRule(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, "-A ts-input ") {
			continue
		}
		return strings.Contains(line, "-s 100.96.0.0/12 ") && strings.Contains(line, "-i CloudflareWARP ") && strings.Contains(line, "meshscale Mesh coexistence") && strings.HasSuffix(line, "-j RETURN")
	}
	return false
}
