//go:build !linux

package main

import (
	"context"
	"errors"
	"runtime"
	"strings"
)

func doctorWARPInterface(ctx context.Context) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", errors.New("route inspection unsupported")
	}
	out, err := doctorCommand(ctx, "route", "-n", "get", "-inet", "100.96.0.1")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		key, value, _ := strings.Cut(strings.TrimSpace(line), ":")
		if key == "interface" && strings.HasPrefix(strings.TrimSpace(value), "utun") {
			return strings.TrimSpace(value), nil
		}
	}
	return "", errors.New("Mesh sample does not select a utun interface")
}
func doctorMeshRoute(ctx context.Context, _ *doctorInputs) doctorCheck {
	name, err := doctorWARPInterface(ctx)
	if err != nil {
		return doctorResult("warn", "Mesh sample route unavailable or not on utun", "inspect route -n get 100.96.0.1 while WARP is connected")
	}
	return doctorResult("warn", "100.96.0.1 selects "+name+"; WARP ownership and full prefix unverified", "compare WARP's tunnel interface and netstat -rn -f inet")
}
func doctorOverlap(context.Context, *doctorInputs) doctorCheck {
	return doctorResult("warn", "Linux policy/iptables exception is not applicable on this OS", "inspect routes to overlapping Tailscale peers with both clients connected")
}
