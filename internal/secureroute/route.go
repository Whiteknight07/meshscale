// Package secureroute applies optional TCP tuning only to owned secure routes.
package secureroute

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/vishvananda/netlink"
)

// Exec executes a command without changing sysctls, underlay routes or qdiscs.
type Exec func(name string, args ...string) error

// Command adapts os/exec to the route installer.
func Command(ctx context.Context) Exec {
	return func(name string, args ...string) error {
		if out, err := exec.CommandContext(ctx, name, args...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w: %s", name, err, out)
		}
		return nil
	}
}

// Runner is the command runner used by exit routing.
type Runner interface {
	Run(context.Context, string, string, ...string) ([]byte, error)
}

// FromRunner adapts a runner that accepts stdin and returns command output.
func FromRunner(ctx context.Context, run Runner) Exec {
	return func(name string, args ...string) error {
		_, err := run.Run(ctx, "", name, args...)
		return err
	}
}

// Install tries route-local BBR, requests tcp_bbr if necessary, then falls back
// to the original route. Route deletion removes the tuning. Callers supply
// command execution so fallback/error paths never mutate real hosts in tests.
func Install(exec Exec, ipArgs ...string) error {
	tuned := append(append([]string(nil), ipArgs...), "congctl", "bbr")
	if err := exec("ip", tuned...); err == nil {
		return nil
	}
	if exec("modprobe", "tcp_bbr") == nil {
		if err := exec("ip", tuned...); err == nil {
			return nil
		}
	}
	if err := exec("ip", ipArgs...); err != nil {
		return fmt.Errorf("install secure route: %w", err)
	}
	return nil
}

// Replace is Install for callers that build routes with netlink: it replaces
// route with route-local BBR, requesting tcp_bbr once if needed, and falls back
// to the untuned route.
func Replace(exec Exec, route netlink.Route) error {
	route.Congctl = "bbr"
	if netlink.RouteReplace(&route) == nil {
		return nil
	}
	if exec("modprobe", "tcp_bbr") == nil && netlink.RouteReplace(&route) == nil {
		return nil
	}
	route.Congctl = ""
	return netlink.RouteReplace(&route)
}
