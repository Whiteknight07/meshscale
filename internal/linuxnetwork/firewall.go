// Package linuxnetwork owns the official Linux client's Tailscale coexistence rules.
package linuxnetwork

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

// Manager owns only meshscale's tagged rule, never Tailscale's configuration.
type Manager interface {
	Reconcile(context.Context) error
	Cleanup(context.Context) error
}

type commandFunc func(context.Context, string, ...string) ([]byte, error)

type firewall struct {
	run          commandFunc
	hasInterface func(string) bool
	routing      *routingManager
}

func New() Manager {
	return &firewall{
		routing: &routingManager{run: newRoutingRunner(), warn: log.Printf},
		run: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, path, args...).CombinedOutput()
		},
		hasInterface: func(name string) bool { _, err := net.InterfaceByName(name); return err == nil },
	}
}

// Reconcile returns Mesh ingress from ts-input before its CGNAT anti-spoof
// drop, preserving the remainder of INPUT and any other host firewall tables.
func (f *firewall) Reconcile(ctx context.Context) error {
	if !f.hasInterface("tailscale0") || !f.hasInterface("CloudflareWARP") {
		return f.reconcileRouting(ctx, false)
	}
	return errors.Join(f.reconcileRouting(ctx, true), f.apply(ctx, false))
}

// Cleanup works even after WARP or Tailscale removed its interface.
func (f *firewall) Cleanup(ctx context.Context) error {
	var routeErr error
	if f.routing != nil && f.routing.run != nil {
		routeErr = f.routing.cleanup(ctx)
	}
	return errors.Join(routeErr, f.apply(ctx, true))
}

func (f *firewall) apply(ctx context.Context, remove bool) error {
	run := f.run
	output, err := run(ctx, "iptables", "-w", "5", "-S", "ts-input")
	if err != nil {
		// Tailscale may be stopped, use nodivert/off, or have no iptables chain.
		// Never create its chain or alter the INPUT jump on its behalf.
		missingBinary := remove && errors.Is(err, exec.ErrNotFound)
		missingChain := strings.Contains(string(output), "No chain/target/match by that name") || strings.Contains(string(output), "does not exist")
		if missingBinary || missingChain {
			return nil
		}
		return fmt.Errorf("inspect Tailscale input chain: %w: %s", err, strings.TrimSpace(string(output)))
	}
	rule := []string{"-i", "CloudflareWARP", "-s", meshaddr.IPv4Range.String(), "-m", "comment", "--comment", "meshscale Mesh coexistence", "-j", "RETURN"}
	output, err = run(ctx, "iptables", append([]string{"-w", "5", "-C", "ts-input"}, rule...)...)
	if err == nil && !remove {
		return nil
	}
	if err == nil {
		output, err = run(ctx, "iptables", append([]string{"-w", "5", "-D", "ts-input"}, rule...)...)
		if err != nil {
			return fmt.Errorf("remove Mesh coexistence rule: %w: %s", err, strings.TrimSpace(string(output)))
		}
		return nil
	}
	var status interface{ ExitCode() int }
	if !errors.As(err, &status) || status.ExitCode() != 1 {
		return fmt.Errorf("check Mesh coexistence rule: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if remove {
		return nil
	}
	output, err = run(ctx, "iptables", append([]string{"-w", "5", "-I", "ts-input", "1"}, rule...)...)
	if err != nil {
		return fmt.Errorf("install Mesh coexistence rule: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (f *firewall) reconcileRouting(ctx context.Context, enabled bool) error {
	if f.routing == nil || f.routing.run == nil {
		return nil
	}
	return f.routing.reconcile(ctx, enabled)
}
