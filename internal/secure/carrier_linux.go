//go:build linux

package secure

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

const (
	carrierChain   = "MESHSCALE-SECURE"
	carrierComment = "meshscale secure carrier"
)

// iptablesRunner runs one iptables or ip6tables command and returns its
// combined output.
type iptablesRunner func(ctx context.Context, binary string, args ...string) ([]byte, error)

func runIPTables(ctx context.Context, binary string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, binary, append([]string{"-w"}, args...)...).CombinedOutput()
}

// Kernel WG has wildcard UDP sockets. Scope its exclusive port to this Mesh
// address/range before exposing the engine, preserving the original carrier's
// Mesh-only receive boundary. Invalid traffic is dropped before existing accepts.
func restrictCarrier(ctx context.Context, local netip.Addr) (func(), error) {
	return installCarrierRules(ctx, runIPTables, local)
}

// installCarrierRules owns a dedicated chain, rebuilt on every start, so rules
// for a previous Mesh address never survive an address change or a crash.
func installCarrierRules(ctx context.Context, run iptablesRunner, local netip.Addr) (func(), error) {
	port := strconv.Itoa(Port)
	jump := []string{"INPUT", "-p", "udp", "--dport", port, "-j", carrierChain}
	chains := map[string][][]string{
		"iptables": {
			{"!", "-d", local.String(), "-j", "DROP"},
			{"!", "-s", meshaddr.IPv4Range.String(), "-j", "DROP"},
		},
		"ip6tables": {{"-j", "DROP"}},
	}
	cleanup := func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for binary := range chains {
			removeCarrierChain(c, run, binary, jump)
		}
	}
	for _, binary := range []string{"iptables", "ip6tables"} {
		removeLegacyCarrierRules(ctx, run, binary)
		if out, err := run(ctx, binary, "-N", carrierChain); err != nil && !strings.Contains(string(out), "exists") {
			cleanup()
			return nil, fmt.Errorf("create secure carrier chain: %w: %s", err, out)
		}
		if out, err := run(ctx, binary, "-F", carrierChain); err != nil {
			cleanup()
			return nil, fmt.Errorf("flush secure carrier chain: %w: %s", err, out)
		}
		for _, rule := range chains[binary] {
			if out, err := run(ctx, binary, append([]string{"-A", carrierChain}, rule...)...); err != nil {
				cleanup()
				return nil, fmt.Errorf("restrict secure kernel carrier: %w: %s", err, out)
			}
		}
		present, err := ruleExists(ctx, run, binary, jump)
		if err != nil {
			cleanup()
			return nil, err
		}
		if !present {
			if out, err := run(ctx, binary, append([]string{"-I", "INPUT", "1"}, jump[1:]...)...); err != nil {
				cleanup()
				return nil, fmt.Errorf("restrict secure kernel carrier: %w: %s", err, out)
			}
		}
	}
	return cleanup, nil
}

// ruleExists reports whether iptables -C finds rule; it exits 1 when absent.
func ruleExists(ctx context.Context, run iptablesRunner, binary string, rule []string) (bool, error) {
	out, err := run(ctx, binary, append([]string{"-C"}, rule...)...)
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("check secure carrier firewall rule: %w: %s", err, out)
}

func removeCarrierChain(ctx context.Context, run iptablesRunner, binary string, jump []string) {
	for {
		if _, err := run(ctx, binary, append([]string{"-D"}, jump...)...); err != nil {
			break
		}
	}
	_, _ = run(ctx, binary, "-F", carrierChain)
	_, _ = run(ctx, binary, "-X", carrierChain)
}

// removeLegacyCarrierRules deletes INPUT rules that older versions inserted
// directly, tagged with carrierComment and bound to whatever Mesh IP was
// current then.
func removeLegacyCarrierRules(ctx context.Context, run iptablesRunner, binary string) {
	out, err := run(ctx, binary, "-S", "INPUT")
	if err != nil {
		return
	}
	quoted := strconv.Quote(carrierComment)
	for _, line := range strings.Split(string(out), "\n") {
		rest, ok := strings.CutPrefix(line, "-A INPUT ")
		if !ok || !strings.Contains(rest, quoted) {
			continue
		}
		before, after, _ := strings.Cut(rest, quoted)
		args := append([]string{"-D", "INPUT"}, strings.Fields(before)...)
		args = append(append(args, carrierComment), strings.Fields(after)...)
		_, _ = run(ctx, binary, args...)
	}
}
