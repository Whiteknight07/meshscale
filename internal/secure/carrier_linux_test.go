//go:build linux

package secure

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// fakeIPTables emulates the INPUT chain and carrierChain of one table per
// binary, enough for installCarrierRules.
type fakeIPTables struct {
	input map[string][]string
	chain map[string][]string // nil slice: chain absent
	made  map[string]bool
}

func (f *fakeIPTables) run(_ context.Context, binary string, args ...string) ([]byte, error) {
	notFound := func() ([]byte, error) {
		err := exec.Command("false").Run() // a real exit status 1
		return []byte("Bad rule"), err
	}
	rule := strings.Join(args[1:], " ")
	switch args[0] {
	case "-S":
		var out []string
		for _, r := range f.input[binary] {
			out = append(out, "-A INPUT "+r)
		}
		return []byte(strings.Join(out, "\n")), nil
	case "-N":
		if f.made[binary] {
			return []byte("Chain already exists."), errors.New("exit status 1")
		}
		f.made[binary] = true
	case "-F":
		f.chain[binary] = nil
	case "-X":
		f.made[binary] = false
	case "-A":
		f.chain[binary] = append(f.chain[binary], strings.Join(args[2:], " "))
	case "-I":
		f.input[binary] = append([]string{strings.Join(args[3:], " ")}, f.input[binary]...)
	case "-C", "-D":
		i := slices.Index(f.input[binary], strings.Join(args[2:], " "))
		if args[1] != "INPUT" || i < 0 {
			return notFound()
		}
		if args[0] == "-D" {
			f.input[binary] = slices.Delete(f.input[binary], i, i+1)
		}
	default:
		return nil, errors.New("unexpected " + rule)
	}
	return nil, nil
}

func TestCarrierRulesFollowMeshAddress(t *testing.T) {
	port := strconv.Itoa(Port)
	legacy := `! -d 100.96.0.7/32 -p udp -m udp --dport ` + port + ` -m comment --comment "meshscale secure carrier" -j DROP`
	f := &fakeIPTables{
		input: map[string][]string{"iptables": {"-j ACCEPT", legacy}},
		chain: map[string][]string{},
		made:  map[string]bool{},
	}
	// The fake matches -D on its literal arguments, so record what the legacy
	// cleanup asked to delete.
	var deleted []string
	run := func(ctx context.Context, binary string, args ...string) ([]byte, error) {
		if args[0] == "-D" && slices.Contains(args, carrierComment) {
			deleted = append(deleted, strings.Join(args, " "))
			f.input[binary] = slices.DeleteFunc(f.input[binary], func(r string) bool { return r == legacy })
			return nil, nil
		}
		return f.run(ctx, binary, args...)
	}

	for _, ip := range []string{"100.96.0.7", "100.96.0.9"} {
		if _, err := installCarrierRules(t.Context(), run, netip.MustParseAddr(ip)); err != nil {
			t.Fatal(err)
		}
	}
	jump := "-p udp --dport " + port + " -j " + carrierChain
	if want := []string{jump, "-j ACCEPT"}; !slices.Equal(f.input["iptables"], want) {
		t.Fatalf("INPUT = %q; want %q", f.input["iptables"], want)
	}
	if !slices.Contains(f.chain["iptables"], "! -d 100.96.0.9 -j DROP") || len(f.chain["iptables"]) != 2 {
		t.Fatalf("chain kept stale address: %q", f.chain["iptables"])
	}
	if len(deleted) != 1 || !strings.Contains(deleted[0], "-D INPUT ! -d 100.96.0.7/32") {
		t.Fatalf("legacy cleanup = %q", deleted)
	}

	cleanup, err := installCarrierRules(t.Context(), run, netip.MustParseAddr("100.96.0.9"))
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	for _, binary := range []string{"iptables", "ip6tables"} {
		if slices.Contains(f.input[binary], jump) || f.made[binary] {
			t.Fatalf("%s left carrier state: %q", binary, f.input[binary])
		}
	}
}

// Run inside a throwaway namespace:
// MESHSCALE_LIVE_CARRIER=1 ip netns exec <ns> go test -run CarrierRulesLive ./internal/secure
func TestCarrierRulesLive(t *testing.T) {
	if os.Getenv("MESHSCALE_LIVE_CARRIER") != "1" {
		t.Skip("set MESHSCALE_LIVE_CARRIER=1 inside a network namespace")
	}
	port := strconv.Itoa(Port)
	legacy := []string{"-I", "INPUT", "!", "-d", "100.96.0.7/32", "-p", "udp", "--dport", port, "-m", "comment", "--comment", carrierComment, "-j", "DROP"}
	if out, err := runIPTables(t.Context(), "iptables", legacy...); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	cleanup, err := installCarrierRules(t.Context(), runIPTables, netip.MustParseAddr("100.96.0.9"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := installCarrierRules(t.Context(), runIPTables, netip.MustParseAddr("100.96.0.9")); err != nil {
		t.Fatal(err)
	}
	for _, binary := range []string{"iptables", "ip6tables"} {
		out, _ := runIPTables(t.Context(), binary, "-S")
		if strings.Contains(string(out), carrierComment) || strings.Count(string(out), "-j "+carrierChain) != 1 {
			t.Fatalf("%s rules:\n%s", binary, out)
		}
		t.Logf("%s:\n%s", binary, out)
	}
	cleanup()
	for _, binary := range []string{"iptables", "ip6tables"} {
		if out, _ := runIPTables(t.Context(), binary, "-S"); strings.Contains(string(out), carrierChain) {
			t.Fatalf("%s left:\n%s", binary, out)
		}
	}
}
