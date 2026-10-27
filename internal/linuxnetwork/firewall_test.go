package linuxnetwork

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"testing"
)

type firewallExit int

func (e firewallExit) Error() string { return "iptables failed" }
func (e firewallExit) ExitCode() int { return int(e) }

func TestFirewallLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		operations                    []string
		noInterface, noChain, present bool
		fail                          string
		wantInserts, wantDeletes      int
		wantError                     bool
	}{
		{name: "absent chain", operations: []string{"up", "down"}, noChain: true},
		{name: "absent interface", operations: []string{"up"}, noInterface: true},
		{name: "existing rule", operations: []string{"up"}, present: true},
		{name: "idempotent roundtrip", operations: []string{"up", "up", "down", "down"}, wantInserts: 1, wantDeletes: 1},
		{name: "Tailscale recreates chain", operations: []string{"up", "restart", "up", "down"}, wantInserts: 2, wantDeletes: 1},
		{name: "cleanup after interface removal", operations: []string{"down", "down"}, present: true, noInterface: true, wantDeletes: 1},
		{name: "inspect denied", operations: []string{"up"}, fail: "-S", wantError: true},
		{name: "check denied", operations: []string{"up"}, fail: "-C", wantError: true},
		{name: "insert failed", operations: []string{"up"}, fail: "-I", wantError: true},
		{name: "delete failed", operations: []string{"down"}, present: true, fail: "-D", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			present, inserts, deletes := tc.present, 0, 0
			failure := firewallExit(4)
			f := &firewall{hasInterface: func(string) bool { return !tc.noInterface }}
			f.run = func(_ context.Context, path string, args ...string) ([]byte, error) {
				if path != "iptables" || len(args) < 4 || !reflect.DeepEqual(args[:2], []string{"-w", "5"}) || args[3] != "ts-input" {
					t.Fatalf("unexpected command: %s %v", path, args)
				}
				if args[2] == tc.fail {
					return []byte("Permission denied"), failure
				}
				if args[2] == "-S" {
					if tc.noChain {
						return []byte("iptables: No chain/target/match by that name."), firewallExit(1)
					}
					return []byte("-N ts-input\n-A ts-input -s 100.64.0.0/10 ! -i tailscale0 -j DROP"), nil
				}
				start := 4
				if args[2] == "-I" {
					if args[4] != "1" {
						t.Fatal(args)
					}
					start = 5
				}
				want := []string{"-i", "CloudflareWARP", "-s", "100.96.0.0/12", "-m", "comment", "--comment", "meshscale Mesh coexistence", "-j", "RETURN"}
				if !reflect.DeepEqual(args[start:], want) {
					t.Fatalf("overbroad rule: %v", args)
				}
				switch args[2] {
				case "-C":
					if !present {
						return nil, firewallExit(1)
					}
					return nil, nil
				case "-I":
					inserts++
					present = true
					return nil, nil
				case "-D":
					deletes++
					present = false
					return nil, nil
				default:
					t.Fatalf("unexpected mutation: %v", args)
					return nil, nil
				}
			}
			for _, op := range tc.operations {
				var err error
				switch op {
				case "up":
					err = f.Reconcile(context.Background())
				case "down":
					err = f.Cleanup(context.Background())
				case "restart":
					present = false
					continue
				}
				if (err != nil) != tc.wantError {
					t.Fatalf("%s: %v", op, err)
				}
				if tc.wantError && !errors.Is(err, failure) {
					t.Fatalf("lost error cause: %v", err)
				}
			}
			if inserts != tc.wantInserts || deletes != tc.wantDeletes {
				t.Fatalf("inserts=%d deletes=%d", inserts, deletes)
			}
		})
	}
}

func TestMissingIPTables(t *testing.T) {
	for _, remove := range []bool{false, true} {
		f := &firewall{hasInterface: func(string) bool { return true }, run: func(context.Context, string, ...string) ([]byte, error) { return nil, exec.ErrNotFound }}
		err := f.apply(context.Background(), remove)
		if remove && err != nil || !remove && !errors.Is(err, exec.ErrNotFound) {
			t.Fatal(err)
		}
	}
}
