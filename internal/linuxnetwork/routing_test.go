package linuxnetwork

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type fakeRouting struct {
	snapshot             routingSnapshot
	dirty                bool
	fail                 string
	failure              error
	adds, deletes, reads int
}

func (f *fakeRouting) Changed() (bool, error) { dirty := f.dirty; f.dirty = false; return dirty, nil }
func (f *fakeRouting) Snapshot(bool) (routingSnapshot, error) {
	f.reads++
	if f.fail == "inspect" {
		return routingSnapshot{}, f.failure
	}
	return f.snapshot, nil
}
func (f *fakeRouting) Add(r policyRule) error {
	f.adds++
	if f.fail == "add" {
		return f.failure
	}
	f.snapshot.Rules = append(f.snapshot.Rules, r)
	return nil
}
func (f *fakeRouting) Delete(r policyRule) error {
	f.deletes++
	if f.fail == "delete" {
		return f.failure
	}
	for i, rule := range f.snapshot.Rules {
		if rule == r {
			f.snapshot.Rules = append(f.snapshot.Rules[:i], f.snapshot.Rules[i+1:]...)
			break
		}
	}
	return nil
}
func (f *fakeRouting) Close() { f.dirty = true }

func TestRoutingLifecycle(t *testing.T) {
	prefix := netip.MustParsePrefix("100.96.0.0/12")
	for _, tc := range []struct {
		name                               string
		priority                           int
		interfaces, existing, defaultRoute bool
		operations                         []string
		fail                               string
		wantAdd, wantDelete, wantWarn      int
	}{
		{name: "both clients", priority: 5209, interfaces: true, operations: []string{"up"}, wantAdd: 1},
		{name: "dynamic priority", priority: 4100, interfaces: true, operations: []string{"up"}, wantAdd: 1},
		{name: "no interfaces", operations: []string{"up"}},
		{name: "interface disappears", existing: true, operations: []string{"up"}, wantDelete: 1},
		{name: "no WARP policy", interfaces: true, operations: []string{"up"}},
		{name: "idempotent existing", priority: 5209, interfaces: true, existing: true, operations: []string{"up", "up"}},
		{name: "roundtrip", priority: 5209, interfaces: true, operations: []string{"up", "up", "down", "down"}, wantAdd: 1, wantDelete: 1},
		{name: "priority moved", priority: 4100, interfaces: true, existing: true, operations: []string{"up"}, wantAdd: 1, wantDelete: 1},
		{name: "exit node", priority: 5209, interfaces: true, defaultRoute: true, operations: []string{"up"}, wantWarn: 1},
		{name: "exit removes stale", priority: 5209, interfaces: true, defaultRoute: true, existing: true, operations: []string{"up"}, wantDelete: 1, wantWarn: 1},
		{name: "cleanup without interfaces", existing: true, operations: []string{"down"}, wantDelete: 1},
		{name: "inspect failed", interfaces: true, operations: []string{"up"}, fail: "inspect"},
		{name: "add failed", priority: 5209, interfaces: true, operations: []string{"up"}, fail: "add", wantAdd: 1},
		{name: "delete failed", existing: true, operations: []string{"down"}, fail: "delete", wantDelete: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRouting{dirty: true, fail: tc.fail, failure: errors.New("netlink failed"), snapshot: routingSnapshot{WARPTables: map[int]bool{65743: true}, TailscaleDefault: tc.defaultRoute}}
			// Operator's hand-added rule is never ours to remove.
			runner.snapshot.Rules = []policyRule{{Priority: 5200, Table: 52, Destination: prefix}}
			if tc.priority != 0 {
				runner.snapshot.Rules = append(runner.snapshot.Rules, policyRule{Priority: tc.priority, Table: 65743, Mark: 0x100cf, Invert: true})
			}
			if tc.existing {
				runner.snapshot.Rules = append(runner.snapshot.Rules, policyRule{Priority: 5208, Table: 52, Protocol: 243, Destination: prefix})
			}
			warnings := 0
			f := &firewall{routing: &routingManager{run: runner, warn: func(string, ...any) { warnings++ }}, hasInterface: func(string) bool { return tc.interfaces }, run: func(context.Context, string, ...string) ([]byte, error) {
				return []byte("does not exist"), firewallExit(1)
			}}
			for _, op := range tc.operations {
				var err error
				if op == "down" {
					err = f.Cleanup(context.Background())
				} else {
					err = f.Reconcile(context.Background())
				}
				if (err != nil) != (tc.fail != "") {
					t.Fatal(err)
				}
				if err != nil && !errors.Is(err, runner.failure) {
					t.Fatalf("lost cause: %v", err)
				}
			}
			if runner.adds != tc.wantAdd || runner.deletes != tc.wantDelete || warnings != tc.wantWarn {
				t.Fatalf("add/delete/warn=%d/%d/%d", runner.adds, runner.deletes, warnings)
			}
			if len(tc.operations) == 2 && tc.operations[1] == "up" && runner.reads != 1 {
				t.Fatalf("unchanged tick read routing %d times", runner.reads)
			}
		})
	}
}

func TestRoutingChangeInvalidatesSnapshot(t *testing.T) {
	runner := &fakeRouting{dirty: true, snapshot: routingSnapshot{WARPTables: map[int]bool{65743: true}, Rules: []policyRule{{Priority: 5209, Table: 65743, Mark: 0x100cf, Invert: true}}}}
	manager := &routingManager{run: runner}
	for range 3 {
		if err := manager.reconcile(context.Background(), true); err != nil {
			t.Fatal(err)
		}
	}
	if runner.reads != 1 || runner.adds != 1 {
		t.Fatal(runner)
	}
	runner.snapshot.TailscaleDefault = true
	runner.dirty = true
	if err := manager.reconcile(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if runner.reads != 2 || runner.deletes != 1 {
		t.Fatal(runner)
	}
}
