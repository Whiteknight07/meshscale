package names

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

func TestBuild(t *testing.T) {
	ps := []Participant{
		{ID: "c", Name: "LAPTOP", IPv4: "100.96.0.3"},
		{ID: "a", Name: "Laptop", IPv4: "100.96.0.1", IPv6: "2606:4700:cf1::1"},
		{ID: "d", Name: "laptop-2", IPv4: "100.96.0.4"},
		{ID: "b", Name: "Laptop", IPv4: "100.96.0.2"},
		{ID: "e", Name: "Bob's Phone (iOS)", IPv6: "2606:4700:cf1::5"},
		{ID: "f", Name: "💻"},
	}
	got, err := Build(ps, ".MESH.")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"a": "laptop.mesh", "b": "laptop-3.mesh", "c": "laptop-4.mesh", "d": "laptop-2.mesh", "e": "bob-s-phone-ios.mesh", "f": "device.mesh"}
	for _, r := range got {
		if r.Name != want[r.ID] {
			t.Errorf("%s: %s, want %s", r.ID, r.Name, want[r.ID])
		}
		if r.ID == "a" && r.IP != "100.96.0.1" {
			t.Error("IPv4 should be preferred")
		}
	}
	ps[0], ps[1] = ps[1], ps[0]
	again, err := Build(ps, "mesh")
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatalf("API order changed names: %v, %v", again, err)
	}
	long, err := Build([]Participant{{ID: "1", Name: strings.Repeat("a", 90)}, {ID: "2", Name: strings.Repeat("a", 90)}}, "my.mesh")
	if err != nil || len(strings.Split(long[1].Name, ".")[0]) != 63 {
		t.Fatalf("long names: %v, %v", long, err)
	}
}

func TestValidation(t *testing.T) {
	for _, s := range []string{"", "a..b", "-mesh", "mesh-", "m_esh", "a/mesh", strings.Repeat("a", 64), strings.Repeat("a.", 100) + "a"} {
		if _, err := Suffix(s); err == nil {
			t.Errorf("accepted suffix %q", s)
		}
	}
	for _, ps := range [][]Participant{
		{{Name: "no ID"}},
		{{ID: "a"}, {ID: "a"}},
		{{ID: "a", IPv4: "bad"}},
		{{ID: "a", IPv6: "fe80::1%eth0"}},
	} {
		if _, err := Build(ps, "mesh"); err == nil {
			t.Errorf("accepted %v", ps)
		}
	}
}

func TestDiffLifecycleAndOwnership(t *testing.T) {
	desired := []Record{{ID: "node/a", Name: "laptop.mesh", IP: "100.96.0.1"}, {ID: "node/b", Name: "phone.mesh", IP: "100.96.0.2"}}
	other := cfapi.GatewayRule{ID: "customer", Name: "Default deny for private traffic", Action: "block", Filters: []string{"l4"}, Precedence: 500}
	lookalike := ruleFor(Record{ID: "customer", Name: "lookalike.mesh", IP: "100.96.0.9"})
	lookalike.ID, lookalike.Description = "lookalike", "Customer owned"
	changes, err := Diff(desired, []cfapi.GatewayRule{other, lookalike})
	if err != nil || len(changes) != 2 || changes[0].Action != "create" || changes[0].Rule.Precedence != 1 {
		t.Fatalf("create: %v, %v", changes, err)
	}
	a, b := changes[0].Rule, changes[1].Rule
	a.ID, b.ID = "a", "b"
	existing := []cfapi.GatewayRule{other, lookalike, a, b}
	if diff, err := Diff(desired, existing); err != nil || len(diff) != 0 {
		t.Fatalf("not idempotent: %v, %v", diff, err)
	}
	desired[0].Name, desired[0].IP = "renamed.mesh", "100.96.0.8"
	changes, err = Diff(desired[:1], existing)
	if err != nil || len(changes) != 2 || changes[0].Action != "update" || changes[1].Action != "delete" || changes[0].Rule.ID != "a" || changes[0].Rule.Precedence != a.Precedence {
		t.Fatalf("rename/IP/delete: %v, %v", changes, err)
	}
	// Disabled or identity-restricted owned rules are repaired.
	a.Enabled, a.Identity = false, `identity.email == "only@example.com"`
	changes, err = Diff([]Record{{ID: "node/a", Name: "laptop.mesh", IP: "100.96.0.1"}}, []cfapi.GatewayRule{a})
	if err != nil || len(changes) != 1 || !changes[0].Rule.Enabled || changes[0].Rule.Identity != "" {
		t.Fatalf("repair: %v, %v", changes, err)
	}
	// Retain the last known address while an offline node cannot be joined.
	changes, err = Diff([]Record{{ID: "node/a", Name: "laptop.mesh"}}, []cfapi.GatewayRule{a})
	if err != nil || len(changes) != 0 {
		t.Fatalf("offline: %v, %v", changes, err)
	}
	a.ReadOnly = true
	if _, err := Diff(nil, []cfapi.GatewayRule{a}); err == nil {
		t.Error("accepted read-only rule")
	}
}

func TestDiffDuplicatesAndEmpty(t *testing.T) {
	r := Record{ID: "node/a", Name: "a.mesh", IP: "100.96.0.1"}
	a, b := ruleFor(r), ruleFor(r)
	a.ID, b.ID = "a", "b"
	changes, err := Diff([]Record{r}, []cfapi.GatewayRule{b, a})
	if err != nil || len(changes) != 1 || changes[0].Action != "delete" || changes[0].Rule.ID != "b" {
		t.Fatalf("duplicate rules: %v, %v", changes, err)
	}
	if _, err := Diff([]Record{r, r}, nil); err == nil {
		t.Error("accepted duplicate desired record")
	}
	changes, err = Diff(nil, []cfapi.GatewayRule{a, b, {ID: "other", Name: "Do Not Inspect"}})
	if err != nil || len(changes) != 2 {
		t.Fatalf("empty account: %v, %v", changes, err)
	}
}

type fakeGateway struct {
	calls []string
	err   error
}

func (f *fakeGateway) CreateGatewayRule(context.Context, string, cfapi.GatewayRule) (cfapi.GatewayRule, error) {
	f.calls = append(f.calls, "create")
	return cfapi.GatewayRule{}, f.err
}
func (f *fakeGateway) UpdateGatewayRule(context.Context, string, string, cfapi.GatewayRule) (cfapi.GatewayRule, error) {
	f.calls = append(f.calls, "update")
	return cfapi.GatewayRule{}, f.err
}
func (f *fakeGateway) DeleteGatewayRule(context.Context, string, string) error {
	f.calls = append(f.calls, "delete")
	return f.err
}

func TestApply(t *testing.T) {
	r := ruleFor(Record{ID: "node/a", Name: "a.mesh", IP: "100.96.0.1"})
	r.ID = "a"
	changes := []Change{{"create", r}, {"update", r}, {"delete", r}}
	f := &fakeGateway{}
	if err := Apply(t.Context(), f, "acc", changes); err != nil || strings.Join(f.calls, ",") != "create,update,delete" {
		t.Fatalf("apply: %v %v", f.calls, err)
	}
	f = &fakeGateway{err: errors.New("denied")}
	if err := Apply(t.Context(), f, "acc", changes); err == nil || len(f.calls) != 1 {
		t.Fatalf("did not stop on error: %v, %v", f.calls, err)
	}
	f = &fakeGateway{}
	if err := Apply(t.Context(), f, "acc", []Change{{Action: "delete", Rule: cfapi.GatewayRule{ID: "customer"}}}); err == nil || len(f.calls) != 0 {
		t.Fatal("mutated an unowned rule")
	}
}
