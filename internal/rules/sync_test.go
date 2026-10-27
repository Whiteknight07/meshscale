package rules

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

func desiredRules(t *testing.T) []cfapi.GatewayRule {
	t.Helper()
	p, err := Parse([]byte(`{"rules":[{"from":["*"],"to":["*:22"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	r, err := Compile(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestOwnership(t *testing.T) {
	good := networkRule("allow-1", "allow", "true")
	if Owner(good) != "allow-1" {
		t.Fatal(good)
	}
	for _, change := range []func(*cfapi.GatewayRule){
		func(r *cfapi.GatewayRule) { r.Name = "customer" },
		func(r *cfapi.GatewayRule) { r.Description = "customer" },
		func(r *cfapi.GatewayRule) { r.Description = ownerPrefix },
		func(r *cfapi.GatewayRule) { r.Filters = []string{"dns"} },
		func(r *cfapi.GatewayRule) { r.Filters = []string{"l4", "dns"} },
	} {
		r := good
		change(&r)
		if Owner(r) != "" {
			t.Fatalf("adopted %+v", r)
		}
	}
}

func TestDiffReconcileAndReset(t *testing.T) {
	desired := desiredRules(t)
	customer := cfapi.GatewayRule{ID: "customer", Name: "Default deny for private traffic", Action: "block", Enabled: true, Filters: []string{"l4"}, Precedence: 10}
	dns := cfapi.GatewayRule{ID: "dns", Name: "meshscale dns: test.mesh", Filters: []string{"dns"}, Precedence: 0}
	existing := []cfapi.GatewayRule{customer, dns}
	before := append([]cfapi.GatewayRule(nil), existing...)
	changes, err := Diff(desired, existing)
	if err != nil || len(changes) != 2 {
		t.Fatalf("%+v %v", changes, err)
	}
	for i, c := range changes {
		if c.Action != "create" || c.Rule.Precedence != int64(i) {
			t.Fatalf("%+v", c)
		}
	}
	if !reflect.DeepEqual(existing, before) {
		t.Fatal("mutated existing")
	}
	for i, c := range changes {
		r := c.Rule
		r.ID = string(rune('a' + i))
		r.Schedule = json.RawMessage(`null`)
		r.Expiration = json.RawMessage(`null`)
		r.RuleSettings.OverrideIPs = []string{}
		existing = append(existing, r)
	}
	changes, err = Diff(desired, existing)
	if err != nil || len(changes) != 0 {
		t.Fatalf("non-idempotent: %+v %v", changes, err)
	}
	duplicate := existing[2]
	duplicate.ID = "z"
	existing = append(existing, duplicate)
	stale := networkRule("old", "allow", "false")
	stale.ID = "stale"
	existing = append(existing, stale)
	existing[2].Enabled = false
	changes, err = Diff(desired, existing)
	if err != nil || len(changes) != 3 || changes[0].Action != "update" {
		t.Fatalf("%+v %v", changes, err)
	}
	for _, c := range changes {
		if c.Rule.ID == "customer" || c.Rule.ID == "dns" {
			t.Fatal("touched customer")
		}
	}
	changes, err = Diff(nil, existing)
	if err != nil || len(changes) != 4 || Owner(changes[0].Rule) != "default-deny" {
		t.Fatalf("reset: %+v %v", changes, err)
	}
}

func TestDiffRefusals(t *testing.T) {
	desired := desiredRules(t)
	for _, existing := range [][]cfapi.GatewayRule{
		{{ID: "customer", Enabled: true, Filters: []string{"l4"}, Precedence: 0}},
		{{ID: "customer", Enabled: true, Filters: []string{"l4"}, Precedence: 1}},
		{func() cfapi.GatewayRule { r := desired[0]; r.ID = "owned"; r.ReadOnly = true; return r }()},
		{desired[0]},
	} {
		if _, err := Diff(desired, existing); err == nil {
			t.Fatalf("accepted %+v", existing)
		}
	}
	if _, err := Diff(append(desired, desired[0]), nil); err == nil {
		t.Fatal("duplicate desired")
	}
	if _, err := Diff([]cfapi.GatewayRule{{Name: "unowned"}}, nil); err == nil {
		t.Fatal("unowned desired")
	}
	existing := make([]cfapi.GatewayRule, 499)
	for i := range existing {
		existing[i] = cfapi.GatewayRule{Filters: []string{"l4"}, Precedence: int64(i + 10000)}
	}
	if _, err := Diff(desired, existing); err == nil {
		t.Fatal("limit ignored")
	}
	// Reset must still work when the account is already over the default limit.
	existing = append(existing, existing[:2]...)
	owned := desired[0]
	owned.ID = "owned"
	existing = append(existing, owned)
	if changes, err := Diff(nil, existing); err != nil || len(changes) != 1 {
		t.Fatalf("reset at limit: %v %v", changes, err)
	}
}

type fakeGateway struct {
	calls []string
	fail  bool
}

func (f *fakeGateway) CreateGatewayRule(_ context.Context, _ string, r cfapi.GatewayRule) (cfapi.GatewayRule, error) {
	f.calls = append(f.calls, "create")
	if f.fail {
		return r, errors.New("failed")
	}
	return r, nil
}
func (f *fakeGateway) UpdateGatewayRule(_ context.Context, _, _ string, r cfapi.GatewayRule) (cfapi.GatewayRule, error) {
	f.calls = append(f.calls, "update")
	return r, nil
}
func (f *fakeGateway) DeleteGatewayRule(_ context.Context, _, _ string) error {
	f.calls = append(f.calls, "delete")
	return nil
}
func TestApplyValidatesBeforeWriting(t *testing.T) {
	desired := desiredRules(t)
	good := Change{"create", desired[0]}
	for _, bad := range []Change{{"delete", cfapi.GatewayRule{ID: "customer"}}, {"invalid", desired[0]}, {"delete", desired[0]}} {
		f := &fakeGateway{}
		if err := Apply(t.Context(), f, "acc", []Change{good, bad}); err == nil || len(f.calls) != 0 {
			t.Fatalf("%+v %v", bad, f.calls)
		}
	}
	f := &fakeGateway{fail: true}
	err := Apply(t.Context(), f, "acc", []Change{good, good})
	if err == nil || !strings.Contains(err.Error(), "partial") || len(f.calls) != 1 {
		t.Fatalf("%v %v", err, f.calls)
	}
}

func TestGatewayExpressionNormalization(t *testing.T) {
	pairs := [][2]string{
		{`net.src.internal_src_ip in {100.96.0.3/32 2606:4700:cf1:1000::3/128} and ((net.dst.ip in {100.96.0.4/32} and net.dst.port == 8080))`, `net.src.internal_src_ip in {100.96.0.3 2606:4700:cf1:1000::3} and (net.dst.ip in {100.96.0.4} and net.dst.port == 8080)`},
		{`a and (b and c)`, `(a and b) and c`},
		{`a and (b or (c or d))`, `a and ((b or c) or d)`},
	}
	for _, p := range pairs {
		if canonicalExpression(p[0]) != canonicalExpression(p[1]) {
			t.Fatalf("unequal: %s / %s", p[0], p[1])
		}
	}
	for _, p := range [][2]string{{`a and (b or c)`, `(a and b) or c`}, {`net.dst.port >= 10`, `net.dst.port > 10`}, {`net.dst.ip in {100.96.0.0/24}`, `net.dst.ip in {100.96.0.0/32}`}} {
		if canonicalExpression(p[0]) == canonicalExpression(p[1]) {
			t.Fatalf("false equality: %v", p)
		}
	}
	desired := desiredRules(t)
	want := desired[0]
	actual := want
	actual.Traffic = strings.ReplaceAll(actual.Traffic, " and (", " and ((") + ")"
	if !matches(actual, want) {
		t.Fatal("redundant parentheses cause update")
	}
}
