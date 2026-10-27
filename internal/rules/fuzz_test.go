package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

// Groups that reference each other twice per level expand to 2^depth
// selectors; the file is tiny, so parsing it must still be instant.
func TestParseRejectsExponentialGroups(t *testing.T) {
	groups := []string{`"g0":["*"]`}
	for i := 1; i <= 40; i++ {
		groups = append(groups, fmt.Sprintf(`"g%d":["group:g%d","group:g%d"]`, i, i-1, i-1))
	}
	data := `{"groups":{` + strings.Join(groups, ",") + `},"rules":[{"from":["group:g40"],"to":["*:22"]}]}`
	start := time.Now()
	if _, err := Parse([]byte(data)); err == nil || !strings.Contains(err.Error(), "expands to more than") {
		t.Fatalf("accepted exponential groups: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("parse took %v", elapsed)
	}
}

var fuzzParticipants = []Participant{
	{ID: "a", Name: "laptop", Email: "alice@example.com", IPv4: "100.96.0.1"},
	{ID: "b", Name: "nas", Email: "bob@example.com", IPv4: "100.96.0.2", IPv6: "2606:4700:cf1:1000::2"},
	{ID: "c", Name: "Mac Laptop", Email: "alice@example.com", IPv6: "2606:4700:cf1:1000::3"},
}

func FuzzCompile(f *testing.F) {
	for _, seed := range []string{
		`{"rules":[]}`,
		`{"groups":{"servers":["laptop","nas"],"nested":["group:servers"]},"rules":[{"from":["*","alice@example.com","Mac Laptop"],"to":["servers:22,443","group:nested:1000-2000","[2606:4700:cf1:1000::4]:*"]}]}`,
		`{"rules":[{"from":["100.96.0.0/12"],"to":["[2606:4700:cf1:1000::/64]:1-65535"]}]}`,
		`{"groups":{"x":["group:y"],"y":["group:x"]},"rules":[]}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data string) {
		p, err := Parse([]byte(data))
		if err != nil {
			return
		}
		compiled, err := Compile(p, fuzzParticipants)
		if err != nil {
			return
		}
		if len(compiled) != len(p.Rules)+1 || compiled[len(compiled)-1].Action != "block" {
			t.Fatalf("compiled %d rules for %d policy rules", len(compiled), len(p.Rules))
		}
		for _, r := range compiled {
			if Owner(r) == "" {
				t.Fatalf("compiled an unowned rule %#v", r)
			}
			// Selectors never reach Gateway: only validated Mesh prefixes do.
			for _, field := range strings.Fields(strings.NewReplacer("{", " ", "}", " ", "(", " ", ")", " ").Replace(r.Traffic)) {
				switch {
				case strings.HasPrefix(field, "net."), field == "in", field == "and", field == "or", field == "==", field == ">=", field == "<=":
				case strings.Trim(field, "0123456789") == "":
				default:
					if _, err := meshPrefix(field); err != nil {
						t.Fatalf("unexpected expression token %q in %q", field, r.Traffic)
					}
				}
			}
			if strings.HasPrefix(canonicalExpression(r.Traffic), "invalid:") {
				t.Fatalf("compiled an expression the canonicalizer rejects: %q", r.Traffic)
			}
			if !matches(r, r) {
				t.Fatalf("compiled rule does not match itself: %q", r.Traffic)
			}
		}
	})
}

func FuzzCanonicalExpression(f *testing.F) {
	f.Add(`net.src.internal_src_ip in {100.96.0.1/32} and ((net.dst.ip in {100.96.0.2}) or (net.dst.ip in {100.96.0.3} and net.dst.port == 22))`)
	f.Add(`((((`)
	f.Add(`a or b and c`)
	f.Fuzz(func(t *testing.T, s string) {
		key := canonicalExpression(s)
		if strings.HasPrefix(key, "invalid:") {
			return
		}
		// Gateway may add or drop redundant parentheses on readback.
		if again := canonicalExpression("(" + s + ")"); again != key {
			t.Fatalf("parenthesized form differs: %q vs %q", again, key)
		}
	})
}

func FuzzDiff(f *testing.F) {
	f.Add(int64(1000), int64(1), true, "l4", "x")
	f.Add(int64(-5), int64(1000), false, "dns", "")
	f.Fuzz(func(t *testing.T, customerPrecedence, ownedPrecedence int64, enabled bool, filter, id string) {
		desired, err := Compile(&Policy{Rules: []Rule{{From: []string{"*"}, To: []string{"*:22"}}}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		existing := []cfapi.GatewayRule{
			{ID: "customer", Name: "customer", Enabled: enabled, Filters: []string{filter}, Precedence: customerPrecedence},
			{ID: id, Name: RulePrefix + "allow-1", Description: ownerPrefix + "allow-1", Filters: []string{"l4"}, Precedence: ownedPrecedence},
		}
		changes, err := Diff(desired, existing)
		if err != nil {
			return
		}
		for _, c := range changes {
			if Owner(c.Rule) == "" {
				t.Fatalf("plan touches an unowned rule: %#v", c)
			}
			if c.Action != "delete" && filter == "l4" && enabled && c.Rule.Precedence >= customerPrecedence {
				t.Fatalf("owned rule at %d is not before the customer rule at %d", c.Rule.Precedence, customerPrecedence)
			}
		}
	})
}
