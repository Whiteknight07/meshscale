package rules

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"sort"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

type Change struct {
	Action string            `json:"operation"`
	Rule   cfapi.GatewayRule `json:"rule"`
}

// Diff reserves unused precedence values before customer network policies.
// It fails instead of moving customer rules when there is insufficient space.
func Diff(desired, existing []cfapi.GatewayRule) ([]Change, error) {
	want := append([]cfapi.GatewayRule(nil), desired...)
	occupied := map[int64]bool{}
	limit := int64(math.MaxInt64)
	otherCount := 0
	byOwner := map[string][]cfapi.GatewayRule{}
	for _, r := range existing {
		if id := Owner(r); id != "" {
			if r.ID == "" || r.ReadOnly {
				return nil, fmt.Errorf("owned network rule %q is read-only or has no ID", r.Name)
			}
			byOwner[id] = append(byOwner[id], r)
			continue
		}
		for _, f := range r.Filters {
			if f == "l4" {
				otherCount++
				occupied[r.Precedence] = true
				if r.Enabled && r.Precedence < limit {
					limit = r.Precedence
				}
			}
		}
	}
	if len(want) > 0 && otherCount+len(want) > 500 {
		return nil, fmt.Errorf("network policies exceed Cloudflare's default account limit of 500")
	}
	next := int64(1000)
	if limit <= next+int64(len(want)) {
		next = 0
	}
	seen := map[string]bool{}
	var changes, deletes []Change
	for i := range want {
		r := &want[i]
		id := Owner(*r)
		if id == "" || seen[id] {
			return nil, fmt.Errorf("unowned or duplicate desired network rule %q", r.Name)
		}
		seen[id] = true
		for occupied[next] && next < limit {
			next++
		}
		if next >= limit {
			return nil, fmt.Errorf("insufficient precedence space before customer network policy at %d; review its precedence in Gateway", limit)
		}
		r.Precedence = next
		next++
		old := byOwner[id]
		sort.Slice(old, func(i, j int) bool { return old[i].ID < old[j].ID })
		if len(old) == 0 {
			changes = append(changes, Change{"create", *r})
		} else {
			r.ID = old[0].ID
			if !matches(old[0], *r) {
				changes = append(changes, Change{"update", *r})
			}
			for _, duplicate := range old[1:] {
				deletes = append(deletes, Change{"delete", duplicate})
			}
		}
	}
	for id, old := range byOwner {
		if !seen[id] {
			for _, r := range old {
				deletes = append(deletes, Change{"delete", r})
			}
		}
	}
	// Reset removes the deny first. Normal sync establishes allows and the deny
	// before pruning stale rules. Gateway propagation is not transactional.
	sort.Slice(deletes, func(i, j int) bool {
		a, b := deletes[i].Rule, deletes[j].Rule
		if (a.Action == "block") != (b.Action == "block") {
			return a.Action == "block"
		}
		return a.ID < b.ID
	})
	peak := otherCount
	for _, old := range byOwner {
		peak += len(old)
	}
	for _, c := range changes {
		if c.Action == "create" {
			peak++
		}
	}
	if len(want) > 0 && peak > 500 {
		return nil, fmt.Errorf("sync would temporarily exceed 500 network policies; remove obsolete owned rules before retrying")
	}
	return append(changes, deletes...), nil
}

func matches(a, b cfapi.GatewayRule) bool {
	a.ID, b.ID = "", ""
	a.Traffic = canonicalExpression(a.Traffic)
	b.Traffic = canonicalExpression(b.Traffic)
	// Cloudflare returns null, empty or omitted optional fields interchangeably.
	if len(a.RuleSettings.OverrideIPs) == 0 {
		a.RuleSettings.OverrideIPs = nil
	}
	if len(b.RuleSettings.OverrideIPs) == 0 {
		b.RuleSettings.OverrideIPs = nil
	}
	if string(a.Schedule) == "null" {
		a.Schedule = nil
	}
	if string(a.Expiration) == "null" {
		a.Expiration = nil
	}
	return reflect.DeepEqual(a, b)
}

type Gateway interface {
	CreateGatewayRule(context.Context, string, cfapi.GatewayRule) (cfapi.GatewayRule, error)
	UpdateGatewayRule(context.Context, string, string, cfapi.GatewayRule) (cfapi.GatewayRule, error)
	DeleteGatewayRule(context.Context, string, string) error
}

// Apply validates the entire plan before writing and stops at the first API
// error. Re-run sync to reconcile a partial application, or reset to remove it.
func Apply(ctx context.Context, client Gateway, account string, changes []Change) error {
	for _, c := range changes {
		if Owner(c.Rule) == "" || c.Rule.ReadOnly || (c.Action != "create" && c.Rule.ID == "") {
			return fmt.Errorf("refusing to mutate unowned, read-only or unidentified network rule")
		}
		if c.Action != "create" && c.Action != "update" && c.Action != "delete" {
			return fmt.Errorf("unknown rules operation %q", c.Action)
		}
	}
	for _, c := range changes {
		var err error
		switch c.Action {
		case "create":
			_, err = client.CreateGatewayRule(ctx, account, c.Rule)
		case "update":
			_, err = client.UpdateGatewayRule(ctx, account, c.Rule.ID, c.Rule)
		case "delete":
			err = client.DeleteGatewayRule(ctx, account, c.Rule.ID)
		}
		if err != nil {
			return fmt.Errorf("%s %s: %w (sync may be partial; retry sync or run rules reset)", c.Action, c.Rule.Name, err)
		}
	}
	return nil
}
