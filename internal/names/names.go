// Package names assigns Mesh DNS names and reconciles owned Gateway policies.
package names

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

const (
	DefaultSuffix = "mesh"
	RulePrefix    = "meshscale dns: "
	ownerPrefix   = "Managed by meshscale DNS v1; participant="
)

type Participant struct {
	ID, Name, IPv4, IPv6 string
}

type Record struct {
	ID, Name, IP string
}

// Suffix validates an ASCII DNS suffix, accepting a leading/trailing dot.
func Suffix(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(strings.TrimSuffix(s, "."), ".")
	if len(s) == 0 || len(s) > 189 {
		return "", fmt.Errorf("DNS suffix must contain 1 to 189 characters")
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label != sanitize(label) {
			return "", fmt.Errorf("invalid DNS suffix %q: use DNS labels of letters, digits and hyphens", s)
		}
	}
	return s, nil
}

func sanitize(s string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(s) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			b.WriteRune(c)
		} else if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	s = strings.Trim(b.String(), "-")
	if len(s) > 63 {
		s = strings.TrimRight(s[:63], "-")
	}
	if s == "" {
		return "device"
	}
	return s
}

// Build is independent of API order. Reserve natural names before assigning
// numeric suffixes, so a duplicate "laptop" cannot steal "laptop-2".
// Participants without a known address keep their name but cannot create a rule.
func Build(participants []Participant, suffix string) ([]Record, error) {
	suffix, err := Suffix(suffix)
	if err != nil {
		return nil, err
	}
	ps := append([]Participant(nil), participants...)
	sort.Slice(ps, func(i, j int) bool { return ps[i].ID < ps[j].ID })
	// next resumes each base's suffix search, keeping many duplicates linear.
	reserved, used, next := map[string]bool{}, map[string]bool{}, map[string]int{}
	for _, p := range ps {
		reserved[sanitize(p.Name)] = true
	}
	var records []Record
	for i, p := range ps {
		if p.ID == "" || i > 0 && ps[i-1].ID == p.ID {
			return nil, fmt.Errorf("missing or duplicate DNS participant ID %q", p.ID)
		}
		base := sanitize(p.Name)
		label := base
		if used[label] {
			for n := max(next[base], 2); ; n++ {
				tail := "-" + strconv.Itoa(n)
				prefix := strings.TrimRight(base[:min(len(base), 63-len(tail))], "-")
				label = prefix + tail
				if !used[label] && !reserved[label] {
					next[base] = n + 1
					break
				}
			}
		}
		used[label] = true
		ip := p.IPv4
		if ip == "" {
			ip = p.IPv6
		}
		if ip != "" {
			addr, err := netip.ParseAddr(ip)
			if err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() {
				return nil, fmt.Errorf("invalid Mesh IP %q for %s", ip, p.ID)
			}
			ip = addr.Unmap().String()
		}
		records = append(records, Record{ID: p.ID, Name: label + "." + suffix, IP: ip})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Name < records[j].Name })
	return records, nil
}

// Owner requires both markers; a similarly named customer rule is never ours.
func Owner(rule cfapi.GatewayRule) string {
	if !strings.HasPrefix(rule.Name, RulePrefix) || !strings.HasPrefix(rule.Description, ownerPrefix) {
		return ""
	}
	return strings.TrimPrefix(rule.Description, ownerPrefix)
}

type Change struct {
	Action string
	Rule   cfapi.GatewayRule
}

func ruleFor(r Record) cfapi.GatewayRule {
	return cfapi.GatewayRule{
		Name: RulePrefix + r.Name, Description: ownerPrefix + r.ID,
		Enabled: true, Action: "override", Filters: []string{"dns"},
		Traffic:      fmt.Sprintf("dns.fqdn == %q", r.Name),
		RuleSettings: cfapi.GatewayRuleSettings{OverrideIPs: []string{r.IP}},
	}
}

func emptyJSON(s []byte) bool { return len(s) == 0 || string(s) == "null" }

func matches(a, b cfapi.GatewayRule) bool {
	return a.Name == b.Name && a.Description == b.Description && a.Enabled == b.Enabled &&
		a.Action == b.Action && len(a.Filters) == 1 && a.Filters[0] == "dns" &&
		strings.Join(strings.Fields(a.Traffic), " ") == b.Traffic &&
		a.Identity == "" && a.DevicePosture == "" && emptyJSON(a.Schedule) && emptyJSON(a.Expiration) &&
		a.RuleSettings.OverrideHost == "" && len(a.RuleSettings.OverrideIPs) == 1 &&
		a.RuleSettings.OverrideIPs[0] == b.RuleSettings.OverrideIPs[0]
}

// Diff never changes unrelated policies or their precedence. Unknown offline
// addresses preserve existing rules until a live join supplies the address.
func Diff(desired []Record, existing []cfapi.GatewayRule) ([]Change, error) {
	want := map[string]Record{}
	for _, r := range desired {
		if r.ID == "" || want[r.ID].ID != "" {
			return nil, fmt.Errorf("missing or duplicate desired DNS participant %q", r.ID)
		}
		want[r.ID] = r
	}
	rules := append([]cfapi.GatewayRule(nil), existing...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	seen := map[string]bool{}
	var changes []Change
	var precedence int64
	for _, rule := range rules {
		for _, filter := range rule.Filters {
			if filter == "dns" && rule.Precedence > precedence {
				precedence = rule.Precedence
			}
		}
		id := Owner(rule)
		if id == "" {
			continue
		}
		r, exists := want[id]
		if rule.ReadOnly || rule.ID == "" {
			return nil, fmt.Errorf("owned Gateway DNS rule %q is read-only or has no ID", rule.Name)
		}
		if !exists || seen[id] {
			changes = append(changes, Change{Action: "delete", Rule: rule})
			continue
		}
		seen[id] = true
		if r.IP == "" {
			continue
		}
		updated := ruleFor(r)
		updated.ID, updated.Precedence = rule.ID, rule.Precedence
		if !matches(rule, updated) {
			changes = append(changes, Change{Action: "update", Rule: updated})
		}
	}
	for _, r := range desired {
		if seen[r.ID] || r.IP == "" {
			continue
		}
		rule := ruleFor(r)
		precedence++
		rule.Precedence = precedence
		changes = append(changes, Change{Action: "create", Rule: rule})
	}
	return changes, nil
}

type Gateway interface {
	CreateGatewayRule(context.Context, string, cfapi.GatewayRule) (cfapi.GatewayRule, error)
	UpdateGatewayRule(context.Context, string, string, cfapi.GatewayRule) (cfapi.GatewayRule, error)
	DeleteGatewayRule(context.Context, string, string) error
}

// Apply stops on the first error. A later sync safely resumes the remaining diff.
func Apply(ctx context.Context, client Gateway, account string, changes []Change) error {
	for _, change := range changes {
		if Owner(change.Rule) == "" {
			return fmt.Errorf("refusing to %s an unowned Gateway rule", change.Action)
		}
		var err error
		switch change.Action {
		case "create":
			_, err = client.CreateGatewayRule(ctx, account, change.Rule)
		case "update":
			_, err = client.UpdateGatewayRule(ctx, account, change.Rule.ID, change.Rule)
		case "delete":
			err = client.DeleteGatewayRule(ctx, account, change.Rule.ID)
		default:
			return fmt.Errorf("unknown DNS change %q", change.Action)
		}
		if err != nil {
			return fmt.Errorf("%s %s: %w", change.Action, change.Rule.Name, err)
		}
	}
	return nil
}
