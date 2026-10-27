package rules

import (
	"fmt"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

const (
	RulePrefix  = "meshscale rule: "
	ownerPrefix = "Managed by meshscale network rules v1; rule="
)

// Owner requires both markers and the exact network filter. DNS and customer
// rules are never adopted, even if their names resemble ours.
func Owner(r cfapi.GatewayRule) string {
	if !strings.HasPrefix(r.Name, RulePrefix) || !strings.HasPrefix(r.Description, ownerPrefix) || len(r.Filters) != 1 || r.Filters[0] != "l4" {
		return ""
	}
	return strings.TrimPrefix(r.Description, ownerPrefix)
}

func networkRule(id, action, traffic string) cfapi.GatewayRule {
	return cfapi.GatewayRule{Name: RulePrefix + id, Description: ownerPrefix + id, Enabled: true, Action: action, Filters: []string{"l4"}, Traffic: traffic}
}

func ipExpression(field string, ips []string) string {
	selector := "net.dst.ip"
	if field == "src" {
		// Source IP is the public on-ramp address; Mesh identity uses the inner IP.
		selector = "net.src.internal_src_ip"
	}
	return selector + " in {" + strings.Join(ips, " ") + "}"
}

// Compile emits one allow per policy rule, then exactly one Mesh default deny.
// Destinations retain their port associations instead of forming a cross product.
func Compile(p *Policy, participants []Participant) ([]cfapi.GatewayRule, error) {
	if p == nil {
		return nil, nil
	}
	var result []cfapi.GatewayRule
	for i, rule := range p.Rules {
		var src []string
		for _, s := range rule.From {
			ips, err := p.resolve(s, participants)
			if err != nil {
				return nil, fmt.Errorf("rule %d from: %w", i+1, err)
			}
			src = append(src, ips...)
		}
		src = unique(src)
		if len(src) == 0 || len(rule.To) == 0 {
			return nil, fmt.Errorf("rule %d is empty", i+1)
		}
		var dst []string
		for _, target := range rule.To {
			s, ports, err := destination(target)
			if err != nil {
				return nil, err
			}
			ips, err := p.resolve(s, participants)
			if err != nil {
				return nil, fmt.Errorf("rule %d to: %w", i+1, err)
			}
			port, err := portExpression(ports)
			if err != nil {
				return nil, err
			}
			expression := ipExpression("dst", ips)
			if port != "" {
				expression = "(" + expression + " and " + port + ")"
			}
			dst = append(dst, expression)
		}
		result = append(result, networkRule(fmt.Sprintf("allow-%d", i+1), "allow", ipExpression("src", src)+" and ("+strings.Join(dst, " or ")+")"))
	}
	result = append(result, networkRule("default-deny", "block", ipExpression("dst", []string{MeshIPv4, MeshIPv6})))
	for _, r := range result {
		if len(r.Traffic) > 140000 {
			return nil, fmt.Errorf("%s exceeds Gateway’s 140,000-character expression limit", r.Name)
		}
	}
	return result, nil
}

func unique(values []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, s := range values {
		if !seen[s] {
			result = append(result, s)
			seen[s] = true
		}
	}
	return result
}
