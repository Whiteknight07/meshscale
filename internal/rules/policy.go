// Package rules compiles access policies into owned Gateway network rules.
package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

var MeshIPv4 = meshaddr.IPv4Range.String()

const MeshIPv6 = "2606:4700:cf1:1000::/64"

type Policy struct {
	Groups map[string][]string `json:"groups,omitempty"`
	Rules  []Rule              `json:"rules"`
}

type Rule struct {
	From []string `json:"from"`
	To   []string `json:"to"`
}

type Participant struct{ ID, Name, Email, IPv4, IPv6 string }

// maxSelectors bounds group expansion: nested groups can otherwise double at
// every level. Gateway's expression limit is reached well before this.
const maxSelectors = 10000

// Parse accepts strict JSON. Unknown fields and empty selectors are errors.
func Parse(data []byte) (*Policy, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var p *Policy
	if err := d.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy JSON: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("policy must contain one JSON object")
	}
	if p == nil || p.Rules == nil {
		return nil, fmt.Errorf("policy requires a rules array (use [] to deny all)")
	}
	for name, members := range p.Groups {
		if name == "" || strings.ContainsAny(name, ":@/[] \t\r\n") || name == "*" {
			return nil, fmt.Errorf("invalid group name %q", name)
		}
		if len(members) == 0 {
			return nil, fmt.Errorf("group %q is empty", name)
		}
	}
	// Validate unused groups too, including cycles.
	for name := range p.Groups {
		if _, err := p.expand("group:"+name, nil); err != nil {
			return nil, err
		}
	}
	for i, r := range p.Rules {
		if len(r.From) == 0 || len(r.To) == 0 {
			return nil, fmt.Errorf("rule %d requires nonempty from and to", i+1)
		}
		for _, s := range r.From {
			if _, err := p.expand(s, nil); err != nil {
				return nil, fmt.Errorf("rule %d from: %w", i+1, err)
			}
		}
		for _, target := range r.To {
			s, ports, err := destination(target)
			if err == nil {
				_, err = p.expand(s, nil)
			}
			if err == nil {
				_, err = portExpression(ports)
			}
			if err != nil {
				return nil, fmt.Errorf("rule %d to %q: %w", i+1, target, err)
			}
		}
	}
	return p, nil
}

func (p *Policy) expand(s string, stack map[string]bool) ([]string, error) {
	if s == "" || s != strings.TrimSpace(s) {
		return nil, fmt.Errorf("invalid selector %q", s)
	}
	name := strings.TrimPrefix(s, "group:")
	members, exists := p.Groups[name]
	if strings.HasPrefix(s, "group:") || exists {
		if !exists {
			return nil, fmt.Errorf("unknown group %q", name)
		}
		if stack[name] {
			return nil, fmt.Errorf("group cycle at %q", name)
		}
		next := map[string]bool{name: true}
		for k, v := range stack {
			next[k] = v
		}
		var result []string
		for _, member := range members {
			items, err := p.expand(member, next)
			if err != nil {
				return nil, err
			}
			result = append(result, items...)
			if len(result) > maxSelectors {
				return nil, fmt.Errorf("group %q expands to more than %d selectors", name, maxSelectors)
			}
		}
		return result, nil
	}
	if s != "*" {
		if _, err := meshPrefix(s); err != nil {
			if _, e := netip.ParseAddr(s); e == nil {
				return nil, err
			}
			// Names may contain spaces, as displayed by status. Reserved selector
			// punctuation and control characters are not device names.
			if strings.ContainsAny(s, ":/[]*\t\r\n") || strings.ContainsFunc(s, unicode.IsControl) {
				return nil, fmt.Errorf("invalid selector %q: %w", s, err)
			}
		}
	}
	return []string{s}, nil
}

func destination(s string) (string, string, error) {
	// The final colon separates ports; bracket IPv6 addresses/CIDRs.
	i := strings.LastIndexByte(s, ':')
	if i < 1 || i == len(s)-1 {
		return "", "", fmt.Errorf("expected selector:ports")
	}
	selector := s[:i]
	if strings.HasPrefix(selector, "[") && strings.HasSuffix(selector, "]") {
		selector = selector[1 : len(selector)-1]
	} else if strings.Contains(selector, ":") && !strings.HasPrefix(selector, "group:") {
		return "", "", fmt.Errorf("IPv6 destinations require [address]:ports")
	}
	return selector, s[i+1:], nil
}

func meshPrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, e := netip.ParseAddr(s)
		if e != nil || a.Is4In6() || a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("expected a Mesh IP or CIDR")
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("IPv4-mapped IPv6 is unsupported")
	}
	for _, m := range []netip.Prefix{meshaddr.IPv4Range, netip.MustParsePrefix(MeshIPv6)} {
		if m.Contains(p.Addr()) && p.Bits() >= m.Bits() {
			return p.Masked(), nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("IP/CIDR %q is outside default Mesh device ranges", s)
}

func portExpression(s string) (string, error) {
	if s == "*" {
		return "", nil
	}
	var parts []string
	for _, value := range strings.Split(s, ",") {
		bounds := strings.Split(value, "-")
		if len(bounds) > 2 {
			return "", fmt.Errorf("invalid ports %q", s)
		}
		ns := make([]int, len(bounds))
		for i, b := range bounds {
			n, err := strconv.Atoi(b)
			if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != b {
				return "", fmt.Errorf("port %q must be 1..65535", b)
			}
			ns[i] = n
		}
		if len(ns) == 1 {
			parts = append(parts, fmt.Sprintf("net.dst.port == %d", ns[0]))
		} else {
			if ns[0] > ns[1] {
				return "", fmt.Errorf("reversed port range %q", value)
			}
			parts = append(parts, fmt.Sprintf("(net.dst.port >= %d and net.dst.port <= %d)", ns[0], ns[1]))
		}
	}
	if len(parts) == 1 {
		return parts[0], nil
	}
	return "(" + strings.Join(parts, " or ") + ")", nil
}

func (p *Policy) resolve(s string, participants []Participant) ([]string, error) {
	selectors, err := p.expand(s, nil)
	if err != nil {
		return nil, err
	}
	found := map[string]bool{}
	for _, selector := range selectors {
		if selector == "*" {
			found[MeshIPv4], found[MeshIPv6] = true, true
			continue
		}
		if prefix, err := meshPrefix(selector); err == nil {
			found[prefix.String()] = true
			continue
		}
		matches := 0
		for _, d := range participants {
			if (strings.Contains(selector, "@") && d.Email == selector) || (!strings.Contains(selector, "@") && d.Name == selector) {
				matches++
				hasIP := false
				for _, ip := range []string{d.IPv4, d.IPv6} {
					if ip == "" {
						continue
					}
					prefix, err := meshPrefix(ip)
					if err != nil {
						return nil, fmt.Errorf("device %q: %w", d.Name, err)
					}
					found[prefix.String()], hasIP = true, true
				}
				if !hasIP {
					return nil, fmt.Errorf("device %q has no known Mesh IP; sync when it connects", d.Name)
				}
			}
		}
		if matches == 0 {
			return nil, fmt.Errorf("selector %q matches no active registrations", selector)
		}
		if matches > 1 && !strings.Contains(selector, "@") {
			return nil, fmt.Errorf("ambiguous device name %q; use IPs or an owner email", selector)
		}
	}
	result := make([]string, 0, len(found))
	for ip := range found {
		result = append(result, ip)
	}
	sort.Strings(result)
	return result, nil
}
