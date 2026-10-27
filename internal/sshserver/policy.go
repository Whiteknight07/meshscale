package sshserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/mail"
	"os"
	"slices"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/secure"
)

type Rule struct {
	Name  string   `json:"name,omitempty"`
	From  []string `json:"from"`
	Users []string `json:"users"`
}

type Policy struct {
	Rules       []Rule `json:"rules"`
	missingPath string
}

func DefaultPolicy() Policy {
	return Policy{Rules: []Rule{}}
}

// Allows matches only identities the client cannot choose:
//   - "*" matches every account participant;
//   - "user@example.com" matches devices owned by that user (case-insensitive);
//   - "device:<id>" matches one Cloudflare device ID;
//   - a plain name matches a Mesh node, whose name only admins can set.
//
// A user device's name is its self-reported hostname, so it never grants
// access. UID 0 aliases cannot inherit access intended for ordinary accounts.
func (p Policy) Allows(id Identity, name string, uid uint32) bool {
	return p.MatchingRule(id, name, uid) >= 0
}

// MatchingRule returns the first granting rule index, or -1 for default deny.
func (p Policy) MatchingRule(id Identity, name string, uid uint32) int {
	for i, rule := range p.Rules {
		if !slices.ContainsFunc(rule.From, id.matches) {
			continue
		}
		for _, selector := range rule.Users {
			if uid == 0 {
				if name == "root" && selector == "root" {
					return i
				}
			} else if selector == name || selector == "autogroup:nonroot" {
				return i
			}
		}
	}
	return -1
}

func (id Identity) matches(selector string) bool {
	switch {
	case selector == "*":
		return true
	case strings.Contains(selector, "@"):
		return id.Owner != "" && secure.SameEmail(selector, id.Owner)
	case strings.HasPrefix(selector, "device:"):
		return id.DeviceID != "" && selector == "device:"+id.DeviceID
	default:
		return id.Node && selector == id.Device
	}
}

func ParsePolicy(data []byte) (Policy, error) {
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return p, fmt.Errorf("policy must contain exactly one JSON object")
	}
	if p.Rules == nil {
		return p, fmt.Errorf("policy must contain a rules array (use [] to deny all)")
	}
	for _, r := range p.Rules {
		if strings.TrimSpace(r.Name) != r.Name || strings.ContainsAny(r.Name, "\x00\r\n") {
			return p, fmt.Errorf("invalid rule name")
		}
		if len(r.From) == 0 || len(r.Users) == 0 {
			return p, fmt.Errorf("each rule requires from and users")
		}
		for _, s := range append(append([]string{}, r.From...), r.Users...) {
			if s == "" || strings.TrimSpace(s) != s || strings.ContainsAny(s, "\x00\r\n") {
				return p, fmt.Errorf("invalid empty or whitespace policy selector")
			}
		}
		for _, s := range r.From {
			if s == "device:" {
				return p, fmt.Errorf("device selector needs a device ID")
			}
		}
		for _, s := range r.Users {
			if strings.ContainsAny(s, "*:") && s != "autogroup:nonroot" {
				return p, fmt.Errorf("unsupported user selector %q", s)
			}
		}
	}
	return p, nil
}

func LoadPolicy(path string) (Policy, error) {
	f, err := openPolicyFile(path)
	if os.IsNotExist(err) {
		p := DefaultPolicy()
		p.missingPath = path
		return p, nil
	}
	if err != nil {
		return Policy{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return Policy{}, err
	}
	if len(data) > 1<<20 {
		return Policy{}, fmt.Errorf("SSH policy exceeds 1 MiB")
	}
	return ParsePolicy(data)
}

// Missing reports a missing file separately from an explicitly empty policy.
func (p Policy) Missing() bool { return p.missingPath != "" }

func (p Policy) MissingMessage() string {
	prefix := ""
	if os.Geteuid() == 0 {
		prefix = "sudo "
	}
	return fmt.Sprintf("SSH: no policy (denying all): %s; on the server run: %smeshscale ssh policy init --policy %q", p.missingPath, prefix, p.missingPath)
}

func (p Policy) RuleName(index int) string {
	if p.Rules[index].Name != "" {
		return fmt.Sprintf("rule %d (%q)", index+1, p.Rules[index].Name)
	}
	return fmt.Sprintf("rule %d", index+1)
}

// StarterPolicy grants only the verified account owner's identity.
func StarterPolicy(owner string, allowRoot bool) (Policy, error) {
	address, err := mail.ParseAddress(owner)
	if err != nil || address.Address != owner || strings.ContainsAny(owner, "\r\n") {
		return Policy{}, fmt.Errorf("invalid account owner email")
	}
	users := []string{"autogroup:nonroot"}
	if allowRoot {
		users = append(users, "root")
	}
	return Policy{Rules: []Rule{{Name: "account owner", From: []string{owner}, Users: users}}}, nil
}

// InitPolicy publishes a complete policy atomically. Without force a concurrent
// creator wins; even with force, symlinks and insecure paths are refused.
func InitPolicy(path, owner string, allowRoot, force bool) (Policy, error) {
	p, err := StarterPolicy(owner, allowRoot)
	if err != nil {
		return p, err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return p, err
	}
	return p, writePolicyFile(path, append(data, '\n'), force)
}

// LocalUser checks the same account and login-shell constraints as sshd.
func LocalUser(name string) (string, uint32, error) {
	u, err := lookupLocalUser(name)
	if err != nil {
		return "", 0, err
	}
	return u.Name, u.UID, nil
}

// DenialReason explains default deny without treating partial matches as ordered
// deny rules: a later rule may still grant access.
func (p Policy) DenialReason(id Identity, name string, uid uint32) string {
	if uid == 0 && name != "root" {
		return "alternate UID 0 usernames are always denied"
	}
	var matched []string
	for i, rule := range p.Rules {
		if slices.ContainsFunc(rule.From, id.matches) {
			matched = append(matched, p.RuleName(i))
		}
	}
	if len(matched) == 0 {
		return "no rule matched the identity (default deny)"
	}
	return strings.Join(matched, ", ") + " matched the identity but did not allow this local user (default deny)"
}
