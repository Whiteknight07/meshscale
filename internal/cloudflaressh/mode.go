// Package cloudflaressh provisions Cloudflare Access for Infrastructure. The
// account CA is deliberately absent from the resource deletion interface.
package cloudflaressh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
	"golang.org/x/crypto/ssh"
)

type CAService interface {
	SSHCA(context.Context, string) (cfapi.SSHCA, error)
	CreateSSHCA(context.Context, string) (cfapi.SSHCA, error)
}

func EnsureCA(ctx context.Context, api CAService, account string) (cfapi.SSHCA, bool, error) {
	ca, err := api.SSHCA(ctx, account)
	created := false
	if err != nil {
		if !cfapi.IsMissing(err) {
			return ca, false, fmt.Errorf("read account SSH CA (requires access-ssh-auditing.write; renew meshscale login): %w", err)
		}
		ca, err = api.CreateSSHCA(ctx, account)
		created = err == nil
		if err != nil {
			return ca, false, fmt.Errorf("create account SSH CA: %w", err)
		}
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(ca.PublicKey))
	if err != nil {
		return ca, created, fmt.Errorf("parse account SSH CA public key: %w", err)
	}
	if len(rest) != 0 || ca.ID == "" {
		return ca, created, fmt.Errorf("cloudflare returned an invalid account SSH CA")
	}
	if _, ok := key.(*ssh.Certificate); ok {
		return ca, created, fmt.Errorf("cloudflare returned a certificate instead of a CA public key")
	}
	return ca, created, nil
}

type Resources interface {
	InfrastructureTarget(context.Context, string, string) (cfapi.InfrastructureTarget, error)
	InfrastructureApplication(context.Context, string, string) (cfapi.InfrastructureApplication, error)
	ListInfrastructureTargets(context.Context, string) ([]cfapi.InfrastructureTarget, error)
	ListInfrastructureApplications(context.Context, string) ([]cfapi.InfrastructureApplication, error)
	PutInfrastructureTarget(context.Context, string, cfapi.InfrastructureTarget) (cfapi.InfrastructureTarget, error)
	DeleteInfrastructureTarget(context.Context, string, string) error
	PutInfrastructureApplication(context.Context, string, cfapi.InfrastructureApplication) (cfapi.InfrastructureApplication, error)
	DeleteInfrastructureApplication(context.Context, string, string) error
}
type State struct {
	TargetVirtualNetwork string     `json:"target_virtual_network,omitempty"`
	Nonce                string     `json:"nonce,omitempty"`
	TargetAttempted      bool       `json:"target_attempted,omitempty"`
	AppAttempted         bool       `json:"app_attempted,omitempty"`
	Mode                 string     `json:"mode"`
	Account              string     `json:"account"`
	Name                 string     `json:"name"`
	IP                   string     `json:"ip"`
	Owner                string     `json:"owner"`
	Users                []string   `json:"users"`
	CAID                 string     `json:"ca_id"`
	TargetID             string     `json:"target_id,omitempty"`
	AppID                string     `json:"app_id,omitempty"`
	PolicyIDs            []string   `json:"policy_ids,omitempty"`
	Host                 *HostState `json:"host,omitempty"`
}
type Store interface{ Save(State) error }
type Host interface {
	Enable(context.Context, *State, string) error
	Disable(context.Context, *State, string) error
}
type Manager struct {
	Resources Resources
	Store     Store
	Host      Host
}

var usernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]*[$]?$`)

func Validate(s State) error {
	ip, err := netip.ParseAddr(s.IP)
	if err != nil {
		return fmt.Errorf("parse server Mesh IP: %w", err)
	}
	if ip.Zone() != "" || !(meshaddr.IsIPv4(ip) || netip.MustParsePrefix("2606:4700:cf1:1000::/64").Contains(ip)) {
		return fmt.Errorf("server IP is outside the supported Mesh device ranges")
	}
	email, err := mail.ParseAddress(s.Owner)
	if err != nil || email.Address != s.Owner || strings.ContainsAny(s.Owner, "\r\n") {
		return fmt.Errorf("invalid owner email")
	}
	if s.Name == "" || strings.ContainsAny(s.Name, "\r\n\x00") || len(s.Users) == 0 {
		return fmt.Errorf("server name and explicit local usernames are required")
	}
	for _, u := range s.Users {
		if !usernamePattern.MatchString(u) {
			return fmt.Errorf("invalid explicit local username %q", u)
		}
	}
	return nil
}

// desiredResources binds the remote target and application to one random,
// durably journaled creation. Predictable user-facing names prove no ownership.
func desiredResources(s *State) (cfapi.InfrastructureTarget, cfapi.InfrastructureApplication) {
	hostname := "meshscale-ssh-" + s.Nonce
	target := cfapi.InfrastructureTarget{ID: s.TargetID, Hostname: hostname}
	ip := &cfapi.TargetIP{Address: s.IP, VirtualNetworkID: s.TargetVirtualNetwork}
	if netip.MustParseAddr(s.IP).Is4() {
		target.IP.IPv4 = ip
	} else {
		target.IP.IPv6 = ip
	}
	p := cfapi.InfrastructurePolicy{Name: s.Name + " owner", Decision: "allow", Include: []map[string]any{{"email": map[string]string{"email": s.Owner}}}}
	if len(s.PolicyIDs) == 1 {
		p.ID = s.PolicyIDs[0]
	}
	p.ConnectionRules.SSH.Usernames = append([]string(nil), s.Users...)
	sort.Strings(p.ConnectionRules.SSH.Usernames)
	criterion := cfapi.InfrastructureCriterion{Port: 22, Protocol: "SSH"}
	criterion.Include.TargetAttributes.Hostname = []string{hostname}
	app := cfapi.InfrastructureApplication{ID: s.AppID, Name: s.Name + " meshscale-create:" + s.Nonce, Type: "infrastructure", SessionDuration: "15m", TargetCriteria: []cfapi.InfrastructureCriterion{criterion}, Policies: []cfapi.InfrastructurePolicy{p}}
	return target, app
}
func pinCreatedTarget(s *State, actual cfapi.InfrastructureTarget) error {
	wanted, _ := desiredResources(s)
	if s.TargetID != "" {
		return verifyTarget(actual, wanted)
	}
	var network string
	if actual.IP.IPv4 != nil {
		network = actual.IP.IPv4.VirtualNetworkID
	}
	if actual.IP.IPv6 != nil {
		network = actual.IP.IPv6.VirtualNetworkID
	}
	if wanted.IP.IPv4 != nil {
		wanted.IP.IPv4.VirtualNetworkID = network
	}
	if wanted.IP.IPv6 != nil {
		wanted.IP.IPv6.VirtualNetworkID = network
	}
	if err := verifyTarget(actual, wanted); err != nil {
		return err
	}
	s.TargetVirtualNetwork = network
	return nil
}
func verifyTarget(actual, wanted cfapi.InfrastructureTarget) error {
	if actual.ID == "" || wanted.ID != "" && actual.ID != wanted.ID || actual.Hostname != wanted.Hostname || !reflect.DeepEqual(actual.IP, wanted.IP) {
		return fmt.Errorf("SSH target ownership or address mismatch; refusing mutation")
	}
	return nil
}
func verifyApplication(actual, wanted cfapi.InfrastructureApplication) error {
	fail := func() error {
		return fmt.Errorf("SSH application ownership, target or owner-only policy mismatch; refusing mutation")
	}
	if actual.ID == "" || wanted.ID != "" && actual.ID != wanted.ID || actual.Name != wanted.Name || actual.Type != "infrastructure" || len(actual.Policies) != 1 || !reflect.DeepEqual(actual.TargetCriteria, wanted.TargetCriteria) {
		return fail()
	}
	a, b := actual.Policies[0], wanted.Policies[0]
	// JSON normalization also handles map[string]any returned by API decoding.
	includeA, _ := json.Marshal(a.Include)
	includeB, _ := json.Marshal(b.Include)
	users := append([]string(nil), a.ConnectionRules.SSH.Usernames...)
	sort.Strings(users)
	if a.Decision != "allow" || string(includeA) != string(includeB) || len(a.Exclude) != 0 || len(a.Require) != 0 || !reflect.DeepEqual(users, b.ConnectionRules.SSH.Usernames) {
		return fail()
	}
	return nil
}
func (m Manager) verifyResources(ctx context.Context, s *State, allowMissing bool) error {
	if s.Nonce == "" && (s.TargetID != "" || s.AppID != "" || s.TargetAttempted || s.AppAttempted) {
		return fmt.Errorf("saved SSH resources have no creation nonce; manual administrator review is required")
	}
	if s.Nonce == "" {
		return nil
	}
	if decoded, err := hex.DecodeString(s.Nonce); err != nil || len(decoded) != 16 {
		return fmt.Errorf("invalid SSH creation nonce")
	}
	if err := Validate(*s); err != nil {
		return err
	}
	target, app := desiredResources(s)
	if s.TargetID != "" {
		actual, err := m.Resources.InfrastructureTarget(ctx, s.Account, s.TargetID)
		if !(allowMissing && cfapi.IsMissing(err)) {
			if err != nil {
				return fmt.Errorf("read owned SSH target: %w", err)
			}
			if err := verifyTarget(actual, target); err != nil {
				return err
			}
		}
	}
	if s.AppID != "" {
		actual, err := m.Resources.InfrastructureApplication(ctx, s.Account, s.AppID)
		if !(allowMissing && cfapi.IsMissing(err)) {
			if err != nil {
				return fmt.Errorf("read owned SSH application: %w", err)
			}
			if err := verifyApplication(actual, app); err != nil {
				return err
			}
		}
	}
	return nil
}

// Recover interrupted POSTs using their exact creation markers, never a server
// name or IP shared with an administrator's independently created resources.
func (m Manager) recoverResources(ctx context.Context, s *State) error {
	previousTarget, previousApp := s.TargetID, s.AppID
	if !s.TargetAttempted && !s.AppAttempted {
		return nil
	}
	if err := Validate(*s); err != nil {
		return err
	}
	if s.Nonce == "" {
		return fmt.Errorf("SSH recovery requires a creation nonce")
	}
	target, app := desiredResources(s)
	if s.TargetID == "" && s.TargetAttempted {
		targets, err := m.Resources.ListInfrastructureTargets(ctx, s.Account)
		if err != nil {
			return fmt.Errorf("recover SSH target: %w", err)
		}
		for _, candidate := range targets {
			if candidate.Hostname != target.Hostname {
				continue
			}
			if err := pinCreatedTarget(s, candidate); err != nil {
				return err
			}
			if s.TargetID != "" {
				return fmt.Errorf("ambiguous SSH target creation nonce")
			}
			s.TargetID = candidate.ID
		}
	}
	if s.AppID == "" && s.AppAttempted {
		apps, err := m.Resources.ListInfrastructureApplications(ctx, s.Account)
		if err != nil {
			return fmt.Errorf("recover SSH application: %w", err)
		}
		for _, candidate := range apps {
			if candidate.Name != app.Name {
				continue
			}
			actual, err := m.Resources.InfrastructureApplication(ctx, s.Account, candidate.ID)
			if err != nil {
				return err
			}
			if actual.ID != candidate.ID {
				return fmt.Errorf("recovered SSH application ID mismatch")
			}
			if err := verifyApplication(actual, app); err != nil {
				return err
			}
			if s.AppID != "" {
				return fmt.Errorf("ambiguous SSH application creation nonce")
			}
			s.AppID = actual.ID
		}
	}
	if previousTarget != s.TargetID || previousApp != s.AppID {
		return m.Store.Save(*s)
	}
	return nil
}
func (m Manager) Enable(ctx context.Context, s *State, ca cfapi.SSHCA) error {
	if err := Validate(*s); err != nil {
		return err
	}
	if err := m.recoverResources(ctx, s); err != nil {
		return err
	}
	if err := m.verifyResources(ctx, s, false); err != nil {
		return err
	}
	if s.Nonce == "" {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return fmt.Errorf("create SSH ownership nonce: %w", err)
		}
		s.Nonce = hex.EncodeToString(nonce[:])
	}
	s.CAID = ca.ID
	if err := m.Store.Save(*s); err != nil {
		return fmt.Errorf("save SSH migration: %w", err)
	}
	target, app := desiredResources(s)
	if s.TargetID == "" {
		s.TargetAttempted = true
		if err := m.Store.Save(*s); err != nil {
			return err
		}
	}
	t, err := m.Resources.PutInfrastructureTarget(ctx, s.Account, target)
	if err != nil {
		return fmt.Errorf("provision SSH target (retry to recover creation): %w", err)
	}
	if err := pinCreatedTarget(s, t); err != nil {
		return err
	}
	s.TargetID = t.ID
	if err := m.Store.Save(*s); err != nil {
		return fmt.Errorf("persist SSH target before continuing: %w", err)
	}
	if s.AppID == "" {
		s.AppAttempted = true
		if err := m.Store.Save(*s); err != nil {
			return err
		}
	}
	a, err := m.Resources.PutInfrastructureApplication(ctx, s.Account, app)
	if err != nil {
		return fmt.Errorf("provision owner-only SSH application (retry to recover creation): %w", err)
	}
	if a.ID == "" || app.ID != "" && a.ID != app.ID {
		return fmt.Errorf("SSH application response ID mismatch")
	}
	actual, err := m.Resources.InfrastructureApplication(ctx, s.Account, a.ID)
	if err != nil {
		return fmt.Errorf("verify created SSH application: %w", err)
	}
	if actual.ID != a.ID {
		return fmt.Errorf("SSH application read-back ID mismatch")
	}
	if err := verifyApplication(actual, app); err != nil {
		return err
	}
	a = actual
	s.AppID = a.ID
	s.PolicyIDs = nil
	for _, p := range a.Policies {
		s.PolicyIDs = append(s.PolicyIDs, p.ID)
	}
	if err := m.Store.Save(*s); err != nil {
		return fmt.Errorf("persist SSH application before continuing: %w", err)
	}
	// Fetch effective policies separately: an application response may contain
	// only policy references rather than the actual enforcement selectors.
	if err := m.verifyResources(ctx, s, false); err != nil {
		return err
	}
	if err := m.Host.Enable(ctx, s, ca.PublicKey); err != nil {
		return fmt.Errorf("configure OpenSSH (resources tracked for retry or ssh-mode own): %w", err)
	}
	s.Mode = "cloudflare"
	return m.Store.Save(*s)
}
func (m Manager) Disable(ctx context.Context, s *State, mode string) error {
	if mode != "own" && mode != "off" {
		return fmt.Errorf("invalid SSH mode %q", mode)
	}
	if err := m.recoverResources(ctx, s); err != nil {
		return err
	}
	if err := m.verifyResources(ctx, s, true); err != nil {
		return err
	}
	// Remove interception first; never expose the old listener on an API failure.
	if s.AppID != "" {
		if err := m.Resources.DeleteInfrastructureApplication(ctx, s.Account, s.AppID); err != nil && !cfapi.IsMissing(err) {
			return fmt.Errorf("delete owned SSH application: %w", err)
		}
		s.AppID = ""
		s.PolicyIDs = nil
		s.AppAttempted = false
		if err := m.Store.Save(*s); err != nil {
			return err
		}
	}
	if s.TargetID != "" {
		if err := m.Resources.DeleteInfrastructureTarget(ctx, s.Account, s.TargetID); err != nil && !cfapi.IsMissing(err) {
			return fmt.Errorf("delete owned SSH target: %w", err)
		}
		s.TargetID = ""
		s.TargetAttempted = false
		if err := m.Store.Save(*s); err != nil {
			return err
		}
	}
	if err := m.Host.Disable(ctx, s, mode); err != nil {
		return fmt.Errorf("restore SSH server: %w", err)
	}
	s.Mode = mode
	s.Nonce = ""
	s.TargetVirtualNetwork = ""
	s.TargetAttempted = false
	s.AppAttempted = false
	return m.Store.Save(*s)
}

// JoinRollback retains the original error as well as a failed rollback.
func JoinRollback(err, rollback error) error {
	if rollback == nil {
		return err
	}
	return errors.Join(err, fmt.Errorf("SSH rollback: %w", rollback))
}
