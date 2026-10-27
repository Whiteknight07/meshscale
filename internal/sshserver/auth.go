package sshserver

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/Whiteknight07/meshscale/internal/meshaddr"
	"github.com/Whiteknight07/meshscale/internal/secure"
)

type localUser struct {
	Name, Home, Shell string
	UID, GID          uint32
	Groups            []uint32
	identity          Identity
}

type Authorizer struct {
	Identities       IdentitySource
	SecureIdentities IdentitySource
	LocalUID         *uint32 // rootless servers may serve only their own UID
	PolicyPath       string
	Audit            *log.Logger
	lookupUser       func(string) (*localUser, error)
	loadPolicy       func() (Policy, error)
}

func (a *Authorizer) audit(decision string, id Identity, ip, user, reason string) {
	logger := a.Audit
	if logger == nil {
		logger = log.Default()
	}
	logger.Printf("ssh decision=%s owner=%q device=%q registration=%q wireguard_key=%q ip=%q user=%q reason=%q", decision, id.Owner, id.Device, id.RegistrationID, id.PublicKey, ip, user, reason)
}

func (a *Authorizer) authorize(ctx context.Context, remote net.Addr, username string) (target *localUser, err error) {
	return a.authorizeConnection(ctx, remote, username, false)
}

func (a *Authorizer) authorizeConnection(ctx context.Context, remote net.Addr, username string, authenticated bool) (target *localUser, err error) {
	var id Identity
	ipText, _, splitErr := net.SplitHostPort(remote.String())
	defer func() {
		decision, reason := "accept", "identity and policy allow login"
		if err != nil {
			decision, reason = "deny", err.Error()
		}
		a.audit(decision, id, ipText, username, reason)
	}()
	load := a.loadPolicy
	if load == nil {
		load = func() (Policy, error) { return LoadPolicy(a.PolicyPath) }
	}
	p, policyErr := load()
	if policyErr == nil && p.Missing() {
		return nil, &missingPolicyError{p}
	}
	ip, parseErr := netip.ParseAddr(ipText)
	source := a.Identities
	if authenticated {
		source = a.SecureIdentities
	}
	if splitErr != nil || parseErr != nil || (!authenticated && !meshaddr.IsDevice(ip)) || (authenticated && !secure.IsIP(ip)) {
		return nil, fmt.Errorf("source is outside the Mesh device ranges")
	}
	if source == nil {
		return nil, fmt.Errorf("identity source is unavailable")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	id, err = source.Lookup(lookupCtx, ip.Unmap())
	if err != nil {
		return nil, fmt.Errorf("identity lookup failed: %w", err)
	}
	if id.RegistrationID == "" || id.DeviceID == "" || id.IP != ip.Unmap() || authenticated && id.PublicKey == "" || !authenticated && id.PublicKey != "" {
		return nil, fmt.Errorf("identity lookup returned an invalid identity")
	}
	lookup := a.lookupUser
	if lookup == nil {
		lookup = lookupLocalUser
	}
	target, err = lookup(username)
	if err != nil {
		return nil, fmt.Errorf("local user unavailable: %w", err)
	}
	if a.LocalUID != nil && target.UID != *a.LocalUID {
		return nil, fmt.Errorf("rootless SSH server can only serve its own local user")
	}
	// Identity lookup can take seconds; re-read at admission so a policy removed
	// or replaced during the lookup cannot authorize using the earlier snapshot.
	p, policyErr = load()
	if policyErr != nil {
		return nil, fmt.Errorf("read SSH policy: %w", policyErr)
	}
	if p.Missing() {
		return nil, &missingPolicyError{p}
	}

	if !p.Allows(id, target.Name, target.UID) {
		return nil, fmt.Errorf("SSH policy does not allow this local user")
	}
	target.identity = id
	return target, nil
}

type missingPolicyError struct{ policy Policy }

func (e *missingPolicyError) Error() string { return e.policy.MissingMessage() }
