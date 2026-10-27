package sshserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"testing"
)

type fakeIdentitySource struct {
	err   error
	calls int
}

func (f *fakeIdentitySource) Lookup(_ context.Context, ip netip.Addr) (Identity, error) {
	f.calls++
	if f.err != nil {
		return Identity{}, f.err
	}
	return Identity{RegistrationID: "reg", DeviceID: "dev", Device: "laptop", Owner: "alice@example.com", IP: ip}, nil
}

func testAuthorizer(out *bytes.Buffer) *Authorizer {
	return &Authorizer{
		Identities: &fakeIdentitySource{}, Audit: log.New(out, "", 0),
		loadPolicy: func() (Policy, error) {
			return Policy{Rules: []Rule{{From: []string{"*"}, Users: []string{"autogroup:nonroot"}}}}, nil
		},
		lookupUser: func(name string) (*localUser, error) {
			if name == "missing" {
				return nil, fmt.Errorf("unknown user")
			}
			uid := uint32(1000)
			if name == "root" || name == "alias" {
				uid = 0
			}
			return &localUser{Name: name, UID: uid, Shell: "/bin/sh", Home: "/tmp"}, nil
		},
	}
}

func TestAuthDecisions(t *testing.T) {
	for _, tc := range []struct {
		name, user, ip           string
		apiErr, policyErr, allow bool
	}{
		{"allow", "alice", "100.96.0.3", false, false, true},
		{"root", "root", "100.96.0.3", false, false, false},
		{"uid0 alias", "alias", "100.96.0.3", false, false, false},
		{"unknown user", "missing", "100.96.0.3", false, false, false},
		{"API failure", "alice", "100.96.0.3", true, false, false},
		{"policy failure", "alice", "100.96.0.3", false, true, false},
		{"public", "alice", "203.0.113.1", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			a := testAuthorizer(&out)
			source := a.Identities.(*fakeIdentitySource)
			if tc.apiErr {
				source.err = errors.New("API unavailable")
			}
			if tc.policyErr {
				a.loadPolicy = func() (Policy, error) { return Policy{}, errors.New("invalid policy") }
			}
			_, err := a.authorize(context.Background(), &net.TCPAddr{IP: net.ParseIP(tc.ip), Port: 1234}, tc.user)
			if (err == nil) != tc.allow {
				t.Fatalf("err=%v want allow=%v", err, tc.allow)
			}
			decision := "deny"
			if tc.allow {
				decision = "accept"
			}
			if !strings.Contains(out.String(), "decision="+decision) || !strings.Contains(out.String(), `user="`+tc.user+`"`) || !strings.Contains(out.String(), tc.ip) {
				t.Fatalf("incomplete audit: %s", out.String())
			}
			if tc.ip == "203.0.113.1" && source.calls != 0 {
				t.Fatal("queried API for non-Mesh source")
			}
		})
	}
}

func TestRootlessServerRestrictsLocalUID(t *testing.T) {
	var out bytes.Buffer
	a := testAuthorizer(&out)
	uid := uint32(1001)
	a.LocalUID = &uid
	a.lookupUser = func(name string) (*localUser, error) {
		id := uid
		if name == "other" {
			id = 1002
		}
		return &localUser{Name: name, UID: id, Home: "/tmp", Shell: "/bin/sh"}, nil
	}
	remote := &net.TCPAddr{IP: net.ParseIP("100.96.0.2"), Port: 1234}
	if _, err := a.authorize(context.Background(), remote, "self"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.authorize(context.Background(), remote, "other"); err == nil {
		t.Fatal("rootless server authorized another UID")
	}
}

func TestAuthRechecksPolicyAfterIdentityLookup(t *testing.T) {
	var out bytes.Buffer
	a := testAuthorizer(&out)
	loads := 0
	a.loadPolicy = func() (Policy, error) {
		loads++
		if loads == 1 {
			return Policy{Rules: []Rule{{From: []string{"*"}, Users: []string{"autogroup:nonroot"}}}}, nil
		}
		p := DefaultPolicy()
		p.missingPath = "/missing/ssh.json"
		return p, nil
	}
	_, err := a.authorize(context.Background(), &net.TCPAddr{IP: net.ParseIP("100.96.0.3"), Port: 1234}, "alice")
	if err == nil || !strings.Contains(err.Error(), "no policy (denying all)") || loads != 2 {
		t.Fatalf("loads=%d error=%v", loads, err)
	}
}
