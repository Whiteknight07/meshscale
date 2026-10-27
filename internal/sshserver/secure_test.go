package sshserver

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/secure"
)

func TestSecureIdentityAdmission(t *testing.T) {
	key, _ := secure.GenerateKey()
	public, _ := key.Public()
	ip, _ := secure.Address("account", public)
	peer := secure.Peer{RegistrationID: "reg", DeviceID: "dev", Name: "laptop", Owner: "alice@example.com", PublicKey: public, IP: ip, MeshIP: netip.MustParseAddr("100.96.0.3")}
	for _, tc := range []struct {
		name                             string
		ip                               netip.Addr
		authenticated, securePeer, allow bool
	}{
		{"secure key on secure interface", ip, true, true, true},
		{"secure IP spoofed on Mesh", ip, false, true, false},
		{"Mesh peer claims secure interface", peer.MeshIP, true, true, false},
		{"secure peer downgrade", peer.MeshIP, false, true, false},
		{"plain phone fallback", peer.MeshIP, false, false, true},
		{"unknown secure key", ip, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			a := testAuthorizer(&out)
			keys := &KeyRegistry{Plain: a.Identities, Load: func(context.Context) ([]secure.Peer, error) {
				if tc.securePeer {
					return []secure.Peer{peer}, nil
				}
				return nil, nil
			}}
			a.Identities = keys.PlainSource()
			a.SecureIdentities = keys
			user, err := a.authorizeConnection(t.Context(), net.TCPAddrFromAddrPort(netip.AddrPortFrom(tc.ip, 1234)), "alice", tc.authenticated)
			if (err == nil) != tc.allow {
				t.Fatalf("allow=%t error=%v log=%s", tc.allow, err, out.String())
			}
			if err == nil && tc.authenticated && user.identity.PublicKey != public {
				t.Fatal("identity lost key")
			}
		})
	}
}
func TestSecureRegistryRefreshFailure(t *testing.T) {
	key, _ := secure.GenerateKey()
	public, _ := key.Public()
	ip, _ := secure.Address("account", public)
	failed := false
	r := &KeyRegistry{Load: func(context.Context) ([]secure.Peer, error) {
		if failed {
			return nil, errors.New("API offline")
		}
		return []secure.Peer{{RegistrationID: "reg", DeviceID: "dev", PublicKey: public, IP: ip}}, nil
	}}
	if _, err := r.Lookup(t.Context(), ip); err != nil {
		t.Fatal(err)
	}
	failed = true
	r.expires = time.Time{}
	if _, err := r.Lookup(t.Context(), ip); err == nil {
		t.Fatal("stale key accepted after failed refresh")
	}
	if len(r.peers) != 0 {
		t.Fatal("failed refresh retained identity")
	}
}

func TestKeyRegistrySlowRefresh(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	registry := &KeyRegistry{Load: func(ctx context.Context) ([]secure.Peer, error) {
		close(started)
		select {
		case <-release:
			return nil, errors.New("offline")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	first := make(chan error, 1)
	go func() { _, err := registry.snapshot(t.Context()); first <- err }()
	<-started
	// A second caller can cancel promptly while a single shared load is slow.
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	second := make(chan error, 1)
	go func() { _, err := registry.snapshot(ctx); second <- err }()
	select {
	case err := <-second:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("slow API held registry mutex")
	}
	registry.mu.Lock()
	if registry.refresh == nil {
		t.Fatal("missing refresh")
	}
	if registry.peers != nil || !registry.expires.IsZero() {
		t.Fatal("stale peers retained")
	}
	registry.mu.Unlock()
	close(release)
	if err := <-first; err == nil {
		t.Fatal("load error authorized stale peers")
	}
}

func BenchmarkKeyRegistryCached(b *testing.B) {
	registry := &KeyRegistry{peers: []secure.Peer{{RegistrationID: "peer"}}, expires: time.Now().Add(time.Hour)}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := registry.snapshot(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}
