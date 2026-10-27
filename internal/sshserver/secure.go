package sshserver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Whiteknight07/meshscale/internal/meshaddr"
	"github.com/Whiteknight07/meshscale/internal/secure"
)

// KeyRegistry joins secure IP -> authenticated WireGuard key -> live account
// registration. It never accepts a secure identity via the plain Mesh listener.
type KeyRegistry struct {
	Load    func(context.Context) ([]secure.Peer, error)
	Plain   IdentitySource
	mu      sync.Mutex
	peers   []secure.Peer
	expires time.Time
	refresh *keyRefresh
}

type keyRefresh struct {
	done  chan struct{}
	peers []secure.Peer
	err   error
}

func (r *KeyRegistry) snapshot(ctx context.Context) ([]secure.Peer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if time.Now().Before(r.expires) {
		peers := r.peers
		r.mu.Unlock()
		return peers, nil
	}
	call := r.refresh
	if call == nil {
		call = &keyRefresh{done: make(chan struct{})}
		r.refresh = call
		r.peers, r.expires = nil, time.Time{}
		go r.refreshKeys(call)
	}
	r.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-call.done:
		return call.peers, call.err
	}
}

func (r *KeyRegistry) refreshKeys(call *keyRefresh) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if r.Load == nil {
		call.err = fmt.Errorf("secure key source unavailable")
	} else {
		call.peers, call.err = r.Load(ctx)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if call.err == nil && ctx.Err() == nil {
		r.peers = call.peers
		r.expires = time.Now().Add(15 * time.Second)
	} else {
		if call.err == nil {
			call.err = ctx.Err()
		}
		call.peers = nil
	}
	r.refresh = nil
	close(call.done)
}

func (r *KeyRegistry) Lookup(ctx context.Context, ip netip.Addr) (Identity, error) {
	if !secure.IsIP(ip) {
		return Identity{}, fmt.Errorf("not a secure source address")
	}
	peers, err := r.snapshot(ctx)
	if err != nil {
		return Identity{}, err
	}
	var result Identity
	for _, p := range peers {
		if p.IP != ip {
			continue
		}
		if result.PublicKey != "" {
			return Identity{}, fmt.Errorf("ambiguous secure identity")
		}
		result = Identity{RegistrationID: p.RegistrationID, DeviceID: p.DeviceID, Device: p.Name, Node: p.Node, Owner: p.Owner, IP: ip, PublicKey: p.PublicKey}
	}
	if result.PublicKey == "" {
		return Identity{}, fmt.Errorf("no WireGuard key owns source address")
	}
	return result, nil
}

// LookupPlain prevents downgrade: peers advertising secure mode must use their
// key, while phones and other plain-only participants retain Mesh-IP identity.
func (r *KeyRegistry) LookupPlain(ctx context.Context, ip netip.Addr) (Identity, error) {
	if !meshaddr.IsDevice(ip) {
		return Identity{}, fmt.Errorf("not a Mesh source address")
	}
	peers, err := r.snapshot(ctx)
	if err != nil {
		return Identity{}, err
	}
	if r.Plain == nil {
		return Identity{}, fmt.Errorf("plain identity source unavailable")
	}
	id, err := r.Plain.Lookup(ctx, ip)
	if err != nil {
		return Identity{}, err
	}
	for _, p := range peers {
		if p.RegistrationID == id.RegistrationID {
			return Identity{}, fmt.Errorf("secure peer must connect through WireGuard")
		}
	}
	return id, nil
}

type plainKeys struct{ *KeyRegistry }

func (p plainKeys) Lookup(ctx context.Context, ip netip.Addr) (Identity, error) {
	return p.LookupPlain(ctx, ip)
}
func (r *KeyRegistry) PlainSource() IdentitySource { return plainKeys{r} }

// SecureListener marks only trusted WireGuard netstack/TUN listeners, including
// leases received over the same-UID private daemon socket. Callers must never
// wrap an ordinary Mesh listener. TUN listeners use SO_BINDTODEVICE on Linux.
func SecureListener(l net.Listener) net.Listener { return secureListener{l} }

type secureListener struct{ net.Listener }
type secureConn struct{ net.Conn }

func (secureConn) wireGuardAuthenticated() {}
func (l secureListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return secureConn{c}, nil
}
