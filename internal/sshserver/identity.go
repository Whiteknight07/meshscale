// Package sshserver implements SSH authorized by Cloudflare Mesh identity.
package sshserver

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

type Identity struct {
	RegistrationID string
	DeviceID       string
	Device         string
	// Node is true when Device is a Mesh node name, which only account admins
	// can set. Other device names are reported by the client itself.
	Node      bool
	Owner     string
	IP        netip.Addr
	PublicKey string
}

type IdentitySource interface {
	Lookup(context.Context, netip.Addr) (Identity, error)
}

type registryAPI interface {
	ListRegistrations(context.Context, string) ([]cfapi.Registration, error)
	ListMeshNodes(context.Context, string) ([]cfapi.MeshNode, error)
	ListMeshConnectors(context.Context, string, string) ([]cfapi.MeshConnector, error)
}

// Registry keeps one short-lived account snapshot. Expired data is never used
// after an API error. Revocation can take up to CacheTTL to affect new sessions.
type Registry struct {
	API           registryAPI
	Account       string
	CacheTTL      time.Duration
	mu            sync.Mutex
	expires       time.Time
	registrations []cfapi.Registration
	names         map[string]string
}

func (r *Registry) Lookup(ctx context.Context, ip netip.Addr) (Identity, error) {
	if !meshaddr.IsDevice(ip) {
		return Identity{}, fmt.Errorf("source is outside the Mesh device ranges")
	}
	ip = ip.Unmap()
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	if !time.Now().Before(r.expires) {
		r.registrations, r.names, r.expires = nil, nil, time.Time{}
		registrations, err := r.API.ListRegistrations(ctx, r.Account)
		if err != nil {
			return Identity{}, fmt.Errorf("refresh registrations: %w", err)
		}
		nodes, err := r.API.ListMeshNodes(ctx, r.Account)
		if err != nil {
			return Identity{}, fmt.Errorf("refresh node names: %w", err)
		}
		names := map[string]string{}
		for _, n := range nodes {
			if n.DeletedAt != nil {
				continue
			}
			connectors, err := r.API.ListMeshConnectors(ctx, r.Account, n.ID)
			if err != nil {
				return Identity{}, fmt.Errorf("refresh node identity: %w", err)
			}
			for _, c := range connectors {
				if _, exists := names[c.ID]; exists {
					return Identity{}, fmt.Errorf("ambiguous Mesh node registration")
				}
				names[c.ID] = n.Name
			}
		}
		if err := ctx.Err(); err != nil {
			return Identity{}, err
		}
		r.registrations, r.names = registrations, names
		ttl := r.CacheTTL
		if ttl <= 0 || ttl > 15*time.Second {
			ttl = 15 * time.Second
		}
		r.expires = time.Now().Add(ttl)
	}
	var result Identity
	for _, reg := range r.registrations {
		if reg.DeletedAt != nil || reg.RevokedAt != nil || (reg.RegistrationType != "" && reg.RegistrationType != "warp") {
			continue
		}
		v4, _ := netip.ParseAddr(reg.VirtualIPv4)
		v6, _ := netip.ParseAddr(reg.VirtualIPv6)
		if ip != v4.Unmap() && ip != v6.Unmap() {
			continue
		}
		if result.RegistrationID != "" {
			return Identity{}, fmt.Errorf("multiple active registrations own source IP")
		}
		if reg.ID == "" || reg.Device.ID == "" {
			return Identity{}, fmt.Errorf("incomplete device registration")
		}
		name, node := reg.Device.Name, false
		if n := r.names[reg.ID]; n != "" {
			name, node = n, true
		}
		result = Identity{RegistrationID: reg.ID, DeviceID: reg.Device.ID, Device: name, Node: node, Owner: reg.User.Email, IP: ip}
	}
	if result.RegistrationID == "" {
		return Identity{}, fmt.Errorf("no active registration owns source IP")
	}
	return result, nil
}
