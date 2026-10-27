package linuxnetwork

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

// Protocol 243 tags only our overlap rule; exit routing separately uses 242.
const coexistenceProtocol = 243

type policyRule struct {
	Priority, Table, Protocol int
	Destination               netip.Prefix
	Mark                      uint32
	Invert                    bool
}

func (r policyRule) owned() bool {
	return r.Destination == meshaddr.IPv4Range && r.Table == 52 && r.Protocol == coexistenceProtocol
}

type routingSnapshot struct {
	Rules            []policyRule
	WARPTables       map[int]bool
	TailscaleDefault bool
}

// routingRunner uses netlink for both snapshots and mutations. Changed drains
// kernel notifications without blocking; unchanged ticks do not dump routing.
type routingRunner interface {
	Changed() (bool, error)
	Snapshot(bool) (routingSnapshot, error)
	Add(policyRule) error
	Delete(policyRule) error
	Close()
}

type routingManager struct {
	mu      sync.Mutex
	run     routingRunner
	valid   bool
	enabled bool
	warn    func(string, ...any)
}

func (m *routingManager) reconcile(ctx context.Context, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.apply(ctx, enabled)
}
func (m *routingManager) cleanup(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	defer m.run.Close()
	defer func() { m.valid = false }()
	return m.apply(ctx, false)
}
func (m *routingManager) apply(ctx context.Context, enabled bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	changed, err := m.run.Changed()
	if err != nil {
		return fmt.Errorf("watch coexistence routing: %w", err)
	}
	if m.valid && m.enabled == enabled && !changed {
		return nil
	}
	m.valid = false
	snapshot, err := m.run.Snapshot(enabled)
	if err != nil {
		return fmt.Errorf("inspect coexistence routing: %w", err)
	}
	priority := 0
	if enabled {
		priority = overlapPriority(snapshot)
	}
	if enabled && snapshot.TailscaleDefault && m.warn != nil {
		m.warn("Warning: skipping Mesh/Tailscale overlap rule: table 52 has a default route (Tailscale exit node); Mesh traffic could be captured")
	}
	present := false
	for _, rule := range snapshot.Rules {
		if !rule.owned() {
			continue
		}
		if priority != 0 && rule.Priority == priority && !present {
			present = true
			continue
		}
		if err := m.run.Delete(rule); err != nil {
			return fmt.Errorf("remove Mesh/Tailscale overlap rule: %w", err)
		}
	}
	if priority != 0 && !present {
		rule := policyRule{Priority: priority, Table: 52, Protocol: coexistenceProtocol, Destination: meshaddr.IPv4Range}
		if err := m.run.Add(rule); err != nil {
			return fmt.Errorf("install Mesh/Tailscale overlap rule: %w", err)
		}
	}
	m.valid, m.enabled = true, enabled
	return nil
}
func overlapPriority(snapshot routingSnapshot) int {
	if snapshot.TailscaleDefault {
		return 0
	}
	priority := 0
	for _, rule := range snapshot.Rules {
		if rule.Invert && rule.Mark != 0 && snapshot.WARPTables[rule.Table] && rule.Priority > 1 && (priority == 0 || rule.Priority-1 < priority) {
			priority = rule.Priority - 1
		}
	}
	return priority
}
