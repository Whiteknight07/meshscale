package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Inventory is an immutable account snapshot. A failed refresh retains the last
// successful data and exposes the error instead of silently emptying the list.
type Inventory struct {
	Devices   []Device  `json:"devices"`
	UpdatedAt time.Time `json:"updated_at"`
	Error     string    `json:"error,omitempty"`
	Status    Status    `json:"status"`
}

type InventoryCache struct {
	mu       sync.Mutex
	snapshot Inventory
	load     func(context.Context) ([]Device, error)
	refresh  singleflight.Group
}

func NewInventoryCache(load func(context.Context) ([]Device, error)) *InventoryCache {
	return &InventoryCache{load: load}
}

func (c *InventoryCache) View() Inventory {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Devices and nested fields are published once and never mutated by readers.
	return c.snapshot
}

// inventoryRefreshTimeout bounds one shared refresh, which outlives any
// single caller that gives up on it.
const inventoryRefreshTimeout = 30 * time.Second

// Refresh reloads the inventory, sharing one load among concurrent callers.
// The load does not inherit ctx's cancellation, so a caller that goes away
// cannot fail the refresh for the others still waiting on it.
func (c *InventoryCache) Refresh(ctx context.Context) (Inventory, error) {
	result := c.refresh.DoChan("inventory", func() (any, error) {
		loadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), inventoryRefreshTimeout)
		defer cancel()
		devices, err := c.load(loadCtx)
		c.mu.Lock()
		defer c.mu.Unlock()
		if err != nil {
			c.snapshot.Error = err.Error()
			return c.snapshot, fmt.Errorf("refresh device inventory: %w", err)
		}
		c.snapshot = Inventory{Devices: devices, UpdatedAt: time.Now().UTC()}
		return c.snapshot, nil
	})
	select {
	case <-ctx.Done():
		return Inventory{}, ctx.Err()
	case r := <-result:
		if r.Err != nil {
			return Inventory{}, r.Err
		}
		return r.Val.(Inventory), nil
	}
}

func (c *Control) deviceInventory(w http.ResponseWriter, r *http.Request) {
	if c.Inventory == nil {
		http.Error(w, "device cache unavailable; restart the daemon", http.StatusServiceUnavailable)
		return
	}
	snapshot := c.Inventory.View()
	if r.Method == http.MethodPost {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		fresh, err := c.Inventory.Refresh(ctx)
		switch {
		case err == nil:
			snapshot = fresh
		case snapshot.UpdatedAt.IsZero():
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		default:
			snapshot.Error = err.Error() // serve the last good view
		}
	}
	if snapshot.UpdatedAt.IsZero() {
		http.Error(w, "device cache warming; retry shortly", http.StatusServiceUnavailable)
		return
	}
	snapshot.Status = c.Status()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snapshot)
}
