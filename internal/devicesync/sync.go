// Package devicesync runs account reconciliation after the device set changes.
package devicesync

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

// Device omits volatile last-seen timestamps so polling does not cause writes.
type Device struct {
	ID    string
	Name  string
	IPv4  string
	IPv6  string
	Owner string
}
type Snapshot struct {
	// LocalHosts is set only by local up/daemon, never by account-only callers.
	LocalHosts bool
	Quiet      bool
	Client     *cfapi.Client
	Account    string
	Devices    []Device
}
type Hook func(context.Context, Snapshot) error

type Registry struct {
	mu    sync.RWMutex
	hooks map[string]Hook
}

var Default Registry

// Register makes a hook available to both up and daemon. Names must be unique.
func (r *Registry) Register(name string, hook Hook) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if name == "" || hook == nil || r.hooks[name] != nil {
		panic("invalid or duplicate device sync hook: " + name)
	}
	if r.hooks == nil {
		r.hooks = make(map[string]Hook)
	}
	r.hooks[name] = hook
}

func (r *Registry) Run(ctx context.Context, s Snapshot) error {
	r.mu.RLock()
	hooks := make(map[string]Hook, len(r.hooks))
	var names []string
	for name, hook := range r.hooks {
		hooks[name] = hook
		names = append(names, name)
	}
	r.mu.RUnlock()
	sort.Strings(names)
	var errs []error
	for _, name := range names {
		if err := hooks[name](ctx, s); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func Fingerprint(s Snapshot) [32]byte {
	devices := append([]Device(nil), s.Devices...)
	sort.Slice(devices, func(i, j int) bool { return devices[i].ID < devices[j].ID })
	b, _ := json.Marshal(struct {
		Account string
		Devices []Device
	}{s.Account, devices})
	return sha256.Sum256(b)
}
