// Package service implements the foreground daemon and private local controls.
package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Whiteknight07/meshscale/internal/backend"
	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/reachability"
	"github.com/Whiteknight07/meshscale/internal/secure"
)

type Status struct {
	Secure     secure.Status  `json:"secure"`
	Mode       string         `json:"mode"`
	Backend    string         `json:"backend"`
	Connection backend.Status `json:"connection"`
	LastSync   time.Time      `json:"last_sync,omitempty"`
	SyncError  string         `json:"sync_error,omitempty"`
	Devices    int            `json:"devices"`
	Forwards   []Forward      `json:"forwards"`
	SSHPolicy  string         `json:"ssh_policy,omitempty"`
	SSH        bool           `json:"ssh"`
}

type Control struct {
	mu              sync.Mutex
	status          Status
	Proxies         *Proxies
	Reachability    *reachability.Checker
	Inventory       *InventoryCache
	SetSSH          func(context.Context, bool) error
	SSHPolicyStatus func() string
}

func (c *Control) Update(fn func(*Status)) { c.mu.Lock(); defer c.mu.Unlock(); fn(&c.status) }
func (c *Control) Status() Status {
	c.mu.Lock()
	s := c.status
	c.mu.Unlock()
	if s.SSH && c.SSHPolicyStatus != nil {
		s.SSHPolicy = c.SSHPolicyStatus()
	}
	if c.Proxies != nil {
		s.Forwards = c.Proxies.List()
	}
	return s
}
func Socket(dir string) string { return filepath.Join(dir, "status.sock") }

// Run holds an exclusive lock and never replaces another daemon's live socket.
// Filesystem permissions restrict callers to this UID and root.
func (c *Control) Run(ctx context.Context, dir string, ready chan<- struct{}) error {
	release, err := localstate.Lock(dir)
	if err != nil {
		return fmt.Errorf("service state in use: %w", err)
	}
	defer release()
	path := Socket(dir)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to remove non-socket %s", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(path)
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c.Status())
	})
	mux.HandleFunc("POST /reachability", c.checkReachability)
	mux.HandleFunc("GET /devices", c.deviceInventory)
	mux.HandleFunc("POST /devices", c.deviceInventory)
	mux.HandleFunc("PUT /ssh", c.configureSSH)
	mux.HandleFunc("GET /serve", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(c.Proxies.List()) })
	mux.HandleFunc("PUT /serve", func(w http.ResponseWriter, r *http.Request) {
		var f Forward
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&f); err != nil {
			http.Error(w, "invalid forward", 400)
			return
		}
		if err := c.Proxies.Add(ctx, f); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /serve", func(w http.ResponseWriter, r *http.Request) {
		if err := c.Proxies.Remove(0); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	stop := context.AfterFunc(ctx, func() { server.Close() })
	defer stop()
	if ready != nil {
		close(ready)
	}
	err = server.Serve(listener)
	if ctx.Err() != nil || err == http.ErrServerClosed {
		return nil
	}
	return err
}

func Request(ctx context.Context, dir, method, path string, body, out any) error {
	if err := localstate.Dir(dir); err != nil {
		return err
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", Socket(dir))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 35 * time.Second}
	req, err := http.NewRequestWithContext(ctx, method, "http://meshscale"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			// A daemon still running an older binary lacks newer endpoints.
			return fmt.Errorf("daemon: %s: %w", bytes.TrimSpace(b), errors.ErrUnsupported)
		}
		return fmt.Errorf("daemon: %s", bytes.TrimSpace(b))
	}
	if out == nil {
		return nil
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	if err != nil {
		return err
	}
	if len(data) > responseLimit {
		return fmt.Errorf("daemon response exceeds %d MiB", responseLimit>>20)
	}
	return json.Unmarshal(data, out)
}

// responseLimit fits the inventory of an account with tens of thousands of
// devices, about 400 bytes each.
const responseLimit = 64 << 20
