package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// SSHManager owns one cancellable SSH worker. Set(false) does not acknowledge
// completion until the previous worker has exited and released its listeners.
type SSHManager struct {
	mu      sync.Mutex
	parent  context.Context
	run     func(context.Context) error
	update  func(bool)
	logger  *log.Logger
	cancel  context.CancelFunc
	done    chan struct{}
	enabled bool
}

func NewSSHManager(parent context.Context, run func(context.Context) error, update func(bool), logger *log.Logger) *SSHManager {
	return &SSHManager{parent: parent, run: run, update: update, logger: logger}
}
func (m *SSHManager) Set(ctx context.Context, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if enabled && m.enabled && m.parent.Err() == nil {
		return nil
	}
	if m.cancel != nil {
		m.enabled = false
		m.cancel()
		select {
		case <-ctx.Done():
			return fmt.Errorf("stop own SSH: %w", ctx.Err())
		case <-m.done:
			m.cancel, m.done = nil, nil
		}
	}
	if !enabled {
		return nil
	}
	if err := m.parent.Err(); err != nil {
		return fmt.Errorf("start own SSH: %w", err)
	}
	worker, cancel := context.WithCancel(m.parent)
	done := make(chan struct{})
	m.cancel, m.done, m.enabled = cancel, done, true
	go func() { defer close(done); m.serve(worker) }()
	return nil
}
func (m *SSHManager) Close() { _ = m.Set(context.Background(), false) }
func (m *SSHManager) serve(ctx context.Context) {
	defer m.update(false)
	for ctx.Err() == nil {
		m.update(true)
		err := m.run(ctx)
		m.update(false)
		if ctx.Err() != nil {
			return
		}
		m.logger.Printf("SSH stopped: %v; retrying", err)
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (c *Control) configureSSH(w http.ResponseWriter, r *http.Request) {
	if c.SetSSH == nil {
		http.Error(w, "SSH control unavailable", http.StatusServiceUnavailable)
		return
	}
	var request struct {
		Enabled *bool `json:"enabled"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil || request.Enabled == nil {
		http.Error(w, "expected {\"enabled\":bool}", http.StatusBadRequest)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "expected one SSH configuration", http.StatusBadRequest)
		return
	}
	if err := c.SetSSH(r.Context(), *request.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
