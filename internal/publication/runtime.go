package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Whiteknight07/meshscale/internal/localstate"
)

func Socket(dir string) string { return filepath.Join(dir, "publication.sock") }

// Start attaches the private control server, child process and expiry scheduler
// to one daemon lifetime. An idle instance has no timer and makes no API calls.
func (m *Manager) Start(parent context.Context) (stop func(), err error) {
	release, err := localstate.Lock(m.Store.Dir)
	if err != nil {
		return nil, fmt.Errorf("publication state in use: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	success := false
	defer func() {
		if !success {
			cancel()
			release()
			if m.Process != nil {
				m.Process.Stop()
			}
		}
	}()
	m.parent = ctx
	if err := m.recoverPendingRecords(ctx); err != nil {
		return nil, err
	}
	// Interrupted DNS-01 challenges are reclaimed only by recorded ID and marker.
	for _, owned := range append([]OwnedRecord(nil), m.state.Records...) {
		if owned.Record.Type == "TXT" {
			cleanupCtx, done := context.WithTimeout(ctx, 30*time.Second)
			err := m.deleteRecord(cleanupCtx, owned.Record.ID)
			done()
			if err != nil {
				return nil, fmt.Errorf("recover ACME TXT: %w", err)
			}
		}
	}
	if f := m.state.Funnel; f != nil {
		if !f.Enabled {
			cleanupCtx, done := context.WithTimeout(ctx, time.Minute)
			err := m.off(cleanupCtx)
			done()
			if err != nil {
				return nil, fmt.Errorf("recover incomplete Funnel: %w", err)
			}
		} else {
			if err := ValidateOrigin(f.Origin); err != nil {
				return nil, err
			}
			restoreCtx, done := context.WithTimeout(ctx, time.Minute)
			if err := m.restoreFunnel(restoreCtx, f); err != nil {
				done()
				return nil, err
			}
			token, err := m.Tunnels.PublicTunnelToken(restoreCtx, m.state.Account, f.TunnelID)
			done()
			if err != nil {
				return nil, fmt.Errorf("restore Funnel token: %w", err)
			}
			if err := m.Process.Start(ctx, token); err != nil {
				return nil, err
			}
		}
	}
	path := Socket(m.Store.Dir)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale publication socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect publication socket: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen publication socket: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		os.Remove(path)
		return nil, fmt.Errorf("secure publication socket: %w", err)
	}
	var active sync.WaitGroup
	var handlersMu sync.Mutex
	accepting := true
	handler := m.handler()
	trackedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlersMu.Lock()
		if !accepting {
			handlersMu.Unlock()
			http.Error(w, "publication supervisor is stopping", http.StatusServiceUnavailable)
			return
		}
		active.Add(1)
		handlersMu.Unlock()
		defer active.Done()
		handler.ServeHTTP(w, r)
	})
	server := &http.Server{Handler: trackedHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 11 * time.Minute, IdleTimeout: 30 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	var workers sync.WaitGroup
	workers.Go(func() { _ = server.Serve(listener) })
	workers.Go(func() {
		for ctx.Err() == nil {
			next := m.renew(ctx, time.Now())
			var timer *time.Timer
			var alarm <-chan time.Time
			if !next.IsZero() {
				timer = time.NewTimer(max(time.Until(next), time.Second))
				alarm = timer.C
			}
			select {
			case <-ctx.Done():
			case <-m.wake:
			case <-alarm:
			}
			if timer != nil {
				timer.Stop()
			}
		}
	})
	var once sync.Once
	stop = func() {
		once.Do(func() {

			handlersMu.Lock()
			accepting = false
			handlersMu.Unlock()
			cancel()
			server.Close()
			if m.Process != nil {
				m.Process.Stop()
			}
			workers.Wait()
			active.Wait()
			os.Remove(path)
			release()
		})
	}
	success = true
	return stop, nil
}
func decode(w http.ResponseWriter, r *http.Request, out any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decode publication request: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("expected one publication request")
	}
	return nil
}
func (m *Manager) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(m.Status()) })
	mux.HandleFunc("PUT /funnel", func(w http.ResponseWriter, r *http.Request) {
		var request FunnelRequest
		if err := decode(w, r, &request); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		result, err := m.Enable(r.Context(), request)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		_ = json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("DELETE /funnel", func(w http.ResponseWriter, r *http.Request) {
		if err := m.Off(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /cert", func(w http.ResponseWriter, r *http.Request) {
		var request CertRequest
		if err := decode(w, r, &request); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		cert, err := m.Cert(r.Context(), request)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		_ = json.NewEncoder(w).Encode(cert)
	})
	mux.HandleFunc("DELETE /cert", func(w http.ResponseWriter, r *http.Request) {
		var request CertRequest
		if err := decode(w, r, &request); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := m.RemoveCert(r.Context(), request.Name); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}
func Request(ctx context.Context, dir, method, path string, body, out any) error {
	if err := localstate.Dir(dir); err != nil {
		return err
	}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode publication request: %w", err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", Socket(dir))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 11 * time.Minute}
	request, err := http.NewRequestWithContext(ctx, method, "http://meshscale"+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build publication request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("contact publication daemon: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("publication daemon: %s", bytes.TrimSpace(data))
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(out); err != nil {
			return fmt.Errorf("decode publication response: %w", err)
		}
	}
	return nil
}
