package service

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSSHManagerStopWaitsAndRestarts(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, stopping, release := make(chan struct{}, 2), make(chan struct{}, 2), make(chan struct{})
	var running atomic.Bool
	manager := NewSSHManager(parent, func(ctx context.Context) error {
		started <- struct{}{}
		<-ctx.Done()
		stopping <- struct{}{}
		<-release
		return ctx.Err()
	}, running.Store, log.New(io.Discard, "", 0))
	defer manager.Close()
	if err := manager.Set(parent, true); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := manager.Set(parent, true); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- manager.Set(parent, false) }()
	<-stopping
	select {
	case err := <-stopped:
		t.Fatalf("acknowledged before listeners closed: %v", err)
	default:
	}
	close(release)
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if running.Load() {
		t.Fatal("SSH still running")
	}
	if err := manager.Set(parent, true); err != nil {
		t.Fatal(err)
	}
	<-started
	cancel()
	manager.Close()
	if running.Load() {
		t.Fatal("parent cancellation left worker running")
	}
	if err := manager.Set(context.Background(), true); err == nil {
		t.Fatal("started after daemon shutdown")
	}
}

func TestSSHControlValidation(t *testing.T) {
	for _, tc := range []struct {
		body   string
		want   int
		called bool
	}{
		{`{"enabled":false}`, 204, true}, {`{"enabled":true}`, 204, true},
		{`{"enabled":false} {"enabled":true}`, 400, false},
		{`{}`, 400, false}, {`{"enabled":null}`, 400, false}, {`{"enabled":"yes"}`, 400, false}, {`{"enabled":true,"extra":1}`, 400, false},
	} {
		t.Run(tc.body, func(t *testing.T) {
			called := false
			ctrl := &Control{SetSSH: func(_ context.Context, enabled bool) error {
				called = true
				var request struct{ Enabled bool }
				_ = json.Unmarshal([]byte(tc.body), &request)
				if enabled != request.Enabled {
					t.Fatal(enabled)
				}
				return nil
			}}
			response := httptest.NewRecorder()
			ctrl.configureSSH(response, httptest.NewRequest("PUT", "/ssh", strings.NewReader(tc.body)))
			if response.Code != tc.want || called != tc.called {
				t.Fatal(response.Code, called)
			}
		})
	}
}

func TestSSHControlSocketStopsForegroundWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	running := make(chan struct{}, 1)
	stopped := make(chan struct{}, 1)
	manager := NewSSHManager(ctx, func(ctx context.Context) error {
		running <- struct{}{}
		<-ctx.Done()
		stopped <- struct{}{}
		return nil
	}, func(bool) {}, log.New(io.Discard, "", 0))
	defer manager.Close()
	ctrl := &Control{SetSSH: manager.Set}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() { done <- ctrl.Run(ctx, dir, ready) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("socket not ready")
	}
	for _, enabled := range []bool{true, false, true, false} {
		if err := Request(ctx, dir, "PUT", "/ssh", map[string]bool{"enabled": enabled}, nil); err != nil {
			t.Fatal(err)
		}
		if enabled {
			<-running
		} else {
			select {
			case <-stopped:
			default:
				t.Fatal("stop returned before worker stopped")
			}
		}
	}
}
