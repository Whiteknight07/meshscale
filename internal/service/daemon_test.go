package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/backend"
	"github.com/Whiteknight07/meshscale/internal/devicesync"
)

func TestPollRetriesHooksAndIgnoresUnchanged(t *testing.T) {
	var registry devicesync.Registry
	calls := 0
	fail := true
	registry.Register("dns", func(context.Context, devicesync.Snapshot) error {
		calls++
		if fail {
			return errors.New("503")
		}
		return nil
	})
	devices := []devicesync.Device{{ID: "a", Name: "laptop", IPv4: "100.96.0.2"}}
	poll := Poller{Registry: &registry, Load: func(context.Context) (devicesync.Snapshot, error) { return devicesync.Snapshot{Devices: devices}, nil }}
	if _, changed, err := poll.Poll(context.Background()); !changed || err == nil {
		t.Fatal(changed, err)
	}
	fail = false
	if _, changed, err := poll.Poll(context.Background()); !changed || err != nil {
		t.Fatal(changed, err)
	}
	if _, changed, err := poll.Poll(context.Background()); changed || err != nil {
		t.Fatal(changed, err)
	}
	devices[0].Name = "phone"
	if _, changed, err := poll.Poll(context.Background()); !changed || err != nil {
		t.Fatal(changed, err)
	}
	if calls != 3 {
		t.Fatal(calls)
	}
	if got := Backoff(time.Minute, 10); got != 15*time.Minute {
		t.Fatal(got)
	}
}

type fakeBackend struct {
	mu        sync.Mutex
	enrolled  bool
	connects  int
	connected bool
}

func (f *fakeBackend) Status(context.Context) (backend.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return backend.Status{State: "disconnected", Connected: f.connected}, nil
}
func (f *fakeBackend) Registration(context.Context) (backend.Registration, error) {
	if f.enrolled {
		return backend.Registration{ID: "registered"}, nil
	}
	return backend.Registration{}, nil
}
func (f *fakeBackend) Connect(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connects++
	f.connected = true
	return nil
}
func (f *fakeBackend) Disconnect(context.Context) error { return nil }
func TestReconnectRequiresEnrollment(t *testing.T) {
	for _, enrolled := range []bool{false, true} {
		f := &fakeBackend{enrolled: enrolled}
		ctrl := &Control{}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			KeepConnected(ctx, Connection{Backend: f, Expected: backend.Registration{ID: "registered"}, Control: ctrl, Interval: time.Millisecond, Logger: log.New(io.Discard, "", 0)})
			close(done)
		}()
		deadline := time.After(time.Second)
		for ctrl.Status().Connection.State == "" {
			select {
			case <-deadline:
				t.Fatal("no sample")
			case <-time.After(time.Millisecond):
			}
		}
		cancel()
		<-done
		f.mu.Lock()
		calls := f.connects
		f.mu.Unlock()
		if enrolled && calls != 1 || !enrolled && calls != 0 {
			t.Fatalf("enrolled=%v calls=%d", enrolled, calls)
		}
	}
}

type reconcilingBackend struct {
	fakeBackend
	samples    chan struct{}
	reconciles int
	failFirst  bool
}

func (f *reconcilingBackend) ReconcileNetwork(context.Context) error {
	f.reconciles++
	select {
	case f.samples <- struct{}{}:
	default:
	}
	if f.failFirst && f.reconciles == 1 {
		return errors.New("temporary firewall error")
	}
	return nil
}
func TestConnectedNetworkReconciliationRetries(t *testing.T) {
	for _, failFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(failFirst), func(t *testing.T) {
			f := &reconcilingBackend{fakeBackend: fakeBackend{enrolled: true, connected: true}, samples: make(chan struct{}, 2), failFirst: failFirst}
			ctrl := &Control{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				KeepConnected(ctx, Connection{Backend: f, Expected: backend.Registration{ID: "registered"}, Control: ctrl, Interval: time.Millisecond, Logger: log.New(io.Discard, "", 0)})
				close(done)
			}()
			for range 2 {
				select {
				case <-f.samples:
				case <-time.After(time.Second):
					t.Fatal("network reconciliation did not repeat")
				}
			}
			cancel()
			<-done
			if f.reconciles < 2 || ctrl.Status().Connection.Reason != "" {
				t.Fatalf("reconciles=%d status=%+v", f.reconciles, ctrl.Status())
			}
		})
	}
}

type flakyBackend struct {
	fakeBackend
	failures int
}

func (f *flakyBackend) Connect(ctx context.Context) error {
	f.mu.Lock()
	if f.failures > 0 {
		f.failures--
		f.mu.Unlock()
		return errors.New("daemon busy")
	}
	f.mu.Unlock()
	return f.fakeBackend.Connect(ctx)
}

func TestReconnectRetriesAfterFailure(t *testing.T) {
	f := &flakyBackend{fakeBackend: fakeBackend{enrolled: true}, failures: 2}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go KeepConnected(ctx, Connection{Backend: f, Expected: backend.Registration{ID: "registered"}, Control: &Control{}, Interval: time.Millisecond, Logger: log.New(io.Discard, "", 0)})
	deadline := time.After(time.Second)
	for {
		f.mu.Lock()
		connected := f.connected
		f.mu.Unlock()
		if connected {
			return
		}
		select {
		case <-deadline:
			t.Fatal("reconnect was not retried after a failure")
		case <-time.After(time.Millisecond):
		}
	}
}

type watchingBackend struct {
	reconcilingBackend
	updates chan backend.Status
}

func (w *watchingBackend) WatchStatus(ctx context.Context, out chan<- backend.Status) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case status := <-w.updates:
			out <- status
		}
	}
}

func TestStreamUpdatesAndNetworkEvents(t *testing.T) {
	w := &watchingBackend{
		reconcilingBackend: reconcilingBackend{fakeBackend: fakeBackend{enrolled: true}, samples: make(chan struct{}, 1)},
		updates:            make(chan backend.Status),
	}
	w.connected = true
	ctrl := &Control{}
	events := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// An hour-long interval leaves only the stream and events to drive work.
	go KeepConnected(ctx, Connection{Backend: w, Expected: backend.Registration{ID: "registered"}, Control: ctrl, Interval: time.Hour, Logger: log.New(io.Discard, "", 0), NetworkEvents: events})
	wait := func(what string) {
		select {
		case <-w.samples:
		case <-time.After(time.Second):
			t.Fatalf("no reconciliation after %s", what)
		}
	}
	wait("connecting")
	w.updates <- backend.Status{State: "paused"}
	w.updates <- backend.Status{State: "connected", Connected: true}
	wait("a streamed reconnect")
	events <- struct{}{}
	wait("a network event")
	if got := ctrl.Status().Connection.State; got != "connected" {
		t.Fatalf("state = %q, want streamed state", got)
	}
}

type endingWatcher struct {
	fakeBackend
	mu      sync.Mutex
	watches int
}

func (w *endingWatcher) WatchStatus(context.Context, chan<- backend.Status) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.watches++
	return errors.New("warp-svc restarted")
}

func TestStatusStreamRestartsAfterEnding(t *testing.T) {
	w := &endingWatcher{fakeBackend: fakeBackend{enrolled: true, connected: true}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go KeepConnected(ctx, Connection{Backend: w, Expected: backend.Registration{ID: "registered"}, Control: &Control{}, Interval: time.Hour, Logger: log.New(io.Discard, "", 0)})
	deadline := time.After(3 * time.Second)
	for {
		w.mu.Lock()
		watches := w.watches
		w.mu.Unlock()
		if watches >= 2 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("stream restarted %d times, want a restart", watches-1)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestPausedConnectionIsNotReconnected(t *testing.T) {
	f := &fakeBackend{enrolled: true}
	ctrl := &Control{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		KeepConnected(ctx, Connection{Backend: f, Expected: backend.Registration{ID: "registered"}, Control: ctrl, Interval: time.Millisecond, Logger: log.New(io.Discard, "", 0), Paused: func() bool { return true }})
	}()
	deadline := time.After(time.Second)
	for !strings.Contains(ctrl.Status().Connection.Reason, "paused") {
		select {
		case <-deadline:
			t.Fatalf("status = %+v", ctrl.Status().Connection)
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done
	if f.connects != 0 {
		t.Fatalf("reconnected a paused connection %d times", f.connects)
	}
}
