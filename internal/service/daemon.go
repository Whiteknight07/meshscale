package service

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Whiteknight07/meshscale/internal/backend"
	"github.com/Whiteknight07/meshscale/internal/devicesync"
)

// Poller records only successfully reconciled snapshots, so failed hooks retry.
type Poller struct {
	Registry    *devicesync.Registry
	Load        func(context.Context) (devicesync.Snapshot, error)
	initialized bool
	fingerprint [32]byte
}

func (p *Poller) Poll(ctx context.Context) (int, bool, error) {
	s, err := p.Load(ctx)
	if err != nil {
		return 0, false, err
	}
	fingerprint := devicesync.Fingerprint(s)
	if p.initialized && fingerprint == p.fingerprint {
		return len(s.Devices), false, nil
	}
	if err := p.Registry.Run(ctx, s); err != nil {
		return len(s.Devices), true, err
	}
	p.fingerprint, p.initialized = fingerprint, true
	return len(s.Devices), true, nil
}
func Backoff(interval time.Duration, failures int) time.Duration {
	for i := 0; i < failures && interval < 15*time.Minute; i++ {
		interval *= 2
	}
	return min(interval, 15*time.Minute)
}

func PollDevices(ctx context.Context, p *Poller, ctrl *Control, interval time.Duration, logger *log.Logger) {
	failures := 0
	for ctx.Err() == nil {
		pollCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		count, changed, err := p.Poll(pollCtx)
		cancel()
		ctrl.Update(func(s *Status) {
			if err != nil {
				s.SyncError = err.Error()
			} else {
				// LastSync means the last successful poll. Unchanged inventory is
				// still a fresh sync; doctor warns when this timestamp ages.
				s.Devices = count
				s.SyncError = ""
				s.LastSync = time.Now().UTC()
			}
		})
		if err != nil {
			failures++
			logger.Printf("device sync failed: %v", err)
		} else {
			failures = 0
			if changed {
				logger.Printf("devices changed: reconciled %d participant(s)", count)
			}
		}
		timer := time.NewTimer(Backoff(interval, failures))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Connection describes the backend connection the daemon keeps up.
type Connection struct {
	Backend  backend.Backend
	Expected backend.Registration // Connect only while this registration is live
	Control  *Control
	Logger   *log.Logger
	// Interval is the safety-net poll and reconcile period (default 1 minute).
	Interval time.Duration
	// NetworkEvents triggers network reconciliation; nil disables it.
	NetworkEvents <-chan struct{}
	// Paused reports a deliberate disconnect (meshscale down); nil never pauses.
	Paused func() bool
}

// KeepConnected never calls Connect on an unregistered client (consumer WARP
// could take over the default route) or while the user has paused the
// connection. The daemon never enrolls implicitly.
//
// A backend.StatusWatcher pushes state changes; status is still polled every
// interval as a safety net, and every statusPollInterval while disconnected or
// without a stream. Network reconciliation runs when the backend connects, on
// each network event, and every interval.
func KeepConnected(ctx context.Context, c Connection) {
	interval := c.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	networkEvents := c.NetworkEvents
	k := &connectionKeeper{backend: c.Backend, expected: c.Expected, ctrl: c.Control, logger: c.Logger, paused: c.Paused, spacing: min(interval, maxReconnectSpacing)}
	updates, streamDone := k.watch(ctx)
	k.poll(ctx)

	fastPoll := time.NewTicker(min(interval, statusPollInterval))
	defer fastPoll.Stop()
	slowPoll := time.NewTicker(interval)
	defer slowPoll.Stop()
	var rewatch <-chan time.Time
	streamDelay := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case next := <-updates:
			streamDelay = time.Second
			k.observe(ctx, next, nil)
		case err := <-streamDone:
			// warp-svc restarts end the stream; poll meanwhile and restart it.
			updates, streamDone = nil, nil
			if err != nil && ctx.Err() == nil {
				k.logger.Printf("backend status stream ended: %v; restarting in %s", err, streamDelay)
			}
			k.poll(ctx)
			rewatch = time.After(streamDelay)
			streamDelay = min(2*streamDelay, 5*time.Minute)
		case <-rewatch:
			rewatch = nil
			updates, streamDone = k.watch(ctx)
		case <-fastPoll.C:
			if updates == nil || !k.status.Connected {
				k.poll(ctx)
			}
		case <-slowPoll.C:
			if updates != nil && k.status.Connected {
				k.poll(ctx)
			}
			k.reconcile(ctx)
		case _, ok := <-networkEvents:
			if !ok {
				networkEvents = nil // the monitor died; slowPoll still reconciles
				continue
			}
			k.reconcile(ctx)
		}
	}
}

const (
	statusPollInterval  = 30 * time.Second
	backendStepTimeout  = 15 * time.Second
	maxReconnectSpacing = 5 * time.Second // a burst of streamed states connects once
)

// connectionKeeper is owned by the KeepConnected goroutine.
type connectionKeeper struct {
	backend  backend.Backend
	expected backend.Registration
	ctrl     *Control
	logger   *log.Logger
	paused   func() bool
	spacing  time.Duration // minimum time between Connect calls

	status      backend.Status
	lastConnect time.Time
	networkErr  string
	logged      string
}

// watch starts the backend's status stream, if it has one. Both channels are
// nil otherwise, which disables their select cases.
func (k *connectionKeeper) watch(ctx context.Context) (<-chan backend.Status, <-chan error) {
	watcher, ok := k.backend.(backend.StatusWatcher)
	if !ok {
		return nil, nil
	}
	updates := make(chan backend.Status, 8)
	done := make(chan error, 1)
	go func() { done <- watcher.WatchStatus(ctx, updates) }()
	return updates, done
}

func (k *connectionKeeper) poll(ctx context.Context) {
	stepCtx, cancel := context.WithTimeout(ctx, backendStepTimeout)
	next, err := k.backend.Status(stepCtx)
	cancel()
	k.observe(ctx, next, err)
}

func (k *connectionKeeper) observe(ctx context.Context, next backend.Status, err error) {
	if err != nil {
		next = backend.Status{State: "unavailable", Reason: err.Error()}
	}
	wasConnected := k.status.Connected
	k.status = next
	if err == nil && !next.Connected && next.State != "connecting" {
		k.reconnect(ctx)
	}
	if next.Connected && !wasConnected {
		k.reconcile(ctx)
	}
	k.publish()
}

func (k *connectionKeeper) reconnect(ctx context.Context) {
	if k.paused != nil && k.paused() {
		k.status.Reason = "paused by meshscale down; run meshscale up to reconnect"
		return
	}
	if time.Since(k.lastConnect) < k.spacing {
		return
	}
	k.lastConnect = time.Now()
	stepCtx, cancel := context.WithTimeout(ctx, backendStepTimeout)
	defer cancel()
	registration, err := k.backend.Registration(stepCtx)
	if err != nil || registration == (backend.Registration{}) || registration != k.expected {
		k.status.Reason = "registration missing or changed; run meshscale up and restart the daemon"
		return
	}
	if err := k.backend.Connect(stepCtx); err != nil {
		k.status.Reason = fmt.Sprintf("reconnect failed: %v", err)
		return
	}
	k.logger.Printf("reconnecting selected backend")
}

func (k *connectionKeeper) reconcile(ctx context.Context) {
	network, ok := k.backend.(backend.NetworkReconciler)
	if !ok || !k.status.Connected {
		return
	}
	stepCtx, cancel := context.WithTimeout(ctx, backendStepTimeout)
	defer cancel()
	k.networkErr = ""
	if err := network.ReconcileNetwork(stepCtx); err != nil {
		k.networkErr = fmt.Sprintf("network reconciliation failed: %v", err)
	}
	k.publish()
}

func (k *connectionKeeper) publish() {
	status := k.status
	if status.Connected && k.networkErr != "" {
		status.Reason = k.networkErr
	}
	k.ctrl.Update(func(s *Status) { s.Connection = status })
	if line := status.State + " " + status.Reason; line != k.logged {
		k.logger.Printf("backend %s", line)
		k.logged = line
	}
}
