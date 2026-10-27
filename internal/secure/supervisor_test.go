package secure

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeEngine struct {
	reconciles, closed int
	failure            error
}

func (e *fakeEngine) Reconcile([]Peer) error { e.reconciles++; return e.failure }
func (*fakeEngine) Peers() []PeerStatus      { return nil }
func (e *fakeEngine) Close()                 { e.closed++ }

func TestSupervisorLifecycle(t *testing.T) {
	key, _ := GenerateKey()
	public, _ := key.Public()
	ip, _ := Address("account", public)
	self := Peer{RegistrationID: "self", PublicKey: public, IP: ip, MeshIP: netip.MustParseAddr("100.96.0.7")}
	var mu sync.Mutex
	config := Config{Enabled: true, Userspace: true}
	var loadErr error
	peers := []Peer{self}
	var engines []*fakeEngine
	var publications []bool
	now := time.Now()
	ticks := make(chan time.Time)
	statuses := make(chan Status)
	ctx, cancel := context.WithCancel(t.Context())
	s := &Supervisor{
		Tick: ticks, PollInterval: time.Minute, Now: func() time.Time { return now },
		LoadConfig: func(string) (Config, error) { mu.Lock(); defer mu.Unlock(); return config, nil },
		LoadKey:    func(string) (Key, error) { return key, nil },
		Publish: func(_ context.Context, _ Key, enabled bool) (Peer, error) {
			publications = append(publications, enabled)
			return self, nil
		},
		LoadPeers: func(context.Context) ([]Peer, []string, error) {
			mu.Lock()
			defer mu.Unlock()
			return peers, []string{"bad record skipped"}, loadErr
		},
		Start: func(context.Context, Key, Peer, Config) (Engine, error) {
			e := &fakeEngine{}
			engines = append(engines, e)
			return e, nil
		},
		Serve:  serveUntilDone,
		Update: func(s Status) { statuses <- s },
	}
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	receive := func() Status {
		t.Helper()
		select {
		case status := <-statuses:
			return status
		case <-time.After(time.Second):
			t.Fatal("supervisor stalled")
			return Status{}
		}
	}
	step := func(advance time.Duration) Status { now = now.Add(advance); ticks <- now; return receive() }
	if status := receive(); !status.Running || len(status.Warnings) != 1 {
		t.Fatalf("startup: %+v", status)
	}
	if status := step(5 * time.Second); !status.Running || engines[0].reconciles != 1 {
		t.Fatal("refreshed before poll interval")
	}
	mu.Lock()
	loadErr = errors.New("directory offline")
	mu.Unlock()
	degraded := func(status Status) bool {
		return slices.ContainsFunc(status.Warnings, func(w string) bool { return strings.Contains(w, "keeping last known peers") })
	}
	if status := step(time.Minute); !status.Running || engines[0].closed != 0 || !degraded(status) {
		t.Fatalf("directory outage should keep the engine with a warning: %+v", status)
	}
	mu.Lock()
	loadErr = nil
	mu.Unlock()
	if status := step(time.Minute); !status.Running || len(engines) != 1 || degraded(status) {
		t.Fatalf("recovery: %+v", status)
	}
	mu.Lock()
	config.Userspace = false
	mu.Unlock()
	if status := step(5 * time.Second); !status.Running || len(engines) != 2 || engines[0].closed != 1 {
		t.Fatalf("config change: %+v", status)
	}
	mu.Lock()
	peers = nil
	mu.Unlock()
	if status := step(time.Minute); status.Running || status.Error == "" {
		t.Fatalf("revocation: %+v", status)
	}
	mu.Lock()
	config.Enabled = false
	mu.Unlock()
	if status := step(5 * time.Second); status.Enabled || status.Error != "" {
		t.Fatalf("disable: %+v", status)
	}
	if publications[len(publications)-1] {
		t.Fatal("did not withdraw")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPathMTU(t *testing.T) {
	for _, tc := range []struct{ underlay, mtu, mss int }{{1500, 1440, 1380}, {1300, 1280, 1172}, {1280, 1280, 1156}} {
		mtu, mss := PathMTU(tc.underlay)
		if mtu != tc.mtu || mss != tc.mss {
			t.Fatalf("%d: %d/%d", tc.underlay, mtu, mss)
		}
	}
}

func TestNetworkEventReconcilesCachedPeers(t *testing.T) {
	key, _ := GenerateKey()
	public, _ := key.Public()
	ip, _ := Address("account", public)
	self := Peer{RegistrationID: "self", PublicKey: public, IP: ip, MeshIP: netip.MustParseAddr("100.96.0.7")}
	engine := &fakeEngine{}
	loads := 0
	s := &Supervisor{
		Dir: t.TempDir(), runContext: t.Context(), Now: time.Now, PollInterval: time.Minute,
		LoadConfig: func(string) (Config, error) { return Config{Enabled: true, Userspace: true}, nil },
		LoadKey:    func(string) (Key, error) { return key, nil },
		Publish:    func(context.Context, Key, bool) (Peer, error) { return self, nil },
		LoadPeers: func(context.Context) ([]Peer, []string, error) {
			loads++
			return []Peer{self}, nil, nil
		},
		Start:  func(context.Context, Key, Peer, Config) (Engine, error) { return engine, nil },
		Serve:  serveUntilDone,
		Update: func(Status) {},
	}
	if err := s.step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.reconcile(t.Context(), true, false); err != nil {
		t.Fatal(err)
	}
	if loads != 1 || engine.reconciles != 2 {
		t.Fatalf("network event loads=%d reconciles=%d", loads, engine.reconciles)
	}
	s.shutdown()
}

func TestSupervisorStartFailure(t *testing.T) {
	key, _ := GenerateKey()
	statuses := make(chan Status)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := &Supervisor{
		Tick:       make(chan time.Time),
		LoadConfig: func(string) (Config, error) { return Config{Enabled: true}, nil },
		LoadKey:    func(string) (Key, error) { return key, nil },
		Publish:    func(context.Context, Key, bool) (Peer, error) { return Peer{}, nil },
		LoadPeers:  func(context.Context) ([]Peer, []string, error) { return []Peer{{}}, nil, nil },
		Start: func(context.Context, Key, Peer, Config) (Engine, error) {
			var tr *Transport
			return tr, errors.New("start failed")
		},
		Update: func(status Status) { statuses <- status },
	}
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	select {
	case status := <-statuses:
		if status.Running || status.Error != "start failed" {
			t.Fatalf("unexpected status: %+v", status)
		}
	case <-time.After(time.Second):
		t.Fatal("start failure stalled")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestExitAdvertisementWaitsForForwarding(t *testing.T) {
	key, _ := GenerateKey()
	public, _ := key.Public()
	ip, _ := Address("account", public)
	self := Peer{RegistrationID: "self", PublicKey: public, IP: ip, MeshIP: netip.MustParseAddr("100.96.0.7")}
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("forwarding_failure_%t", fail), func(t *testing.T) {
			e := &fakeEngine{}
			var advertisements []bool
			configured := false
			s := &Supervisor{Dir: t.TempDir(), runContext: t.Context(), Now: time.Now, PollInterval: time.Minute,
				LoadConfig: func(string) (Config, error) { return Config{Enabled: true, AdvertiseExit: true}, nil }, LoadKey: func(string) (Key, error) { return key, nil },
				Publish: func(context.Context, Key, bool) (Peer, error) { return self, nil }, LoadPeers: func(context.Context) ([]Peer, []string, error) { return []Peer{self}, nil, nil },
				Start: func(context.Context, Key, Peer, Config) (Engine, error) { return e, nil }, Serve: serveUntilDone, Update: func(Status) {},
				Configure: func(context.Context, Engine, Peer, Config, []Peer) error {
					configured = true
					if fail {
						return errors.New("forwarding not ready")
					}
					return nil
				},
				Advertise: func(_ context.Context, _ Key, offers bool) (Peer, error) {
					if offers && !configured {
						t.Fatal("published before forwarding readiness")
					}
					if !offers && e.closed == 0 {
						t.Fatal("withdrawal preceded local revocation")
					}
					advertisements = append(advertisements, offers)
					return self, nil
				},
			}
			err := s.step(t.Context())
			if (err != nil) != fail {
				t.Fatal(err)
			}
			s.shutdown()
			if fail {
				if len(advertisements) != 0 {
					t.Fatal("published failed exit")
				}
			} else if len(advertisements) != 2 || !advertisements[0] || advertisements[1] {
				t.Fatalf("advertisement lifecycle %v", advertisements)
			}
		})
	}
}

func TestSupervisorPublishesBeforeReadingDirectory(t *testing.T) {
	key, _ := GenerateKey()
	public, _ := key.Public()
	ip, _ := Address("account", public)
	self := Peer{RegistrationID: "self", PublicKey: public, IP: ip, MeshIP: netip.MustParseAddr("100.96.0.7")}
	published := false
	s := &Supervisor{
		Dir: t.TempDir(), runContext: t.Context(), Now: time.Now, PollInterval: time.Minute,
		LoadConfig: func(string) (Config, error) { return Config{Enabled: true, Userspace: true}, nil },
		LoadKey:    func(string) (Key, error) { return key, nil },
		Publish:    func(_ context.Context, _ Key, enabled bool) (Peer, error) { published = enabled; return self, nil },
		// The directory lists this device only once its enabled record exists.
		LoadPeers: func(context.Context) ([]Peer, []string, error) {
			if !published {
				return nil, nil, nil
			}
			return []Peer{self}, nil, nil
		},
		Start:  func(context.Context, Key, Peer, Config) (Engine, error) { return &fakeEngine{}, nil },
		Serve:  serveUntilDone,
		Update: func(Status) {},
	}
	defer s.shutdown()
	if err := s.step(t.Context()); err != nil {
		t.Fatalf("first enable: %v", err)
	}
}

func TestSupervisorFailsClosedWithoutDirectoryAtStart(t *testing.T) {
	key, _ := GenerateKey()
	started := false
	s := &Supervisor{
		Dir: t.TempDir(), runContext: t.Context(), Now: time.Now, PollInterval: time.Minute,
		LoadConfig: func(string) (Config, error) { return Config{Enabled: true, Userspace: true}, nil },
		LoadKey:    func(string) (Key, error) { return key, nil },
		Publish:    func(context.Context, Key, bool) (Peer, error) { return Peer{}, nil },
		LoadPeers:  func(context.Context) ([]Peer, []string, error) { return nil, nil, errors.New("directory offline") },
		Start:      func(context.Context, Key, Peer, Config) (Engine, error) { started = true; return &fakeEngine{}, nil },
		Update:     func(Status) {},
	}
	if err := s.step(t.Context()); err == nil || started {
		t.Fatalf("started without a directory: err=%v started=%v", err, started)
	}
}

// step runs one full reconcile, as the safety tick does.
func (s *Supervisor) step(ctx context.Context) error { return s.reconcile(ctx, false, true) }

func serveUntilDone(ctx context.Context, _ Engine, _ Peer) (func() error, error) {
	return func() error { <-ctx.Done(); return nil }, nil
}

func TestRemoveStaleSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "control.sock")

	// A socket left behind by a killed daemon: bound, then closed without unlink.
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	if err := removeStaleSocket(path); err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	if l, err = net.Listen("unix", path); err != nil {
		t.Fatalf("listen after cleanup: %v", err)
	}
	defer l.Close()

	// A live socket must be kept.
	if err := removeStaleSocket(path); err == nil {
		t.Fatal("live socket was treated as stale")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("live socket removed: %v", err)
	}

	// A regular file is never deleted.
	file := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleSocket(file); err == nil {
		t.Fatal("regular file accepted")
	}
}
