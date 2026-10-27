package secure

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/native"
	"github.com/Whiteknight07/meshscale/internal/wgtransport"
)

// Engine is the lifecycle surface used by Supervisor and its test fakes.
type Engine interface {
	Reconcile([]Peer) error
	Peers() []PeerStatus
	Close()
}

// Optional Engine capabilities. Transport must keep implementing them, or the
// supervisor would silently skip health checks, listeners and status details.
type (
	healthChecker      interface{ Health() error }
	listenerNetwork    interface{ SecureNetwork() wgtransport.Network }
	engineDetails      interface{ Details() (string, int, int) }
	congestionReporter interface{ CongestionControl() string }
)

var (
	_ Engine             = (*Transport)(nil)
	_ healthChecker      = (*Transport)(nil)
	_ listenerNetwork    = (*Transport)(nil)
	_ engineDetails      = (*Transport)(nil)
	_ congestionReporter = (*Transport)(nil)
)

// Supervisor owns one secure engine. Dependencies are called only during a
// bounded refresh; packet processing and identity lookups use installed peers.
// Run must be called once, by one goroutine.
type Supervisor struct {
	Prepare      func(context.Context, Config) error
	Configure    func(context.Context, Engine, Peer, Config, []Peer) error
	Advertise    func(context.Context, Key, bool) (Peer, error)
	advertised   bool
	Dir          string
	PollInterval time.Duration
	Publish      func(context.Context, Key, bool) (Peer, error)
	LoadPeers    func(context.Context) ([]Peer, []string, error)
	Start        func(context.Context, Key, Peer, Config) (Engine, error)
	// Serve opens the local control socket and returns a function serving it
	// until ctx ends. It returns only once the socket accepts connections, so
	// Running is never reported before the socket exists.
	Serve      func(context.Context, Engine, Peer) (func() error, error)
	SyncPolicy func(context.Context) error
	Update     func(Status)
	LoadConfig func(string) (Config, error)
	LoadKey    func(string) (Key, error)
	Now        func() time.Time
	Tick       <-chan time.Time
	Events     <-chan struct{}

	runContext  context.Context
	engine      Engine
	stop        context.CancelFunc
	done        chan error
	previous    Config
	self        Peer
	peers       []Peer
	retryAt     time.Time
	lastErr     error
	nextRefresh time.Time
	warnings    []string
	degraded    map[string]string // control-plane failures by part
}

func (s *Supervisor) shutdown() {
	if s.stop != nil {
		s.stop()
		<-s.done
		s.stop, s.done = nil, nil
	}
	if s.engine != nil {
		s.engine.Close()
		s.engine = nil
	}
	if s.advertised && s.Advertise != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if key, err := s.LoadKey(s.Dir); err == nil {
			_, _ = s.Advertise(ctx, key, false)
		}
		cancel()
		s.advertised = false
	}
}

func (s *Supervisor) serve(ctx context.Context, engine Engine, self Peer) (func() error, error) {
	tr, ok := engine.(listenerNetwork)
	if !ok {
		return nil, fmt.Errorf("secure engine has no listener network")
	}
	path := filepath.Join(s.Dir, "control.sock")
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	closeSocket := func() {
		l.Close()
		os.Remove(path)
	}
	if err := os.Chmod(path, 0600); err != nil {
		closeSocket()
		return nil, err
	}
	return func() error {
		defer closeSocket()
		return native.ServeNetwork(ctx, l, tr.SecureNetwork(), []netip.Addr{self.IP}, func() bool { return true }, IsIP)
	}, nil
}

// removeStaleSocket deletes a socket file left by a daemon that died without
// cleaning up (crash, OOM, SIGKILL). Otherwise Listen fails with "address
// already in use" forever. A socket that still accepts connections is kept.
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode().Type() != os.ModeSocket {
		return fmt.Errorf("%s exists and is not a socket", path)
	}
	if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
		conn.Close()
		return fmt.Errorf("%s is in use by another meshscale process", path)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// fail closes the engine (secure mode fails closed) and backs off restarts,
// so a persistent error cannot churn the interface and firewall rules.
func (s *Supervisor) fail(err error) {
	s.shutdown()
	s.nextRefresh = time.Time{}
	if !s.Now().Before(s.retryAt) {
		s.retryAt = s.Now().Add(s.retryDelay())
	}
	s.lastErr = err
	status := Status{Enabled: s.previous.Enabled, Error: err.Error(), Warnings: s.warnings, ExitNode: s.previous.ExitName, ExitNodeID: s.previous.ExitID, AllowLAN: s.previous.AllowLAN, DNS: "existing resolver"}
	if s.previous.ExitID != "" {
		status.ExitState = "blocked: " + err.Error()
	}
	s.Update(status)
}

func (s *Supervisor) retryDelay() time.Duration {
	interval := s.PollInterval
	if interval <= 0 || interval > 15*time.Second {
		interval = 15 * time.Second
	}
	return interval
}

func (s *Supervisor) listsSelf() bool {
	for _, p := range s.peers {
		if p.RegistrationID == s.self.RegistrationID && p.PublicKey == s.self.PublicKey && p.MeshIP == s.self.MeshIP {
			return true
		}
	}
	return false
}

// degrade records (or, with a nil err, clears) a control-plane failure that
// the running engine survives.
func (s *Supervisor) degrade(part string, err error) {
	if err == nil {
		delete(s.degraded, part)
		return
	}
	if s.degraded == nil {
		s.degraded = make(map[string]string)
	}
	s.degraded[part] = err.Error()
}

func (s *Supervisor) statusWarnings() []string {
	warnings := slices.Clone(s.warnings)
	for _, part := range slices.Sorted(maps.Keys(s.degraded)) {
		warnings = append(warnings, s.degraded[part])
	}
	return warnings
}

// reconcile converges on the current settings and peers. full forces the
// Prepare inspection; networkChanged re-plans routes for the existing peers.
// Returned errors close the engine (Run fails closed). Transient control-plane
// failures while the engine runs are reported as warnings instead, keeping the
// last known peers up through a Cloudflare API blip; a revoked key is enforced
// on the next successful refresh, and lost authorization fails closed at once.
func (s *Supervisor) reconcile(ctx context.Context, networkChanged, full bool) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if s.done != nil {
		select {
		case err := <-s.done:
			s.stop()
			s.stop, s.done = nil, nil
			return fmt.Errorf("secure control stopped: %v", err)
		default:
		}
	}
	if h, ok := s.engine.(healthChecker); ok {
		if err := h.Health(); err != nil {
			return err
		}
	}
	settings, err := s.LoadConfig(s.Dir)
	if err != nil {
		return err
	}
	settingsChanged := settings != s.previous
	if settingsChanged {
		s.shutdown()
		s.previous = settings
		s.nextRefresh = time.Time{}
		s.retryAt = time.Time{}
		s.lastErr = nil
		s.degraded = nil
	}
	if s.engine == nil && s.Now().Before(s.retryAt) {
		return s.lastErr // still backing off from the last failure
	}
	if s.Prepare != nil && (full || networkChanged || settingsChanged) {
		if err := s.Prepare(ctx, settings); err != nil {
			return err
		}
	}
	if !settings.Enabled {
		if s.self.RegistrationID != "" {
			key, err := s.LoadKey(s.Dir)
			if err != nil {
				return err
			}
			if _, err := s.Publish(ctx, key, false); err != nil {
				return err
			}
			s.self = Peer{}
		}
		s.Update(Status{})
		return nil
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("secure mode needs a Linux daemon")
	}
	userspace := settings.Userspace || os.Geteuid() != 0

	starting := s.engine == nil
	var key Key
	if starting {
		// Publish first: the directory read below must contain our own record.
		if key, err = s.LoadKey(s.Dir); err != nil {
			return err
		}
		if s.self, err = s.Publish(ctx, key, true); err != nil {
			return err
		}
		s.nextRefresh = time.Time{}
	}
	peersChanged, refreshed := starting, false
	if !s.Now().Before(s.nextRefresh) {
		peers, warnings, err := s.LoadPeers(ctx)
		if err != nil {
			// Lost authorization may mean this device was revoked: fail closed.
			if starting || cfapi.IsAuthorizationError(err) {
				return err
			}
			s.degrade("directory", fmt.Errorf("refresh secure key directory (keeping last known peers): %w", err))
			s.nextRefresh = s.Now().Add(s.retryDelay())
		} else {
			s.degrade("directory", nil)
			s.warnings = warnings
			peersChanged = peersChanged || !reflect.DeepEqual(s.peers, peers)
			s.peers, refreshed = peers, true
			s.nextRefresh = s.Now().Add(s.PollInterval)
		}
	}
	if peersChanged && !s.listsSelf() {
		return fmt.Errorf("local secure key/registration changed or revoked")
	}
	if starting {
		engineSettings := settings
		engineSettings.Userspace = userspace
		engine, err := s.Start(s.runContext, key, s.self, engineSettings)
		if err != nil {
			return err
		}
		s.engine = engine
		runCtx, stop := context.WithCancel(s.runContext)
		s.stop, s.done = stop, make(chan error, 1)
		serve, err := s.Serve(runCtx, engine, s.self)
		if err != nil {
			s.done <- err // shutdown drains it
			return err
		}
		done := s.done
		go func() { done <- serve() }()
	}
	if peersChanged || networkChanged {
		if s.Configure != nil {
			err = s.Configure(ctx, s.engine, s.self, settings, s.peers)
		} else {
			err = s.engine.Reconcile(s.peers)
		}
		if err != nil {
			return err
		}
	}
	// Advertise only once forwarding is configured, and retry a failed
	// advertisement at the refresh cadence rather than every tick.
	if settings.AdvertiseExit && s.Advertise != nil && (peersChanged || networkChanged || !s.advertised && refreshed) {
		key, err := s.LoadKey(s.Dir)
		if err == nil {
			_, err = s.Advertise(ctx, key, true)
		}
		if err != nil {
			s.degrade("advertise", fmt.Errorf("publish ready exit: %w", err))
		} else {
			s.advertised = true
			s.degrade("advertise", nil)
		}
	}
	if refreshed && s.SyncPolicy != nil {
		if err := s.SyncPolicy(ctx); err != nil {
			s.degrade("policy", fmt.Errorf("secure carrier policy: %w", err))
		} else {
			s.degrade("policy", nil)
		}
	}
	status := Status{Enabled: true, Running: true, Userspace: userspace, IP: s.self.IP.String(), Peers: s.engine.Peers(), Warnings: s.statusWarnings()}
	if d, ok := s.engine.(engineDetails); ok {
		status.Mode, status.MTU, status.MSS = d.Details()
	}
	if d, ok := s.engine.(congestionReporter); ok {
		status.CongestionControl = d.CongestionControl()
	}
	status.ExitNode, status.ExitNodeID, status.AllowLAN = settings.ExitName, settings.ExitID, settings.AllowLAN
	status.OffersExit = s.advertised
	status.DNS = "existing resolver"
	if s.self.IPv4.IsValid() {
		status.IPv4 = s.self.IPv4.String()
	}
	if settings.ExitID != "" {
		status.ExitState = "blocked: selected exit unavailable"
		for _, p := range status.Peers {
			if p.RegistrationID == settings.ExitID && p.PublicKey == settings.ExitKey && p.OffersExit && p.HandshakeAge != nil && *p.HandshakeAge < 180 {
				status.ExitState = "connected (egress not probed)"
			}
		}
	}
	s.Update(status)
	return nil
}

func (s *Supervisor) Run(ctx context.Context) error {
	s.runContext = ctx
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.LoadConfig == nil {
		s.LoadConfig = LoadConfig
	}
	if s.LoadKey == nil {
		s.LoadKey = LoadKey
	}
	if s.Serve == nil {
		s.Serve = s.serve
	}
	if s.PollInterval <= 0 {
		s.PollInterval = time.Minute
	}
	// The light tick applies settings, refreshes status and, when due, the key
	// directory, without running any process. The safety tick also re-runs the
	// full Prepare inspection; network events re-plan routes.
	safety, light := s.Tick, (<-chan time.Time)(nil)
	if safety == nil {
		safetyTicker := time.NewTicker(time.Minute)
		defer safetyTicker.Stop()
		lightTicker := time.NewTicker(5 * time.Second)
		defer lightTicker.Stop()
		safety, light = safetyTicker.C, lightTicker.C
	}
	defer s.shutdown()
	reconcile := func(networkChanged, full bool) {
		if err := s.reconcile(ctx, networkChanged, full); err != nil {
			s.fail(err)
		}
	}
	events := s.Events
	reconcile(false, true)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-safety:
			reconcile(false, true)
		case <-light:
			reconcile(false, false)
		case _, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			reconcile(true, false)
		}
	}
}
