package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/Whiteknight07/meshscale/internal/backend"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/devicesync"
	"github.com/Whiteknight07/meshscale/internal/exitnode"
	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
	"github.com/Whiteknight07/meshscale/internal/native"
	"github.com/Whiteknight07/meshscale/internal/reachability"
	"github.com/Whiteknight07/meshscale/internal/secure"
	"github.com/Whiteknight07/meshscale/internal/service"
	"github.com/Whiteknight07/meshscale/internal/warpcli"
	"github.com/Whiteknight07/meshscale/internal/wgtransport"
)

func init() {
	register(&command{name: "daemon", short: "keep Mesh connected and sync devices (foreground)", run: runDaemon})
}
func runDaemon(parent context.Context, args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	publicationsOnly := fs.Bool("publications-only", false, "supervise Funnel and certificate renewal without touching Mesh connectivity")
	ssh := fs.Bool("ssh", false, "run the keyless SSH server")
	sshPort := fs.Int("ssh-port", 22, "keyless SSH port")
	sshPolicy := fs.String("ssh-policy", "/etc/meshscale/ssh.json", "SSH access policy path")
	poll := fs.Duration("poll-interval", time.Minute, "device API poll interval with exponential error backoff")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: meshscale daemon [--ssh] [--poll-interval 1m]")
	}
	if *publicationsOnly {
		return runPublicationDaemon(parent)
	}
	options, err := config.LoadService()
	if err != nil {
		return err
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "ssh":
			options.SSH = *ssh
		case "ssh-port":
			options.SSHPort = *sshPort
		case "ssh-policy":
			options.SSHPolicy = *sshPolicy
		case "poll-interval":
			options.PollInterval = *poll
		}
	})
	if options.PollInterval < time.Second || options.PollInterval > 15*time.Minute || options.SSHPort < 1 || options.SSHPort > 65535 {
		return fmt.Errorf("invalid poll interval or SSH port")
	}
	local, settings, err := selectedBackend()
	if err != nil {
		return err
	}
	// Restore selected-exit recovery paths before any remote API or DNS lookup.
	// WARP may have restored its original resolver while the daemon was stopped.
	if err := prepareExitBootstrap(parent); err != nil {
		return err
	}
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	client := cfapi.New(tokens, version)
	if official, ok := local.(*warpcli.Client); ok {
		team, err := zeroTrustTeam(parent, client, account)
		if err != nil {
			return err
		}
		official.Organization = team
		official.RequireSafeProfile = true
		if err := official.CheckSafety(parent); err != nil {
			return err
		}
	}
	dir, err := config.ServiceDir()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	proxies := &service.Proxies{Listen: meshListen(local, settings, client, account)}
	if err := proxies.Load(options.Forwards); err != nil {
		return err
	}
	saved := append([]service.Forward(nil), options.Forwards...)
	proxies.Save = func(forwards []service.Forward) error { options.Forwards = forwards; return options.Save() }
	ctrl := &service.Control{Proxies: proxies, Reachability: reachability.New(reachability.Network{Ports: []uint16{uint16(options.SSHPort), 22, 2222, 443, 80}})}
	ctrl.Update(func(s *service.Status) { s.Mode = "daemon"; s.Backend = settings.Backend })
	logger := log.New(os.Stderr, "meshscale daemon: ", log.LstdFlags|log.LUTC)
	networkEvents, watchErr := exitnode.WatchNetwork(ctx)
	if watchErr != nil {
		logger.Printf("network event monitor unavailable: %v", watchErr)
	}
	var sshPolicyWarning sync.Once
	sshManager := service.NewSSHManager(ctx, func(sshCtx context.Context) error {
		sshPolicyWarning.Do(func() { warnMissingSSHPolicy(logger, options.SSHPolicy) })
		return runManagedSSHD(sshCtx, []string{"--port", strconv.Itoa(options.SSHPort), "--policy", options.SSHPolicy})
	}, func(running bool) { ctrl.Update(func(s *service.Status) { s.SSH = running }) }, logger)
	ctrl.SetSSH = sshManager.Set
	ctrl.SSHPolicyStatus = func() string { return sshPolicyState(options.SSHPolicy) }
	errs := make(chan error, 4)
	var workers sync.WaitGroup
	ownsWarp := false
	ownsHosts := false
	defer func() {
		cancel()
		proxies.Close()
		sshManager.Close()
		workers.Wait()
		if ownsHosts {
			if err := cleanupHosts(context.Background()); err != nil {
				logger.Printf("remove hosts DNS: %v", err)
			}
		}
		if ownsWarp {
			stopCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			if err := local.Disconnect(stopCtx); err != nil {
				logger.Printf("disconnect: %v", err)
			}
		}
	}()
	var identity backend.Registration
	identityReady := make(chan struct{})
	ctrl.Inventory = service.NewInventoryCache(func(loadCtx context.Context) ([]meshDevice, error) {
		select {
		case <-identityReady:
		case <-loadCtx.Done():
			return nil, loadCtx.Err()
		}
		state, err := statusMeshState(false)
		if err != nil {
			return nil, err
		}
		return fetchStatusDevices(loadCtx, client, account, registeredLocal{localWARP: local, identity: identity}, settings, state, "")
	})
	ready := make(chan struct{})
	workers.Go(func() { errs <- ctrl.Run(ctx, dir, ready) })
	select {
	case <-ready:
	case err := <-errs:
		return err
	case <-ctx.Done():
		return nil
	}
	ownsHosts = true
	logger.Printf("local status socket: %s", service.Socket(dir))
	nativeReady := make(chan *native.Transport, 1)
	if settings.Backend == "native" {
		nativeDir, err := settings.NativeStateDir()
		if err != nil {
			return err
		}
		state, err := native.LoadState(nativeDir)
		if err != nil {
			return fmt.Errorf("enroll first with meshscale up: %w", err)
		}
		if state.Account != account || state.Pending || state.Registration.ID == "" {
			return fmt.Errorf("no complete native enrollment for this account; run meshscale up first")
		}
		identity, err = local.Registration(ctx)
		if err != nil {
			return err
		}
		// Own the lifetime of the existing enrollment; no account setup or new nodes.
		release, err := localstate.Lock(nativeDir)
		if err != nil {
			return err
		}
		workers.Go(func() {
			errs <- native.Run(ctx, nativeDir, state, native.NewAPI(), native.DaemonOptions{Userspace: settings.Userspace, SOCKS: settings.SOCKS, Output: os.Stdout, OnTransport: func(t *native.Transport) { nativeReady <- t }}, release)
		})
	} else {
		checkCtx, done := context.WithTimeout(ctx, 15*time.Second)
		info, err := local.Registration(checkCtx)
		done()
		if err != nil || info.ID == "" && info.RegistrationID == "" && info.DeviceID == "" {
			return fmt.Errorf("no verified WARP enrollment; run meshscale up first")
		}
		registrations, err := client.ListRegistrations(ctx, account)
		if err != nil {
			return err
		}
		verified := 0
		for _, r := range registrations {
			if r.DeletedAt == nil && r.RevokedAt == nil && (r.ID == info.ID || r.ID == info.RegistrationID || r.Device.ID == info.DeviceID) {
				ip, err := netip.ParseAddr(r.VirtualIPv4)
				if err == nil && meshaddr.IsDevice(ip) {
					verified++
				}
			}
		}
		if verified != 1 {
			return fmt.Errorf("WARP registration is not a unique active Mesh participant in the selected account; run meshscale up first")
		}
		ownsWarp = true
		identity = info
	}
	close(identityReady)
	workers.Go(func() { supervisePublication(ctx, client, account, logger) })
	workers.Go(func() {
		factory := secureBindFactory(osSecureBind)
		if settings.Backend == "native" {
			select {
			case t := <-nativeReady:
				if settings.Userspace {
					factory = func(ip netip.Addr) conn.Bind {
						return &secure.PacketBind{Listen: func(port uint16) (net.PacketConn, error) {
							udp, ok := t.Network.(wgtransport.PacketNetwork)
							if !ok {
								return nil, fmt.Errorf("native network does not expose UDP")
							}
							return udp.ListenPacket(netip.AddrPortFrom(ip, port))
						}}
					}
				}
			case <-ctx.Done():
				return
			}
		}
		errs <- startSecureWorker(ctx, ctrl, client, account, local, options.PollInterval, factory)
	})
	workers.Go(func() {
		service.KeepConnected(ctx, service.Connection{
			Backend: local, Expected: identity, Control: ctrl, Logger: logger,
			Interval: time.Minute, NetworkEvents: networkEvents, Paused: config.Paused,
		})
	})
	poller := &service.Poller{Registry: &devicesync.Default, Load: func(loadCtx context.Context) (devicesync.Snapshot, error) {
		inventory, err := ctrl.Inventory.Refresh(loadCtx)
		snapshot := devicesync.Snapshot{Client: client, Account: account, LocalHosts: true}
		if err != nil {
			return snapshot, err
		}
		for _, d := range inventory.Devices {
			snapshot.Devices = append(snapshot.Devices, devicesync.Device{ID: d.Kind + "/" + d.ID, Name: d.Name, IPv4: d.IPv4, IPv6: d.IPv6, Owner: d.User})
		}
		return snapshot, nil
	}}
	workers.Go(func() { service.PollDevices(ctx, poller, ctrl, options.PollInterval, logger) })
	// Listener setup retries while WARP applies its profile / native handshakes.
	workers.Go(func() {
		pending := saved
		for len(pending) > 0 && ctx.Err() == nil {
			var retry []service.Forward
			for _, forward := range pending {
				if err := proxies.Restore(ctx, forward); err != nil {
					logger.Printf("restore mesh port %d: %v", forward.MeshPort, err)
					retry = append(retry, forward)
				}
			}
			pending = retry
			if len(pending) > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(5 * time.Second):
				}
			}
		}
	})
	if options.SSH {
		// A unit from an older install may still pass --ssh after ssh-mode gave
		// port 22 to Cloudflare; don't fight it every five seconds.
		if mode, err := loadSSHMode(); err == nil && options.SSHPort == 22 && (mode.Mode == "cloudflare" || mode.Mode == "off") {
			logger.Printf("own SSH not started: port 22 is managed by ssh-mode %s", mode.Mode)
		} else if err := sshManager.Set(ctx, true); err != nil {
			return err
		}
	}

	select {
	case <-ctx.Done():
		logger.Print("shutting down")
		return nil
	case err := <-errs:
		if err == nil && ctx.Err() == nil {
			return fmt.Errorf("backend or local control stopped")
		}
		return err
	}
}

func prepareExitBootstrap(ctx context.Context) error {
	dir, err := secureDir()
	if err != nil {
		return err
	}
	release, err := localstate.WaitLock(filepath.Join(dir, "config-lock"), 5*time.Second)
	if err != nil {
		return err
	}
	defer release()
	settings, err := secure.LoadConfig(dir)
	if err != nil {
		return fmt.Errorf("load exit bootstrap: %w", err)
	}
	if settings.ExitID == "" {
		if _, err := os.Stat(filepath.Join(dir, "exit-routing.json")); os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}
	}
	if err := exitnode.New(dir).Prepare(ctx, settings); err != nil {
		return fmt.Errorf("restore selected-exit bootstrap: %w", err)
	}
	return nil
}

// registeredLocal reuses the enrollment verified at startup for inventory.
// KeepConnected still reads the live registration before reconnecting.
type registeredLocal struct {
	localWARP
	identity backend.Registration
}

func (l registeredLocal) Registration(context.Context) (warpcli.RegistrationInfo, error) {
	return l.identity, nil
}
