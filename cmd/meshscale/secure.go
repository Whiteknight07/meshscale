package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Whiteknight07/meshscale/internal/backend"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/exitnode"
	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/secure"
	"github.com/Whiteknight07/meshscale/internal/service"
	"golang.zx2c4.com/wireguard/conn"
)

func init() {
	register(&command{name: "set", short: "set --secure=true|false [--userspace] (daemon applies changes)", run: runSet})
}
func secureDir() (string, error) {
	d, e := config.Dir()
	if e != nil {
		return "", e
	}
	return filepath.Join(d, "secure"), nil
}
func runSet(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	dnsHosts := fs.String("dns-hosts", "auto", "system hosts fallback: auto, on, off (root)")
	engine := fs.String("secure-engine", "auto", "secure engine: auto, kernel, go")
	enabled := fs.Bool("secure", false, "enable device-to-device WireGuard")
	userspace := fs.Bool("userspace", false, "use a private secure netstack")
	advertise := fs.Bool("advertise-exit-node", false, "offer Internet egress to your own secure devices (Linux root)")
	exit := fs.String("exit-node", "", "selected exit name or secure IP; empty restores direct Internet")
	lan := fs.Bool("exit-node-allow-lan-access", false, "allow this client's directly connected LAN while using an exit")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	if len(visited) == 0 || fs.NArg() != 0 {
		return fmt.Errorf("usage: meshscale set --secure=true|false | --advertise-exit-node=true|false | --exit-node=<name|secure IP|\"\"> [--exit-node-allow-lan-access]")
	}
	if visited["dns-hosts"] {
		if len(visited) != 1 {
			return fmt.Errorf("set --dns-hosts separately from secure/exit preferences")
		}
		return setDNSHosts(ctx, *dnsHosts)
	}
	dir, err := secureDir()
	if err != nil {
		return err
	}
	release, err := localstate.WaitLock(filepath.Join(dir, "config-lock"), 5*time.Second)
	if err != nil {
		return fmt.Errorf("update secure settings: %w", err)
	}
	defer release()
	saved, err := secure.LoadConfig(dir)
	if err != nil {
		return err
	}
	previous := saved
	if visited["secure"] {
		saved.Enabled = *enabled
	}
	if visited["secure-engine"] {
		saved.Engine = *engine
	}
	if saved.Engine != "" && saved.Engine != "auto" && saved.Engine != "kernel" && saved.Engine != "go" {
		return fmt.Errorf("invalid secure engine %q", saved.Engine)
	}
	if visited["userspace"] {
		saved.Userspace = *userspace
	} else if os.Geteuid() != 0 {
		saved.Userspace = true
	}
	if visited["advertise-exit-node"] {
		saved.AdvertiseExit = *advertise
		if *advertise {
			saved.Enabled = true
		}
	}
	if visited["exit-node-allow-lan-access"] {
		saved.AllowLAN = *lan
	}
	selecting := visited["exit-node"] && *exit != ""
	if visited["exit-node"] && *exit == "" {
		saved.ExitID, saved.ExitKey, saved.ExitName, saved.ExitMeshIP, saved.IPv4, saved.IPv6 = "", "", "", "", "", ""
	}
	if selecting {
		if visited["secure"] && !*enabled {
			return fmt.Errorf("selecting an exit requires secure mode; drop --secure=false")
		}
		saved.Enabled = true
	}
	// Reject conflicting settings before anything is published.
	if !saved.Enabled && saved.ExitID != "" {
		return fmt.Errorf("deselect with --exit-node= before disabling secure mode; the selected exit remains fail closed")
	}
	if saved.AdvertiseExit && (saved.ExitID != "" || selecting) {
		return fmt.Errorf("a device cannot advertise and select an exit simultaneously")
	}
	if saved.Enabled && runtime.GOOS != "linux" {
		return fmt.Errorf("secure/exit mode requires Linux; macOS helper support remains gated (docs/exit-nodes.md)")
	}
	if saved.AdvertiseExit || saved.ExitID != "" || selecting {
		if runtime.GOOS != "linux" || os.Geteuid() != 0 || saved.Userspace || saved.Engine == "go" {
			return fmt.Errorf("exit nodes require Linux root and kernel WireGuard (--userspace=false)")
		}
	}
	if selecting {
		account, tokens, err := resolveCredentials()
		if err != nil {
			return err
		}
		local, _, err := selectedBackend()
		if err != nil {
			return err
		}
		client := cfapi.New(tokens, version)
		key, err := secure.LoadKey(dir)
		if err != nil {
			return err
		}
		self, err := secure.PublishLocal(ctx, client, client, account, local, key, secure.Advertisement{Enabled: true, Exit: true})
		if err != nil {
			return err
		}
		peers, err := loadSecurePeers(ctx, client, account)
		if err != nil {
			return err
		}
		selected, err := secure.SelectExit(peers, self, *exit)
		if err != nil {
			return err
		}
		saved.ExitID, saved.ExitKey, saved.ExitName, saved.ExitMeshIP, saved.IPv4 = selected.RegistrationID, selected.PublicKey, selected.Name, selected.MeshIP.String(), self.IPv4.String()
		saved.IPv6 = self.IP.String()
	}
	if saved.AdvertiseExit && saved.Enabled {
		if err := exitnode.CheckForwarding(); err != nil {
			return err
		}
	}
	network := exitnode.New(dir)
	if saved.ExitID != "" {
		if err := network.Prepare(ctx, saved); err != nil {
			if previous.ExitID == "" {
				_ = network.Prepare(ctx, previous)
			}
			return fmt.Errorf("prepare selected exit: %w", err)
		}
	}
	if err := saved.Save(dir); err != nil {
		if saved.ExitID != "" && previous.ExitID == "" {
			_ = network.Prepare(ctx, previous)
		}
		return err
	}
	if saved.ExitID == "" && previous.ExitID != "" {
		if err := network.Prepare(ctx, saved); err != nil {
			return fmt.Errorf("exit deselected; remove owned protection: %w", err)
		}
	}
	// Withdrawal also works when the daemon is offline.
	if !saved.Enabled || visited["advertise-exit-node"] && !saved.AdvertiseExit {
		if _, err := os.Lstat(filepath.Join(dir, "wireguard.json")); err == nil {
			account, tokens, err := resolveCredentials()
			if err != nil {
				return err
			}
			local, _, err := selectedBackend()
			if err != nil {
				return err
			}
			client := cfapi.New(tokens, version)
			key, err := secure.LoadKey(dir)
			if err != nil {
				return err
			}
			if _, err := secure.PublishLocal(ctx, client, client, account, local, key, secure.Advertisement{Enabled: saved.Enabled, Exit: saved.ExitID != ""}); err != nil {
				return fmt.Errorf("updated locally; withdraw exit/key advertisement: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	fmt.Fprintf(os.Stdout, "Secure mode: %t; offers exit: %t; selected exit: %q (LAN access: %t). The daemon applies changes within five seconds.\n", saved.Enabled, saved.AdvertiseExit, saved.ExitName, saved.AllowLAN)
	return nil
}

func loadSecurePeers(ctx context.Context, client *cfapi.Client, account string) ([]secure.Peer, error) {
	peers, warnings, err := secure.LoadPeers(ctx, client, client, account)
	for _, warning := range warnings {
		fmt.Fprintln(os.Stderr, "Warning:", warning)
	}
	return peers, err
}

// reconcileSecureSettings applies a supervisor snapshot to local networking.
func reconcileSecureSettings(dir string, expected secure.Config, apply func() error) error {
	release, err := localstate.WaitLock(filepath.Join(dir, "config-lock"), 5*time.Second)
	if err != nil {
		return err
	}
	defer release()
	current, err := secure.LoadConfig(dir)
	if err != nil {
		return err
	}
	if current != expected {
		return fmt.Errorf("secure settings changed before network reconciliation")
	}
	return apply()
}

type secureBindFactory func(netip.Addr) conn.Bind

func osSecureBind(ip netip.Addr) conn.Bind { return secure.NewOSBind(ip) }

func runSecure(ctx context.Context, ctrl *service.Control, client *cfapi.Client, account string, local backend.Backend, dir string, factory secureBindFactory, poll time.Duration) error {
	network := exitnode.New(dir)
	var expected secure.Config
	network.Mutate = func(apply func() error) error {
		return reconcileSecureSettings(dir, expected, apply)
	}
	events, err := network.Watch(ctx)
	if err != nil {
		return fmt.Errorf("subscribe to Linux network changes: %w", err)
	}
	publish := func(ctx context.Context, key secure.Key, enabled, offers bool) (secure.Peer, error) {
		settings, err := secure.LoadConfig(dir)
		if err != nil {
			return secure.Peer{}, err
		}
		return secure.PublishLocal(ctx, client, client, account, local, key, secure.Advertisement{Enabled: enabled, Exit: settings.AdvertiseExit || settings.ExitID != "", Offers: offers})
	}
	supervisor := &secure.Supervisor{
		Events: events,
		Prepare: func(ctx context.Context, settings secure.Config) error {
			expected = settings
			return network.Prepare(ctx, settings)
		},
		Configure: func(ctx context.Context, engine secure.Engine, self secure.Peer, settings secure.Config, peers []secure.Peer) error {
			expected = settings
			return network.Configure(ctx, engine, self, settings, peers)
		},
		Advertise: func(ctx context.Context, key secure.Key, offers bool) (secure.Peer, error) {
			return publish(ctx, key, true, offers)
		},
		Dir: dir, PollInterval: poll,
		Publish: func(ctx context.Context, key secure.Key, enabled bool) (secure.Peer, error) {
			return publish(ctx, key, enabled, false)
		},
		LoadPeers: func(ctx context.Context) ([]secure.Peer, []string, error) {
			return secure.LoadPeers(ctx, client, client, account)
		},
		Start: func(ctx context.Context, key secure.Key, self secure.Peer, settings secure.Config) (secure.Engine, error) {
			mode := settings.Engine
			if settings.AdvertiseExit || settings.ExitID != "" {
				mode = "kernel"
				if settings.Userspace || settings.Engine == "go" {
					return nil, fmt.Errorf("exit nodes require kernel WireGuard and root")
				}
			}
			tr, err := secure.Start(ctx, key, self.IP, settings.Userspace, factory(self.MeshIP), mode)
			if err != nil {
				return nil, err
			}
			return tr, nil
		},
		SyncPolicy: func(ctx context.Context) error { return SyncRules(ctx, io.Discard, client, account, "", false) },
		Update: func(status secure.Status) {
			status.ExitExceptions = network.Exceptions()
			ctrl.Update(func(s *service.Status) { s.Secure = status })
		},
	}
	return supervisor.Run(ctx)
}

func startSecureWorker(ctx context.Context, ctrl *service.Control, client *cfapi.Client, account string, local backend.Backend, poll time.Duration, factory secureBindFactory) error {
	dir, err := secureDir()
	if err != nil {
		return err
	}
	release, err := localstate.Lock(dir)
	if err != nil {
		return fmt.Errorf("secure state is in use: %w", err)
	}
	defer release()
	path := filepath.Join(dir, "control.sock")
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("secure control path is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return runSecure(ctx, ctrl, client, account, local, dir, factory, poll)
}
