package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
	"github.com/Whiteknight07/meshscale/internal/native"
	"github.com/Whiteknight07/meshscale/internal/secure"
	"github.com/Whiteknight07/meshscale/internal/service"
	"github.com/Whiteknight07/meshscale/internal/sshserver"
)

func init() {
	register(&command{name: "sshd", short: "serve keyless SSH on Mesh IPs (Linux; root or native userspace)", run: runSSHD})
}

func runSSHD(ctx context.Context, args []string) error {
	return runSSHDWithPolicyWarning(ctx, args, true)
}

func runSSHDWithPolicyWarning(ctx context.Context, args []string, warnPolicy bool) error {
	options, err := config.LoadService()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("sshd", flag.ContinueOnError)
	port := fs.Int("port", 22, "SSH port on Mesh interfaces only")
	stateDir := fs.String("state-dir", "/var/lib/meshscale", "private directory for the persistent SSH host key")
	policy := fs.String("policy", options.SSHPolicy, "SSH access policy; missing file denies all logins")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: meshscale sshd [--port 22] [--state-dir /var/lib/meshscale] [--policy /etc/meshscale/ssh.json]")
	}
	// systemd stops the unit with SIGTERM; treat it like cancellation.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM)
	defer stop()
	mode, err := loadSSHMode()
	if err != nil {
		return fmt.Errorf("read SSH mode: %w", err)
	}
	if *port == 22 && (mode.Mode == "cloudflare" || mode.Mode == "off") {
		return fmt.Errorf("mesh port 22 is managed by ssh-mode %s; use meshscale ssh-mode own first", mode.Mode)
	}
	local, settings, err := selectedBackend()
	if err != nil {
		return err
	}
	securePath, err := secureDir()
	if err != nil {
		return err
	}
	secureSettings, err := secure.LoadConfig(securePath)
	if err != nil {
		return err
	}
	rootless := os.Geteuid() != 0 && (settings.Backend == "native" && settings.Userspace || secureSettings.Enabled)
	if runtime.GOOS != "linux" || os.Geteuid() != 0 && !rootless {
		return fmt.Errorf("sshd requires Linux and root, or native --userspace for the current local user")
	}
	if rootless {
		dir := securePath
		var err error
		if settings.Backend == "native" {
			dir, err = settings.NativeStateDir()
		}
		if err != nil {
			return err
		}
		explicitStateDir := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "state-dir" {
				explicitStateDir = true
			}
		})
		if !explicitStateDir {
			*stateDir = filepath.Join(dir, "ssh")
		}
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if _, err := sshserver.LoadPolicy(*policy); err != nil {
		return fmt.Errorf("read SSH policy: %w", err)
	}
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	client := cfapi.New(tokens, version)
	ips, err := localSSHIPs(ctx, client, account, local)
	if err != nil {
		return err
	}
	var signer ssh.Signer
	if rootless {
		signer, err = sshserver.UserHostKey(*stateDir)
	} else {
		signer, err = sshserver.HostKey(*stateDir)
	}
	if err != nil {
		return err
	}
	var nativeClient *native.Client
	if settings.Backend == "native" && settings.Userspace {
		nativeClient = local.(*native.Client)
	}
	listeners, err := sshListeners(ctx, nativeClient, ips, *port)
	if err != nil {
		return err
	}
	if secureSettings.Enabled {
		listener, err := secureSSHListener(ctx, securePath, *port)
		if err != nil {
			closeListeners(listeners)
			return fmt.Errorf("secure SSH listener: %w", err)
		}
		listeners = append(listeners, sshserver.SecureListener(listener))
	}
	logger := log.New(os.Stderr, "meshscale ", log.LstdFlags|log.LUTC)
	if warnPolicy {
		warnMissingSSHPolicy(logger, *policy)
	}

	for _, l := range listeners {
		logger.Printf("SSH listening on %s host_key=%s policy=%q", l.Addr(), ssh.FingerprintSHA256(signer.PublicKey()), *policy)
	}
	server := &sshserver.Server{Signer: signer, Auth: &sshserver.Authorizer{
		Identities: &sshserver.Registry{API: client, Account: account}, PolicyPath: *policy, Audit: logger,
	}}
	if secureSettings.Enabled {
		keys := &sshserver.KeyRegistry{Plain: server.Auth.Identities, Load: daemonSecurePeers}
		server.Auth.Identities = keys.PlainSource()
		server.Auth.SecureIdentities = keys
	}
	if rootless {
		uid := uint32(os.Geteuid())
		server.Auth.LocalUID = &uid
	}
	return server.Serve(ctx, listeners)
}

// sshListeners listens on each Mesh address, through the userspace netstack
// when client is set.
func sshListeners(ctx context.Context, client *native.Client, ips []netip.Addr, port int) ([]net.Listener, error) {
	if client == nil {
		return sshserver.Listen(ips, port)
	}
	var listeners []net.Listener
	for _, ip := range ips {
		l, err := client.ListenTCP(ctx, netip.AddrPortFrom(ip, uint16(port)))
		if err != nil {
			closeListeners(listeners)
			return nil, err
		}
		listeners = append(listeners, l)
	}
	return listeners, nil
}

// secureSSHListener leases a listener on this device's secure overlay address
// from the running secure engine.
func secureSSHListener(ctx context.Context, securePath string, port int) (net.Listener, error) {
	status, err := daemonStatus(ctx)
	if err != nil {
		return nil, err
	}
	if !status.Secure.Running {
		return nil, fmt.Errorf("secure engine is not running: %s", status.Secure.Error)
	}
	ip, err := netip.ParseAddr(status.Secure.IP)
	if err != nil {
		return nil, err
	}
	return (&native.Client{Dir: securePath}).ListenTCP(ctx, netip.AddrPortFrom(ip, uint16(port)))
}

// daemonSecurePeers reads the secure engine's installed peers from the daemon.
func daemonSecurePeers(ctx context.Context) ([]secure.Peer, error) {
	status, err := daemonStatus(ctx)
	if err != nil {
		return nil, err
	}
	if !status.Secure.Running {
		return nil, fmt.Errorf("secure peer snapshot unavailable: %s", status.Secure.Error)
	}
	peers := make([]secure.Peer, 0, len(status.Secure.Peers))
	for _, peer := range status.Secure.Peers {
		peers = append(peers, peer.Peer)
	}
	return peers, nil
}

func daemonStatus(ctx context.Context) (service.Status, error) {
	var status service.Status
	dir, err := config.ServiceDir()
	if err != nil {
		return status, err
	}
	err = service.Request(ctx, dir, "GET", "/status", nil, &status)
	return status, err
}

func closeListeners(listeners []net.Listener) {
	for _, l := range listeners {
		l.Close()
	}
}

func localSSHIPs(ctx context.Context, client *cfapi.Client, account string, local localWARP) ([]netip.Addr, error) {
	status, err := local.Status(ctx)
	if err != nil {
		return nil, err
	}
	if !status.Connected {
		return nil, fmt.Errorf("mesh backend must be connected before starting sshd")
	}
	registration, err := local.Registration(ctx)
	if err != nil {
		return nil, err
	}
	registrations, err := client.ListRegistrations(ctx, account)
	if err != nil {
		return nil, err
	}
	devices := mergeMeshDevices(registrations, nil, nil, time.Now())
	markThisMachine(devices, registration)
	var ips []netip.Addr
	matched := false
	for _, device := range devices {
		if !device.ThisMachine {
			continue
		}
		if matched {
			return nil, fmt.Errorf("multiple local Mesh registrations; cannot select safe SSH addresses")
		}
		matched = true
		for _, raw := range []string{device.IPv4, device.IPv6} {
			if raw == "" {
				continue
			}
			ip, err := netip.ParseAddr(raw)
			if err != nil || !meshaddr.IsDevice(ip) {
				return nil, fmt.Errorf("registration has an unsupported Mesh IP %q", raw)
			}
			ips = append(ips, ip.Unmap())
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no local Mesh IPs found in this account")
	}
	return ips, nil
}
