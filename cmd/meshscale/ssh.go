package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
	"github.com/Whiteknight07/meshscale/internal/native"
)

func init() {
	register(&command{name: "ssh", short: "SSH to [user@]device-name or Mesh IP; manage ssh policy", run: runSSH})
}

func runSSH(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "policy" {
		return runSSHPolicy(ctx, args[1:])
	}
	fs := flag.NewFlagSet("ssh", flag.ContinueOnError)
	port := fs.Int("port", 22, "remote SSH port")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() == 0 || *port < 1 || *port > 65535 {
		return fmt.Errorf("usage: meshscale ssh [--port 22] [user@]<name|ip> [command...]")
	}
	local, err := user.Current()
	if err != nil {
		return err
	}
	username, target := local.Username, fs.Arg(0)
	if before, after, ok := strings.Cut(target, "@"); ok {
		username, target = before, after
	}
	if username == "" || strings.HasPrefix(username, "-") || strings.ContainsAny(username, "@\x00\r\n") || target == "" {
		return fmt.Errorf("invalid SSH user or target")
	}
	if ip, handled, err := resolveSecureTarget(ctx, target); handled {
		if err != nil {
			return err
		}
		dir, err := secureDir()
		if err != nil {
			return err
		}
		return nativeSSH(ctx, &native.Client{Dir: dir}, ip, *port, username, fs.Args()[1:])
	}
	devices, cached, err := daemonDevices(ctx, false)
	if err != nil {
		return err
	}
	if !cached {
		account, tokens, err := resolveCredentials()
		if err != nil {
			return err
		}
		state, err := config.LoadMeshState()
		if err != nil {
			return err
		}
		client := cfapi.New(tokens, version)
		devices, err = loadMeshDevices(ctx, client, account, nil, time.Now(), state)
		if err != nil {
			return err
		}
		if err := assignSSHMode(ctx, client, account, devices); err != nil {
			return err
		}
	}
	ip, err := resolveSSHTarget(devices, target)
	if err != nil {
		return err
	}
	mode := "unknown"
	for _, device := range devices {
		if device.IPv4 == ip.String() || device.IPv6 == ip.String() {
			mode = device.SSHMode
		}
	}
	if mode == "off" {
		return fmt.Errorf("SSH is disabled on this server")
	}
	backend, settings, err := selectedBackend()
	if err != nil {
		return err
	}
	if mode == "cloudflare" && settings.Backend == "native" {
		return fmt.Errorf("cloudflare Infrastructure SSH requires an owner-enrolled official WARP client")
	}
	if settings.Backend == "native" && settings.Userspace {
		return nativeSSH(ctx, backend.(*native.Client), ip, *port, username, fs.Args()[1:])
	}
	binary, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("OpenSSH client is missing; install openssh-client: %w", err)
	}
	argv := []string{"ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes", "-p", fmt.Sprint(*port), "-l", username, "--", ip.String()}
	if mode == "cloudflare" {
		argv = cloudflareSSHArgs(ip.String(), *port, username, fs.Args()[1:])
	} else {
		argv = append(argv, fs.Args()[1:]...)
	}
	if runtime.GOOS == "windows" {
		child := exec.CommandContext(ctx, binary, argv[1:]...)
		child.Env = config.ChildEnvironment()
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
		err := child.Run()
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			os.Exit(exit.ExitCode())
		}
		return err
	}
	return syscall.Exec(binary, argv, config.ChildEnvironment())
}

func resolveSSHTarget(devices []meshDevice, target string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(target); err == nil {
		if !meshaddr.IsDevice(ip) {
			return netip.Addr{}, fmt.Errorf("target is outside the Mesh device ranges")
		}
		if _, err := findMeshIP(devices, ip); err != nil {
			return netip.Addr{}, err
		}
		return ip.Unmap(), nil
	}
	var result netip.Addr
	matched := false
	if strings.Contains(target, ".") {
		if err := assignDNSNames(devices); err != nil {
			return netip.Addr{}, err
		}
	}
	dnsTarget := strings.TrimSuffix(target, ".")
	for _, device := range devices {
		if device.Name != target && (device.DNSName == "" || !strings.EqualFold(device.DNSName, dnsTarget)) {
			continue
		}
		if matched {
			return netip.Addr{}, fmt.Errorf("multiple devices named %q; use a Mesh IP", target)
		}
		matched = true
		raw := device.IPv4
		if raw == "" {
			raw = device.IPv6
		}
		ip, err := netip.ParseAddr(raw)
		if err != nil || !meshaddr.IsDevice(ip) {
			return netip.Addr{}, fmt.Errorf("device %q has no supported Mesh IP", target)
		}
		result = ip.Unmap()
	}
	if !matched {
		return netip.Addr{}, fmt.Errorf("no device named %q in this account", target)
	}
	return result, nil
}

// Cloudflare authenticates the native connection using its WARP identity. Keep
// proxy host keys separate from own-mode keys and never offer a local private key.
func cloudflareSSHArgs(ip string, port int, username string, command []string) []string {
	args := []string{"ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "HostKeyAlias=meshscale-cloudflare-" + ip, "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes", "-o", "IdentityFile=none", "-o", "IdentityAgent=none", "-o", "PreferredAuthentications=none", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-p", fmt.Sprint(port), "-l", username, "--", ip}
	return append(args, command...)
}
