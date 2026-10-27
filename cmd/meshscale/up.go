package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Whiteknight07/meshscale/internal/auth"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/secure"
	"github.com/Whiteknight07/meshscale/internal/warpcli"
)

func init() {
	register(&command{name: "up", short: "set up and connect this machine to Mesh", run: runUp})
}

func requireLinuxWARP() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("node enrollment into Mesh is Linux-only; macOS/Windows support is coming")
	}
	if _, err := exec.LookPath("warp-cli"); err != nil {
		return fmt.Errorf("warp-cli is missing: install Cloudflare WARP (cloudflare-warp) from the official repository at https://pkg.cloudflareclient.com/ (Debian/Ubuntu: apt install cloudflare-warp; RHEL: dnf install cloudflare-warp), then start warp-svc")
	}
	return nil
}

func runUp(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	advertiseExit := fs.Bool("advertise-exit-node", false, "offer Internet egress to your own secure Linux devices")
	secureMode := fs.Bool("secure", false, "enable device-to-device WireGuard and run the daemon in foreground")
	backendName := fs.String("backend", "", "connection backend: warp (official default) or native (experimental)")
	userspace := fs.Bool("userspace", false, "native/secure: use a private userspace netstack (native also exposes SOCKS5)")
	stateDir := fs.String("state-dir", "", "native: private credential and control directory")
	socks := fs.String("socks", "", "native userspace: SOCKS5 loopback address (default 127.0.0.1:1080)")
	noBrowser := fs.Bool("no-browser", false, "print the sign-in URL and accept a callback URL or code (SSH)")
	accountID := fs.String("account", "", "Cloudflare account ID for first sign-in")
	hostname := fs.String("hostname", "", "Mesh node name (defaults to this machine's hostname)")
	noLogin := fs.Bool("no-login", false, "macOS: enroll using an existing service token and one administrator prompt")
	serviceTokenFile := fs.String("service-token-file", "", "macOS --no-login: private JSON file containing id, client_id and client_secret")
	replaceConsumer := fs.Bool("replace-consumer", false, "macOS: explicitly clear a personal registration before team enrollment")
	asJSON := fs.Bool("json", false, "macOS: emit enrollment progress as JSON lines")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: meshscale up [--backend warp|native] [--secure] [--userspace] [--hostname name]")
	}
	securePath, err := secureDir()
	if err != nil {
		return err
	}
	secureSettings, err := secure.LoadConfig(securePath)
	if err != nil {
		return err
	}
	secureVisited, userspaceVisited := false, false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "secure" {
			secureVisited = true
		}
		if f.Name == "userspace" {
			userspaceVisited = true
		}
	})
	if *advertiseExit {
		secureSettings.AdvertiseExit = true
		secureSettings.Enabled = true
	}
	if secureVisited {
		secureSettings.Enabled = *secureMode
	}
	if secureSettings.Enabled && runtime.GOOS != "linux" {
		return fmt.Errorf("secure mode requires Linux; macOS helper support is gated (docs/secure.md)")
	}
	if secureSettings.Enabled && userspaceVisited {
		secureSettings.Userspace = *userspace
	}
	if secureSettings.AdvertiseExit && (runtime.GOOS != "linux" || os.Geteuid() != 0 || secureSettings.Userspace) {
		return fmt.Errorf("advertising an exit requires Linux root and kernel WireGuard")
	}
	if secureSettings.Enabled && os.Geteuid() != 0 {
		secureSettings.Userspace = true
	}
	saveSecure := func() error {
		if *advertiseExit || secureVisited || secureSettings.Enabled && userspaceVisited {
			return secureSettings.Save(securePath)
		}
		return nil
	}
	daemonCtx := ctx
	settings, err := config.LoadBackend()
	if err != nil {
		return err
	}
	oldBackend := settings.Backend
	// Check before accepting a new state path or mode: changing those flags must
	// never leave a previous native daemon running in another private directory.
	if oldBackend == "native" {
		dir, err := settings.NativeStateDir()
		if err != nil {
			return err
		}
		release, err := localstate.Lock(dir)
		if err != nil {
			return err
		}
		release()
	}
	if err := settings.Select(*backendName); err != nil {
		return err
	}
	if oldBackend != settings.Backend {
		old, _, err := selectedBackend()
		if err != nil {
			return err
		}
		status, statusErr := old.Status(ctx)
		if status.Connected || statusErr == nil && status.State == "connecting" {
			return fmt.Errorf("%s backend is running; run meshscale down before explicitly switching backends", oldBackend)
		}
		// An installed WARP whose status cannot be read may still own routes.
		if oldBackend == "warp" && statusErr != nil {
			if _, err := exec.LookPath("warp-cli"); err == nil {
				return fmt.Errorf("cannot verify WARP is disconnected: %w", statusErr)
			}
		}
	}
	nativeFlag := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "userspace" && !secureSettings.Enabled || f.Name == "state-dir" || f.Name == "socks" {
			nativeFlag = true
		}
	})
	if settings.Backend != "native" && nativeFlag {
		return fmt.Errorf("--userspace, --state-dir and --socks require --backend native")
	}
	if runtime.GOOS != "darwin" && (*noLogin || *replaceConsumer || *asJSON || *serviceTokenFile != "") {
		return fmt.Errorf("macOS enrollment flags are only supported on macOS")
	}
	// JSON enrollment is a stable interface used by the Mac app after login.
	if !*asJSON && !*noLogin {
		if err := ensureUpLogin(ctx, *noBrowser, *accountID); err != nil {
			return err
		}
	}
	if settings.Backend == "native" {
		if *noLogin || *replaceConsumer || *asJSON || *serviceTokenFile != "" {
			return fmt.Errorf("macOS enrollment flags require the official backend")
		}
		if oldBackend != "native" {
			settings.Userspace = false
		}
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "userspace" {
				settings.Userspace = *userspace
			}
		})
		if *stateDir != "" {
			settings.NativeDir = *stateDir
		}
		if *socks != "" {
			settings.SOCKS = *socks
		}
		if settings.SOCKS == "" {
			settings.SOCKS = "127.0.0.1:1080"
		}
		if err := saveSecure(); err != nil {
			return err
		}
		return runNativeUp(ctx, os.Stdout, settings, strings.TrimSpace(*hostname))
	}
	if runtime.GOOS == "darwin" {
		if err := saveSecure(); err != nil {
			return err
		}
		if !*asJSON && !*noLogin {
			account, tokens, err := resolveCredentials()
			if err != nil {
				return err
			}
			if err := setupForUp(ctx, os.Stdout, cfapi.New(tokens, version), account, tokens); err != nil {
				return err
			}
		}
		if err := runMacUp(ctx, settings, *noLogin, *replaceConsumer, *asJSON, *serviceTokenFile); err != nil {
			return err
		}
		return config.SetPaused(false)
	}
	if *noLogin || *replaceConsumer || *asJSON || *serviceTokenFile != "" {
		return fmt.Errorf("macOS enrollment flags are only supported on macOS")
	}
	if err := requireLinuxWARP(); err != nil {
		return err
	}
	if err := saveSecure(); err != nil {
		return err
	}
	if err := settings.Save(); err != nil {
		return err
	}
	name := strings.TrimSpace(*hostname)
	if name == "" {
		var err error
		name, err = os.Hostname()
		if err != nil {
			return err
		}
	}
	if name == "" {
		return fmt.Errorf("hostname is empty; use --hostname")
	}
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	client := cfapi.New(tokens, version)
	if err := setupForUp(ctx, os.Stdout, client, account, tokens); err != nil {
		return err
	}
	state, err := config.LoadMeshState()
	if err != nil {
		return fmt.Errorf("read Mesh node state: %w", err)
	}
	local := warpcli.New("")
	if err := bringUp(ctx, os.Stdout, client, account, local, name, time.Second, state); err != nil {
		return err
	}
	// Resume background reconnect only after this explicit connection passed
	// validation. Invalid flags or a failed enrollment must preserve down intent.
	if err := config.SetPaused(false); err != nil {
		return err
	}
	if err := local.ReconcileNetwork(ctx); err != nil {
		return err
	}
	dnsCtx, dnsCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dnsCancel()
	if err := syncAfterUp(dnsCtx, client, account); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: device sync failed: %v; run meshscale up to retry.\n", err)
	}
	if secureSettings.Enabled {
		return runDaemon(daemonCtx, nil)
	}
	return nil
}

// bringUp keeps node selection and local enrollment independently testable.
func bringUp(ctx context.Context, out io.Writer, client *cfapi.Client, account string, local *warpcli.Client, name string, poll time.Duration, state *config.MeshState) error {
	info, registrationErr := local.Registration(ctx)
	if registrationErr != nil && !warpcli.IsUnregistered(registrationErr) {
		return fmt.Errorf("read local WARP registration (is warp-svc running?): %w", registrationErr)
	}
	nodes, err := client.ListMeshNodes(ctx, account)
	if err != nil {
		return err
	}
	var node cfapi.MeshNode
	for _, n := range nodes {
		if n.Name == name && n.DeletedAt == nil {
			if node.ID != "" {
				return fmt.Errorf("multiple Mesh nodes named %q; choose a unique --hostname", name)
			}
			node = n
		}
	}
	localID := info.RegistrationID
	if localID == "" {
		localID = info.DeviceID
	}
	if localID == "" {
		localID = info.ID
	}
	if info.ConnectorID == "" && localID != "" {
		info.ConnectorID = state.Node(account, localID)
	}
	if registrationErr == nil && info.ConnectorID == "" && node.ID != "" {
		connectors, err := client.ListMeshConnectors(ctx, account, node.ID)
		if err != nil {
			return err
		}
		for _, c := range connectors {
			if localID != "" && c.ID == localID {
				info.ConnectorID = node.ID
				break
			}
		}
	}
	if registrationErr == nil && (info.ConnectorID == "" || (node.ID != "" && info.ConnectorID != node.ID)) {
		return fmt.Errorf("this machine already has a different WARP registration; refusing to replace it")
	}
	if registrationErr == nil && node.ID == "" {
		return fmt.Errorf("this machine is registered to Mesh node %s; use that node's hostname", info.ConnectorID)
	}
	if node.ID == "" {
		node, err = client.CreateMeshNode(ctx, account, cfapi.CreateMeshNodeParams{Name: name})
		if err != nil {
			return err
		}
		fmt.Fprintln(out, "Created Mesh node:", name)
	} else {
		fmt.Fprintln(out, "Reusing Mesh node:", name)
	}
	if registrationErr != nil {
		token, err := client.MeshNodeToken(ctx, account, node.ID)
		if err != nil {
			return err
		}
		if err := local.ConnectorNew(ctx, token); err != nil {
			return err
		}
		info, err = local.Registration(ctx)
		if err != nil {
			return fmt.Errorf("read enrolled registration: %w", err)
		}
		localID = info.RegistrationID
		if localID == "" {
			localID = info.DeviceID
		}
		if localID == "" {
			localID = info.ID
		}
		fmt.Fprintln(out, "Enrolled this machine.")
	} else {
		fmt.Fprintln(out, "Already enrolled to this Mesh node.")
	}
	state.Remember(account, node.ID, localID)
	if err := state.Save(); err != nil {
		return fmt.Errorf("save Mesh node state: %w", err)
	}
	team, err := zeroTrustTeam(ctx, client, account)
	if err != nil {
		return err
	}
	local.Organization = team
	local.RequireSafeProfile = true
	fmt.Fprintln(out, "Connecting...")
	if err := local.Connect(ctx); err != nil {
		return err
	}
	var last string
	connectedSamples := 0
	for {
		status, err := local.Status(ctx)
		if err != nil {
			return err
		}
		last = status.State
		if status.Reason != "" {
			last += " (" + status.Reason + ")"
		}
		if status.Connected {
			connectedSamples++
		} else {
			connectedSamples = 0
		}
		if connectedSamples >= 3 {
			var ip bytes.Buffer
			if err := writeLocalIP(ctx, &ip, client, account, local, 4); err == nil {
				fmt.Fprintln(out, "Connected. Mesh IP:", strings.TrimSpace(ip.String()))
				return nil
			} else {
				last = err.Error()
			}
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("waiting for Mesh connection: %s: %w", last, ctx.Err())
		case <-timer.C:
		}
	}
}

// Only an absent login starts browser consent. Corrupt/private state errors must
// remain visible rather than being overwritten by a new login.
func ensureUpLogin(ctx context.Context, noBrowser bool, account string) error {
	current, _, err := resolveCredentials()
	if errors.Is(err, errNotLoggedIn) {
		headless := os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" || runtime.GOOS == "linux" && os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == ""
		return loginFlow(ctx, noBrowser || headless, account, os.Stdout, false)
	}
	if err == nil && account != "" && current != account {
		return fmt.Errorf("saved account differs from --account; run meshscale login --account %s to switch", account)
	}
	return err
}

func setupForUp(ctx context.Context, out io.Writer, client *cfapi.Client, account string, tokens cfapi.TokenSource) error {
	fmt.Fprintln(out, "Preparing your account...")
	_, oauth := tokens.(*auth.TokenSource)
	email, err := auth.NewClient().Email(ctx, tokens, oauth)
	if err != nil && !oauth {
		email, err = client.SoleAccountOwnerEmail(ctx, account)
	}
	if err != nil {
		return fmt.Errorf("read account owner: %w", err)
	}
	return completeUpSetup(ctx, out, client, account, email)
}
