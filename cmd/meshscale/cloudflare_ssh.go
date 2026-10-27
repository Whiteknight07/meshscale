package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/Whiteknight07/meshscale/internal/auth"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/cloudflaressh"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/localstate"
)

func init() {
	register(&command{name: "ssh-mode", short: "experimental Linux SSH mode: cloudflare, own or off", run: runSSHMode})
}

type sshModeStore struct{ path string }

func (s sshModeStore) Save(state cloudflaressh.State) error { return localstate.Write(s.path, state) }
func sshModePath() (string, error) {
	dir, err := config.Dir()
	return filepath.Join(dir, "cloudflare-ssh", "state.json"), err
}
func loadSSHMode() (cloudflaressh.State, error) {
	p, err := sshModePath()
	s := cloudflaressh.State{}
	if err != nil {
		return s, err
	}
	err = localstate.Read(p, &s)
	if os.IsNotExist(err) {
		err = nil
	}
	return s, err
}
func runSSHMode(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ssh-mode", flag.ContinueOnError)
	initPolicy := fs.Bool("init-policy", false, "own mode: initialize missing owner-only SSH policy")
	users := fs.String("users", "", "explicit comma-separated existing local usernames (root must be explicit)")
	name := fs.String("name", "", "owned Cloudflare resource name (default meshscale-ssh-<hostname>)")
	enableProxy := fs.Bool("enable-gateway-proxy", false, "enable Gateway TCP proxying ACCOUNT-WIDE for all enrolled clients")
	// Permit both ssh-mode cloudflare --users alice and conventional flags first.
	mode := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		mode, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if mode == "" && fs.NArg() == 1 {
		mode = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return fmt.Errorf("usage: meshscale ssh-mode cloudflare --users alice | own | off")
	}
	if mode != "cloudflare" && mode != "own" && mode != "off" {
		return fmt.Errorf("usage: meshscale ssh-mode cloudflare --users alice | own | off")
	}
	if *initPolicy && mode != "own" {
		return fmt.Errorf("--init-policy requires own mode")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return fmt.Errorf("ssh-mode requires root on a Linux server using the WARP backend")
	}
	_, settings, err := selectedBackend()
	if err != nil {
		return err
	}
	if settings.Backend == "native" {
		return fmt.Errorf("cloudflare SSH requires the official WARP backend")
	}
	path, err := sshModePath()
	if err != nil {
		return err
	}
	release, err := localstate.Lock(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("SSH mode migration in progress: %w", err)
	}
	defer release()
	state, err := loadSSHMode()
	if err != nil {
		return err
	}
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	if state.Account != "" && state.Account != account {
		return fmt.Errorf("saved SSH resources belong to a different account; restore using that account first")
	}
	client := cfapi.New(tokens, version)
	store := sshModeStore{path}
	host := newCloudflareSSHHost(store)
	manager := cloudflaressh.Manager{Resources: client, Store: store, Host: host}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if mode != "cloudflare" {
		if *enableProxy {
			return fmt.Errorf("--enable-gateway-proxy requires cloudflare mode")
		}
		if mode == "own" {
			options, err := config.LoadService()
			if err != nil {
				return err
			}
			for _, path := range ownSSHPolicyPaths(state, options) {
				if err := ensureOwnSSHPolicy(ctx, path, *initPolicy); err != nil {
					return err
				}
			}
		}
		state.Account = account
		if err := manager.Disable(ctx, &state, mode); err != nil {
			return err
		}
		fmt.Printf("SSH mode: %s. Removed owned Cloudflare interception and OpenSSH trust; account CA retained.\n", mode)
		return nil
	}
	if *users == "" && len(state.Users) == 0 {
		return fmt.Errorf("cloudflare mode requires --users with explicit local usernames, for example: meshscale ssh-mode cloudflare --users alice")
	}
	configured := state.Users
	if *users != "" {
		configured = strings.Split(*users, ",")
	}
	slices.Sort(configured)
	configured = slices.Compact(configured)
	for _, u := range configured {
		entry, e := user.Lookup(u)
		if e != nil {
			return fmt.Errorf("lookup local SSH user %q: %w", u, e)
		}
		if entry.Uid == "0" && u != "root" {
			return fmt.Errorf("alternate UID 0 username is forbidden: %s", u)
		}
	}
	email, err := auth.ResolveOwnerEmail(ctx, client, account)
	if err != nil {
		return fmt.Errorf("verify account owner: %w", err)
	}
	local, _, err := selectedBackend()
	if err != nil {
		return err
	}
	ips, err := localSSHIPs(ctx, client, account, local)
	if err != nil {
		return err
	}
	ip := ips[0]
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	resourceName := "meshscale-ssh-" + hostname
	if *name != "" {
		resourceName = *name
	} else if state.Name != "" {
		resourceName = state.Name
	}
	if (state.Host != nil || state.Nonce != "" || state.TargetID != "" || state.AppID != "") && (state.IP != ip.String() || state.Owner != email || state.Name != resourceName || !slices.Equal(state.Users, configured)) {
		return fmt.Errorf("restore ssh-mode own before changing the Mesh IP, owner, resource name or username mapping")
	}
	state.Account, state.Name, state.IP, state.Owner, state.Users = account, resourceName, ip.String(), email, configured
	if err := cloudflaressh.Validate(state); err != nil {
		return err
	}
	gateway, err := client.DeviceSettings(ctx, account)
	if err != nil {
		return fmt.Errorf("read account Gateway TCP proxy setting: %w", err)
	}
	if !gateway.GatewayProxyEnabled {
		if !*enableProxy {
			return fmt.Errorf("gateway TCP proxying is disabled. One-time opt-in: meshscale ssh-mode cloudflare --users %s --enable-gateway-proxy. This enables TCP proxying ACCOUNT-WIDE for all enrolled clients, not just this server; HTTPS decryption and device profiles are unchanged", strings.Join(configured, ","))
		}
		yes := true
		gateway, err = client.UpdateDeviceSettings(ctx, account, cfapi.DeviceSettingsPatch{GatewayProxyEnabled: &yes})
		if err != nil {
			return fmt.Errorf("enable account-wide Gateway TCP proxy: %w", err)
		}
		if !gateway.GatewayProxyEnabled {
			return fmt.Errorf("gateway TCP proxy enable did not verify")
		}
		fmt.Println("Enabled Gateway TCP proxying ACCOUNT-WIDE for all enrolled clients.")
	}
	ca, created, err := cloudflaressh.EnsureCA(ctx, client, account)
	if created {
		fmt.Printf("Created reusable account SSH CA %s (retained when this server opts out).\n", ca.ID)
	}
	if err != nil {
		return err
	}
	if state.Host != nil && state.CAID != "" && state.CAID != ca.ID {
		return fmt.Errorf("account CA changed since this server opted in; restore ssh-mode own before trusting the new CA")
	}
	if !created {
		fmt.Printf("Reusing account SSH CA %s.\n", ca.ID)
	}
	if err := manager.Enable(ctx, &state, ca); err != nil {
		return err
	}
	fmt.Printf("Experimental SSH mode: cloudflare. Owner %s -> %s at %s:22\nTarget %s; application %s; policies %s\nCloudflare terminates SSH and issues short-lived origin certificates. Connect from an owner-enrolled WARP client: meshscale ssh %s@%s\nEdge enforcement is eventually consistent; target discovery alone does not prove activation.\n", email, strings.Join(configured, ","), ip, state.TargetID, state.AppID, strings.Join(state.PolicyIDs, ","), configured[0], hostname)
	return nil
}

// A mode rollback may restore standalone sshd processes with explicit policy
// paths. Validate those policies too, without changing the saved process args.
func ownSSHPolicyPaths(state cloudflaressh.State, options *config.ServiceSettings) []string {
	paths := []string{options.SSHPolicy}
	if state.Host == nil || state.Host.ServiceSSH || len(state.Host.Own) == 0 {
		return paths
	}
	paths = nil
	for _, process := range state.Host.Own {
		path := options.SSHPolicy
		for i, arg := range process.Args {
			if arg == "--policy" || arg == "-policy" {
				if i+1 < len(process.Args) {
					path = process.Args[i+1]
				}
			} else if value, ok := strings.CutPrefix(arg, "--policy="); ok {
				path = value
			} else if value, ok := strings.CutPrefix(arg, "-policy="); ok {
				path = value
			}
		}
		if !slices.Contains(paths, path) {
			paths = append(paths, path)
		}
	}
	return paths
}
