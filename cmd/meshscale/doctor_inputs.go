package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Whiteknight07/meshscale/internal/auth"
	"github.com/Whiteknight07/meshscale/internal/backend"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/exitnode"
	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/native"
	"github.com/Whiteknight07/meshscale/internal/reachability"
	"github.com/Whiteknight07/meshscale/internal/secure"
	"github.com/Whiteknight07/meshscale/internal/secureroute"
	"github.com/Whiteknight07/meshscale/internal/service"
	"github.com/Whiteknight07/meshscale/internal/warpcli"
)

type doctorBackend struct {
	local    backend.Backend
	settings config.BackendSettings
}
type doctorAccount struct {
	id     string
	client *cfapi.Client
}
type doctorInputs struct {
	dir           string
	lookup        func(context.Context, string, string) ([]netip.Addr, error)
	local         *doctorFuture[doctorBackend]
	registration  *doctorFuture[backend.Registration]
	account       *doctorFuture[doctorAccount]
	organization  *doctorFuture[cfapi.Organization]
	registrations *doctorFuture[[]cfapi.Registration]
	daemon        *doctorFuture[service.Status]
	inventory     *doctorFuture[[]meshDevice]
	network       *doctorFuture[exitnode.Snapshot]
}

// Compute paths without config.Dir, which creates directories on first use.
func doctorConfigDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "meshscale"), nil
}
func doctorExistingDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("configuration directory is not a directory")
	}
	return nil
}

// Existing helpers validate ownership/modes but create missing parent directories.
// Checking existence first avoids their creation behavior for diagnostic reads.
func doctorReadJSON(path string, out any) error {
	if _, err := os.Lstat(path); err != nil {
		return err
	}
	return localstate.Read(path, out)
}
func doctorServiceRequest(ctx context.Context, dir, path string, out any) error {
	if err := doctorExistingDir(dir); err != nil {
		return err
	}
	return service.Request(ctx, dir, "GET", path, nil, out)
}
func doctorCredentials(dir string) (doctorAccount, error) {
	if err := doctorExistingDir(dir); err != nil {
		return doctorAccount{}, err
	}
	env, err := config.LoadEnv()
	if err != nil {
		return doctorAccount{}, err
	}
	account, token := env["CLOUDFLARE_ACCOUNT_ID"], env["CLOUDFLARE_API_TOKEN"]
	if account == "" || token == "" {
		session, err := (&auth.Store{Path: filepath.Join(dir, "oauth.json")}).Load()
		if err != nil {
			return doctorAccount{}, errors.New("no usable saved credentials; run meshscale login")
		}
		// Refresh would write credentials and call the OAuth token endpoint.
		if !session.Expiry.After(time.Now().Add(5 * time.Second)) {
			return doctorAccount{}, errors.New("saved OAuth access token expired; run meshscale login")
		}
		account, token = session.Account.ID, session.AccessToken
	}
	return doctorAccount{account, cfapi.New(cfapi.StaticToken(token), version)}, nil
}

var errDoctorTermsNotAccepted = errors.New("cloudflare One terms not accepted yet")

// Doctor only reaches warp-cli after meshscale up/setup saved a backend, so the
// user already agreed to the client's terms there. Without a TTY, warp-cli on
// Linux refuses every command unless --accept-tos is passed on that call; the
// flag is not persisted, so keeping it changes no consent state. The executor
// still rejects everything except these three local reads.
func doctorWarpClient(path string, execute warpcli.ExecFunc) *warpcli.Client {
	client := warpcli.New(path)
	if execute == nil {
		execute = doctorCommand
	}
	client.Exec = func(ctx context.Context, path string, args ...string) ([]byte, error) {
		read := args
		if len(read) > 0 && read[0] == "--accept-tos" {
			read = read[1:]
		}
		switch strings.Join(read, " ") {
		case "status", "registration show", "settings":
		default:
			return nil, errors.New("doctor refused a non-diagnostic warp-cli command")
		}
		output, err := execute(ctx, path, args...)
		lower := strings.ToLower(string(output))
		if err != nil && strings.Contains(lower, "--accept-tos") || strings.Contains(lower, "terms of service") || strings.Contains(lower, "terms not accepted") || strings.Contains(lower, "terms have not been accepted") || strings.Contains(lower, "accept the terms") {
			return nil, errDoctorTermsNotAccepted
		}
		return output, err
	}
	return client
}
func doctorTermsUnavailable(err error) (doctorCheck, bool) {
	if errors.Is(err, errDoctorTermsNotAccepted) {
		return doctorResult("warn", "unavailable: Cloudflare One terms not accepted yet", "review and accept the official client's terms explicitly before retrying"), true
	}
	return doctorCheck{}, false
}

func newDoctorInputs(ctx context.Context) *doctorInputs {
	dir, _ := doctorConfigDir()
	d := &doctorInputs{dir: dir}
	d.local = startDoctorRead(ctx, func(context.Context) (doctorBackend, error) {
		if err := doctorExistingDir(dir); err != nil {
			return doctorBackend{}, err
		}
		settings, err := config.LoadBackend()
		if err != nil {
			return doctorBackend{}, err
		}
		var local backend.Backend
		// Native's default path helper otherwise creates its config directory.
		if settings.Backend == "native" {
			stateDir, err := settings.NativeStateDir()
			if err != nil {
				return doctorBackend{}, err
			}
			if err := doctorExistingDir(stateDir); err != nil {
				return doctorBackend{}, err
			}
			local = &native.Client{Dir: stateDir}
		} else {
			local = doctorWarpClient("", nil)
		}
		return doctorBackend{local, *settings}, nil
	})
	d.registration = startDoctorRead(ctx, func(ctx context.Context) (backend.Registration, error) {
		b, err := d.local.get(ctx)
		if err != nil {
			return backend.Registration{}, err
		}
		return b.local.Registration(ctx)
	})
	d.account = startDoctorRead(ctx, func(context.Context) (doctorAccount, error) { return doctorCredentials(dir) })
	d.organization = startDoctorRead(ctx, func(ctx context.Context) (cfapi.Organization, error) {
		a, err := d.account.get(ctx)
		if err != nil {
			return cfapi.Organization{}, err
		}
		return a.client.Organization(ctx, a.id)
	})
	d.registrations = startDoctorRead(ctx, func(ctx context.Context) ([]cfapi.Registration, error) {
		a, err := d.account.get(ctx)
		if err != nil {
			return nil, err
		}
		return a.client.ListRegistrations(ctx, a.id)
	})
	d.daemon = startDoctorRead(ctx, func(ctx context.Context) (service.Status, error) {
		var s service.Status
		err := doctorServiceRequest(ctx, filepath.Join(dir, "service"), "/status", &s)
		return s, err
	})
	d.inventory = startDoctorRead(ctx, func(ctx context.Context) ([]meshDevice, error) {
		var inventory service.Inventory
		if err := doctorServiceRequest(ctx, filepath.Join(dir, "service"), "/devices", &inventory); err == nil && len(inventory.Devices) > 0 {
			return inventory.Devices, nil
		}
		a, err := d.account.get(ctx)
		if err != nil {
			return nil, err
		}
		// The same merge as status, so names match the published DNS rules.
		// A nil MeshState keeps doctor read-only.
		devices, err := loadMeshDevices(ctx, a.client, a.id, nil, time.Now(), nil)
		if err != nil {
			return nil, err
		}
		if reg, err := d.registration.get(ctx); err == nil {
			markThisMachine(devices, reg)
		}
		return devices, assignDNSNames(devices)
	})
	d.network = startDoctorRead(ctx, func(ctx context.Context) (exitnode.Snapshot, error) { return exitnode.Inspect(ctx, nil) })
	return d
}
func newDoctorTasks(ctx context.Context) []doctorTask {
	d := newDoctorInputs(ctx)
	return []doctorTask{
		{"official-client", "installed executable / version", "install or update the official Cloudflare One client", func(ctx context.Context) doctorCheck {
			if b, err := d.local.get(ctx); err == nil && b.settings.Backend == "native" {
				return doctorResult("warn", "native backend selected; official client is not used", "native is experimental; use the official backend for supported enrollment")
			}
			if !warpcli.Installed() {
				return doctorResult("fail", "warp-cli is missing", "install the official Cloudflare One client")
			}
			out, err := doctorCommand(ctx, warpcli.DefaultPath(), "--version")
			if err != nil {
				return doctorResult("warn", "warp-cli installed; version unavailable", "check warp-cli --version")
			}
			return doctorResult("ok", strings.TrimSpace(string(out)), "use the official client for Mesh carrier support")
		}},
		{"connection", "selected backend state (not a traffic probe)", "inspect warp-cli status and meshscale up", d.checkConnection},
		{"registration", "active registration in configured account", "check meshscale whoami and re-enroll with meshscale up", d.checkRegistration},
		{"team-profile", "Team organization / effective Include profile", "select the configured account's Mesh Include profile", d.checkTeam},
		{"daemon", "GET /status / last successful sync age", "inspect meshscale service status using the enrollment user", d.checkDaemon},
		{"secure", "engine / handshake seen / egress unverified", "inspect meshscale service status and secure settings", d.checkSecure},
		{"ssh-mode", "saved mode / daemon SSH listener enabled", "inspect meshscale ssh-mode and meshscale service status", d.checkSSH},
		{"dns", "system resolver lookup of a Mesh DNS name", "check resolver routing for the configured Mesh DNS suffix", d.checkDNS},
		{"mesh-route", "kernel route evidence for 100.96.0.0/12", "inspect the WARP Include profile and policy routing", d.checkRoute},
		{"tailscale-overlap", "policy rule order / narrow ingress exception", "inspect Mesh/Tailscale coexistence rules", d.checkOverlap},
		{"warp-mtu", "interface MTU (not path MTU)", "inspect the WARP interface MTU", d.checkMTU},
		{"cloudflare-api", "authenticated HTTPS GET organization", "check saved account credentials and API connectivity", d.checkAPI},
		{"peer-reachability", "ICMP echo or TCP connect; no RTT measurement", "try meshscale ping --port 22 on the intended peer", d.checkPeer},
	}
}
func (d *doctorInputs) checkConnection(ctx context.Context) doctorCheck {
	b, err := d.local.get(ctx)
	if err != nil {
		return doctorResult("fail", "selected backend configuration unavailable", "check the enrollment user's backend configuration")
	}
	s, err := b.local.Status(ctx)
	if err != nil {
		if check, ok := doctorTermsUnavailable(err); ok {
			return check
		}
		return doctorResult("fail", b.settings.Backend+" status unavailable", "inspect the selected backend's local service")
	}
	level := "ok"
	if !s.Connected {
		level = "fail"
		if b.settings.Paused {
			level = "warn"
		}
	}
	return doctorResult(level, b.settings.Backend+": "+s.State, "run meshscale up when a connection is wanted")
}
func (d *doctorInputs) checkRegistration(ctx context.Context) doctorCheck {
	reg, err := d.registration.get(ctx)
	if err != nil {
		if check, ok := doctorTermsUnavailable(err); ok {
			return check
		}
		return doctorResult("fail", "local registration unavailable", "enroll this backend with meshscale up")
	}
	regs, err := d.registrations.get(ctx)
	if err != nil {
		return doctorResult("fail", "account registration lookup unavailable", "check the configured account's device-read permission")
	}
	devices := mergeMeshDevices(regs, nil, nil, time.Now())
	markThisMachine(devices, reg)
	count := 0
	for _, device := range devices {
		ip, err := netip.ParseAddr(device.IPv4)
		if device.ThisMachine && err == nil && isDoctorMeshIP(ip) {
			count++
		}
	}
	if count != 1 {
		return doctorResult("fail", "local registration is not a unique active Mesh participant", "check meshscale whoami and re-enroll with meshscale up")
	}
	return doctorResult("ok", "one active Mesh registration matches the configured account", "keep CLI and daemon on the same account configuration")
}
func (d *doctorInputs) checkTeam(ctx context.Context) doctorCheck {
	b, err := d.local.get(ctx)
	if err != nil {
		return doctorResult("fail", "backend configuration unavailable", "check saved backend settings")
	}
	if b.settings.Backend == "native" {
		return doctorResult("warn", "experimental native backend has no official Team/profile", "use the official backend for supported enrollment")
	}
	reg, err := d.registration.get(ctx)
	if err != nil {
		if check, ok := doctorTermsUnavailable(err); ok {
			return check
		}
		return doctorResult("fail", "official registration unavailable", "check warp-cli registration show")
	}
	org, err := d.organization.get(ctx)
	if err != nil {
		return doctorResult("fail", "configured organization lookup unavailable", "check account credentials and organization-read permission")
	}
	client, ok := b.local.(interface {
		Settings(context.Context) (string, error)
	})
	if !ok {
		return doctorResult("fail", "effective client settings unavailable", "check warp-cli settings")
	}
	settings, err := client.Settings(ctx)
	if err != nil {
		if check, ok := doctorTermsUnavailable(err); ok {
			return check
		}
		return doctorResult("fail", "effective client settings unavailable", "check warp-cli settings")
	}
	team := strings.TrimSuffix(org.AuthDomain, ".cloudflareaccess.com")
	if err := warpcli.ValidateSafety(reg, settings, team); err != nil {
		return doctorResult("fail", "Team organization or safe Include profile does not match", "check registration team and the account's Mesh Include profile")
	}
	return doctorResult("ok", "Team registration and safe Include profile match the account", "retain the Mesh Include profile for VPN coexistence")
}
func (d *doctorInputs) checkAPI(ctx context.Context) doctorCheck {
	_, err := d.organization.get(ctx)
	if err != nil {
		detail := "authenticated organization read unavailable"
		var api *cfapi.APIError
		if errors.As(err, &api) {
			detail = fmt.Sprintf("organization read returned HTTP %d", api.StatusCode)
		}
		return doctorResult("fail", detail, "check API connectivity, login expiry and organization-read permission")
	}
	return doctorResult("ok", "configured account organization read succeeded", "retain organization-read permission; this does not test all API grants")
}
func (d *doctorInputs) checkDaemon(ctx context.Context) doctorCheck {
	s, err := d.daemon.get(ctx)
	if err != nil {
		return doctorResult("warn", "daemon socket unavailable", "inspect meshscale service status using the enrollment user")
	}
	if s.Mode != "daemon" {
		return doctorResult("warn", "socket belongs to "+s.Mode+"; no device-sync daemon", "run meshscale daemon for background synchronization")
	}
	if s.LastSync.IsZero() {
		detail := "daemon reachable; no successful sync"
		if s.SyncError != "" {
			detail += "; sync error: " + s.SyncError
		}
		return doctorResult("fail", detail, "inspect daemon journal and account permissions")
	}
	age := max(time.Duration(0), time.Since(s.LastSync)).Round(time.Second)
	level := "ok"
	if age > 3*time.Minute {
		level = "warn"
	}
	detail := fmt.Sprintf("daemon reachable; last sync %s ago", age)
	if s.SyncError != "" {
		level = "fail"
		detail += "; sync error: " + s.SyncError
	}
	return doctorResult(level, detail, "inspect daemon logs if synchronization is stale")
}
func (d *doctorInputs) checkSecure(ctx context.Context) doctorCheck {
	var configured secure.Config
	err := doctorReadJSON(filepath.Join(d.dir, "secure", "config.json"), &configured)
	if err != nil && !os.IsNotExist(err) {
		return doctorResult("fail", "secure configuration unreadable", "check the secure config's ownership and permissions")
	}
	s, daemonErr := d.daemon.get(ctx)
	if daemonErr != nil {
		if configured.Enabled {
			return doctorResult("fail", "secure enabled; daemon state unavailable", "inspect the secure daemon before using .secure targets")
		}
		return doctorResult("ok", "secure disabled; egress unverified", "enable secure mode explicitly when encryption is required")
	}
	if s.Secure.Error != "" {
		return doctorResult("fail", "secure error: "+s.Secure.Error, "inspect secure daemon logs and peer discovery")
	}
	if configured.Enabled && !s.Secure.Running || s.Secure.Enabled && !s.Secure.Running {
		return doctorResult("fail", "secure enabled; engine stopped", "inspect the secure daemon and its saved configuration")
	}
	if !s.Secure.Running {
		return doctorResult("ok", "secure disabled; egress unverified", "enable secure mode explicitly when encryption is required")
	}
	handshakes := 0
	for _, peer := range s.Secure.Peers {
		if peer.LastHandshake != nil {
			handshakes++
		}
	}
	routeState := secureroute.Status()
	detail := fmt.Sprintf("%s running; handshake seen for %d peer(s); egress unverified; route: %s", s.Secure.Mode, handshakes, routeState)
	level := "ok"
	if len(s.Secure.Warnings) > 0 {
		level = "warn"
		detail += "; " + strings.Join(s.Secure.Warnings, "; ")
	}
	if routeState == "route missing" || s.Secure.Mode == "kernel" && strings.HasPrefix(routeState, "not applicable") {
		level = "fail"
	}
	return doctorResult(level, detail, "test the intended secure service; a handshake alone does not verify egress")
}
func (d *doctorInputs) checkSSH(ctx context.Context) doctorCheck {
	var state struct {
		Mode string `json:"mode"`
	}
	err := doctorReadJSON(filepath.Join(d.dir, "cloudflare-ssh", "state.json"), &state)
	if err != nil && !os.IsNotExist(err) {
		return doctorResult("fail", "saved SSH mode unreadable", "check SSH mode state permissions")
	}
	s, daemonErr := d.daemon.get(ctx)
	if state.Mode == "" {
		state.Mode = "own (default)"
	}
	if daemonErr != nil {
		return doctorResult("warn", state.Mode+"; daemon listener state unavailable", "inspect meshscale service status or the external SSH server")
	}
	if state.Mode == "off" && s.SSH || state.Mode == "cloudflare" && s.SSH {
		return doctorResult("fail", state.Mode+" conflicts with enabled daemon SSH", "inspect meshscale ssh-mode and the daemon SSH setting")
	}
	detail := fmt.Sprintf("%s; daemon SSH enabled=%t", state.Mode, s.SSH)
	return doctorResult("ok", detail, "verify the target SSH port and authorization policy separately")
}
func (d *doctorInputs) checkDNS(ctx context.Context) doctorCheck {
	if b, err := d.local.get(ctx); err == nil && b.settings.Backend == "native" && b.settings.Userspace {
		return doctorResult("warn", "native userspace names resolve inside the private stack; system DNS is not used", "use meshscale ping to test private name resolution")
	}
	devices, err := d.inventory.get(ctx)
	if err != nil {
		return doctorResult("warn", "no Mesh name available for a resolver lookup", "check cached inventory and meshscale dns list")
	}
	for _, device := range devices {
		if device.DNSName == "" || device.IPv4 == "" && device.IPv6 == "" {
			continue
		}
		lookup := d.lookup
		if lookup == nil {
			lookup = net.DefaultResolver.LookupNetIP
		}
		ips, err := lookup(ctx, "ip", device.DNSName+".")
		if err != nil {
			return doctorResult("fail", device.DNSName+" did not resolve", "check system resolver split DNS and meshscale dns list")
		}
		for _, ip := range ips {
			// Go returns /etc/hosts IPv4 entries as IPv4-mapped IPv6.
			if ip = ip.Unmap(); ip.String() == device.IPv4 || ip.String() == device.IPv6 {
				return doctorResult("ok", device.DNSName+" resolves to its inventory Mesh address", "retain resolver forwarding for the Mesh DNS suffix")
			}
		}
		return doctorResult("fail", device.DNSName+" resolved to a different address", "check stale DNS policies and the system resolver")
	}
	return doctorResult("warn", "inventory has no resolvable Mesh name", "check meshscale dns list")
}
func (d *doctorInputs) checkPeer(ctx context.Context) doctorCheck {
	devices, err := d.inventory.get(ctx)
	if err != nil {
		return doctorResult("warn", "no peer inventory available", "try meshscale ping on a known Mesh peer")
	}
	for _, device := range devices {
		if device.ThisMachine {
			continue
		}
		ip, err := netip.ParseAddr(device.IPv4)
		if err != nil || !isDoctorMeshIP(ip) {
			continue
		}
		if err := (reachability.Network{}).Probe(ctx, ip); err != nil {
			return doctorResult("warn", "selected peer did not answer ICMP echo or common TCP ports", "try meshscale ping --port with the intended service port")
		}
		return doctorResult("ok", "selected peer answered ICMP echo or TCP connect; egress unverified", "use meshscale ping for a timed TCP connect to a specific port")
	}
	return doctorResult("warn", "no other Mesh peer to probe", "connect a second device before testing peer services")
}

// No stderr from a child is ever included in doctor errors.
func doctorCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = config.ChildEnvironment()
	cmd.WaitDelay = 100 * time.Millisecond
	var output bugreportBuffer
	cmd.Stdout, cmd.Stderr = &output, &output
	err := cmd.Run()
	return output.Bytes(), err
}
