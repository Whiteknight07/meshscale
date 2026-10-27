package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"golang.org/x/sync/errgroup"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/service"
	"github.com/Whiteknight07/meshscale/internal/warpcli"
)

func init() {
	register(&command{name: "status", short: "list Mesh devices, IPs, and connection state", run: runStatus})
}

type localWARP interface {
	Status(context.Context) (warpcli.ConnectionStatus, error)
	Registration(context.Context) (warpcli.RegistrationInfo, error)
}

type meshDevice = service.Device

func runStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	refresh := fs.Bool("refresh", false, "refresh the daemon cache from Cloudflare before printing")
	asJSON := fs.Bool("json", false, "print device information as JSON")
	testStaleIP := fs.String("test-stale-ip", "", "verification only: treat this Mesh IP as stale for this status call")
	noCache := fs.Bool("no-cache", false, "do not read or write the local Mesh association cache")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: meshscale status [--json] [--refresh] [--no-cache]")
	}
	if *testStaleIP != "" {
		if _, err := netip.ParseAddr(*testStaleIP); err != nil {
			return fmt.Errorf("invalid test-stale-ip: %w", err)
		}
	}
	if !*noCache && *testStaleIP == "" {
		devices, reachable, err := daemonDevices(ctx, *refresh)
		if reachable {
			if err != nil {
				return err
			}
			return writeStatus(os.Stdout, devices, *asJSON, time.Now())
		}
	}
	devices, err := liveStatusDevices(ctx, *noCache, *testStaleIP)
	if err != nil {
		return err
	}
	return writeStatus(os.Stdout, devices, *asJSON, time.Now())
}

func liveStatusDevices(ctx context.Context, noCache bool, testStaleIP string) ([]meshDevice, error) {
	account, tokens, err := resolveCredentials()
	if err != nil {
		return nil, err
	}
	state, err := statusMeshState(noCache)
	if err != nil {
		return nil, fmt.Errorf("read Mesh node state: %w", err)
	}
	local, settings, err := selectedBackend()
	if err != nil {
		return nil, err
	}
	return fetchStatusDevices(ctx, cfapi.New(tokens, version), account, local, settings, state, testStaleIP)
}

func fetchStatusDevices(ctx context.Context, client *cfapi.Client, account string, local localWARP, settings *config.BackendSettings, state *config.MeshState, testStaleIP string) ([]meshDevice, error) {
	devices, err := loadMeshDevices(ctx, client, account, local, time.Now(), state)
	if err != nil {
		return nil, err
	}
	if settings.Backend == "native" {
		status, _ := local.Status(ctx)
		for i := range devices {
			if devices[i].ThisMachine {
				devices[i].Backend = "native (experimental)"
				devices[i].Online = status.Connected
				devices[i].OnlineSource = "local"
				if !status.Connected {
					devices[i].ConnectionState = status.State
				}
			}
		}
	}
	if testStaleIP != "" {
		matched := false
		for i := range devices {
			if devices[i].IPv4 == testStaleIP || devices[i].IPv6 == testStaleIP {
				stale := time.Now().Add(-time.Hour)
				devices[i].LastSeenAt, devices[i].Online, devices[i].OnlineSource = &stale, false, "cloudflare"
				matched = true
			}
		}
		if !matched {
			return nil, fmt.Errorf("test-stale-ip %s is not an active account device", testStaleIP)
		}
	}
	probeNow := time.Now()
	ips := statusProbeIPs(devices, probeNow)
	probeCtx, cancelProbes := context.WithCancel(ctx)
	defer cancelProbes()
	probeResults := make(chan map[string]bool, 1)
	go func() { probeResults <- statusReachability(probeCtx, ips) }()

	if err := assignDNSNames(devices); err != nil {
		return nil, err
	}
	entries, routeErr := client.ListRoutes(ctx, account)
	if routeErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load subnet routes: %v\n", routeErr)
	} else {
		assignRoutes(devices, entries)
	}
	if err := assignSecureStatus(ctx, client, account, devices); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: secure state unavailable: %v\n", err)
	}
	if err := assignSSHMode(ctx, client, account, devices); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: SSH mode unavailable: %v\n", err)
	}
	if options, err := config.LoadService(); err == nil {
		for i := range devices {
			d := &devices[i]
			if d.ThisMachine && d.SSHMode != "cloudflare" && d.SSHMode != "off" && (options.SSH || d.SSHMode == "own") {
				d.SSHPolicy = sshPolicyState(options.SSHPolicy)
			}
		}
	}
	applyProbeResults(devices, <-probeResults, probeNow)
	return devices, nil
}

// Verification can query an account without persisting its ID in the normal
// association cache. Default status behavior is unchanged.
func statusMeshState(noCache bool) (*config.MeshState, error) {
	if noCache {
		return &config.MeshState{}, nil
	}
	return config.LoadMeshState()
}

func loadMeshDevices(ctx context.Context, client *cfapi.Client, account string, local localWARP, now time.Time, state *config.MeshState) ([]meshDevice, error) {
	// The lists are independent; fetching them concurrently keeps a direct
	// status near one API round trip rather than one per Mesh node.
	var (
		registrations []cfapi.Registration
		physical      []cfapi.PhysicalDevice
		nodes         []cfapi.MeshNode
	)
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() (err error) {
		registrations, err = client.ListRegistrations(gctx, account)
		return err
	})
	g.Go(func() (err error) {
		physical, err = client.ListPhysicalDevices(gctx, account)
		return err
	})
	g.Go(func() (err error) {
		if nodes, err = client.ListMeshNodes(gctx, account); err != nil {
			return err
		}
		connectors, cctx := errgroup.WithContext(gctx)
		connectors.SetLimit(8)
		for i := range nodes {
			if nodes[i].DeletedAt == nil {
				connectors.Go(func() (err error) {
					nodes[i].Connectors, err = client.ListMeshConnectors(cctx, account, nodes[i].ID)
					return err
				})
			}
		}
		return connectors.Wait()
	})
	if err := g.Wait(); err != nil {
		return nil, err
	}
	// Learn live associations before using remembered offline registrations.
	for _, n := range nodes {
		for _, c := range n.Connectors {
			state.Remember(account, n.ID, c.ID)
		}
	}
	for i := range nodes {
		if nodes[i].DeletedAt != nil || len(nodes[i].Connectors) > 0 {
			continue
		}
		for _, id := range state.Registrations(account, nodes[i].ID) {
			nodes[i].Connectors = append(nodes[i].Connectors, cfapi.MeshConnector{ID: id})
		}
	}
	if err := state.Save(); err != nil {
		return nil, fmt.Errorf("save Mesh node state: %w", err)
	}
	devices := mergeMeshDevices(registrations, physical, nodes, now)
	// The account listing still works when WARP is absent or not enrolled here.
	if local != nil {
		info, err := local.Registration(ctx)
		if err == nil {
			markThisMachine(devices, info)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return devices, nil
}

func mergeMeshDevices(registrations []cfapi.Registration, physical []cfapi.PhysicalDevice, nodes []cfapi.MeshNode, now time.Time) []meshDevice {
	devices := make([]meshDevice, 0, len(registrations)+len(physical)+len(nodes))
	byID := make(map[string]cfapi.PhysicalDevice, len(physical))
	for _, p := range physical {
		byID[p.ID] = p
	}
	seen := map[string]bool{}
	nodeByRegistration := map[string]cfapi.MeshNode{}
	joinedNodes := map[string]bool{}
	for _, n := range nodes {
		if n.DeletedAt != nil {
			continue
		}
		for _, connector := range n.Connectors {
			nodeByRegistration[connector.ID] = n
		}
	}
	for _, r := range registrations {
		if r.DeletedAt != nil || r.RevokedAt != nil || (r.RegistrationType != "" && r.RegistrationType != "warp") {
			continue
		}
		p := byID[r.Device.ID]
		if p.DeletedAt != nil {
			continue
		}
		seen[r.Device.ID] = true
		name := r.Device.Name
		if p.Name != "" {
			name = p.Name
		}
		owner := ownerName(r.User)
		if owner == "" {
			owner = ownerName(p.LastSeenUser)
		}
		d := meshDevice{ID: r.ID, DeviceID: r.Device.ID, Kind: "device", Name: name, User: owner, OwnerEmail: r.User.Email, IPv4: r.VirtualIPv4, IPv6: r.VirtualIPv6, OS: p.DeviceType, LastSeenAt: r.LastSeenAt, Online: recentlySeen(r.LastSeenAt, now)}
		n, ok := nodeByRegistration[r.ID]
		if !ok {
			n, ok = nodeByRegistration[r.Device.ID]
		}
		if ok {
			d.ID, d.RegistrationID, d.Kind, d.Name, d.User, d.OS = n.ID, r.ID, "node", n.Name, "Mesh node", "linux"
			d.Online = n.Status == "healthy" || n.Status == "degraded"
			d.ConnectionState = n.Status
			joinedNodes[n.ID] = true
		}
		devices = append(devices, d)
	}
	for _, p := range physical {
		if seen[p.ID] || p.DeletedAt != nil {
			continue
		}
		devices = append(devices, meshDevice{ID: p.ID, DeviceID: p.ID, Kind: "device", Name: p.Name, User: ownerName(p.LastSeenUser), OS: p.DeviceType, LastSeenAt: p.LastSeenAt, Online: recentlySeen(p.LastSeenAt, now)})
	}
	// Keep nodes without a current registration visible, including offline nodes.
	for _, n := range nodes {
		if n.DeletedAt != nil || joinedNodes[n.ID] {
			continue
		}
		online := n.Status == "healthy" || n.Status == "degraded"
		devices = append(devices, meshDevice{ID: n.ID, Kind: "node", Name: n.Name, User: "Mesh node", OS: "linux", Online: online, LastSeenAt: n.ConnsInactiveAt, ConnectionState: n.Status})
	}
	for i := range devices {
		devices[i].OnlineSource = "cloudflare"
	}
	sort.Slice(devices, func(i, j int) bool {
		a, b := devices[i], devices[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
	return devices
}

func ownerName(user cfapi.User) string {
	if user.Email != "" {
		return user.Email
	}
	return user.Name
}

func recentlySeen(last *time.Time, now time.Time) bool {
	return last != nil && now.Sub(*last) <= 5*time.Minute
}

func markThisMachine(devices []meshDevice, info warpcli.RegistrationInfo) {
	// macOS labels its active registration UUID "Device ID". Prefer a direct
	// registration match before treating it as a physical-device identifier.
	if info.RegistrationID == "" && info.DeviceID != "" {
		for _, device := range devices {
			if device.ID == info.DeviceID || device.RegistrationID == info.DeviceID {
				info.RegistrationID = info.DeviceID
				break
			}
		}
	}
	// An explicit registration ID identifies only that enrollment, even when
	// several registrations on the same physical device are still present.
	for i := range devices {
		d := &devices[i]
		if d.Kind == "node" {
			switch {
			case info.ConnectorID != "":
				d.ThisMachine = d.ID == info.ConnectorID
			case info.RegistrationID != "":
				d.ThisMachine = d.RegistrationID == info.RegistrationID
			case info.DeviceID != "":
				d.ThisMachine = d.DeviceID == info.DeviceID
			case info.ID != "":
				d.ThisMachine = d.RegistrationID == info.ID || d.DeviceID == info.ID
			}
		} else if info.RegistrationID != "" {
			d.ThisMachine = d.ID == info.RegistrationID
		} else if info.DeviceID != "" {
			d.ThisMachine = d.DeviceID == info.DeviceID
		} else if info.ID != "" {
			d.ThisMachine = d.ID == info.ID || d.DeviceID == info.ID
		}
	}
}

func writeStatus(out io.Writer, devices []meshDevice, asJSON bool, now time.Time) error {
	if asJSON {
		if devices == nil {
			devices = []meshDevice{}
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(devices)
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "MESH IP\tDEVICE\tDNS NAME\tUSER/OWNER\tOS\tSTATUS\tSSH MODE\tSECURE\tEXIT NODE\tSECURE TCP"); err != nil {
		return err
	}
	for _, d := range devices {
		ip := d.IPv4
		if ip == "" {
			ip = d.IPv6
		}
		name := d.Name
		if d.ThisMachine {
			name += " (this machine)"
			if d.Backend != "" {
				name += " [" + d.Backend + "]"
			}
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", tableField(ip), tableField(name), tableField(d.DNSName), tableField(d.User), tableField(d.OS), deviceState(d, now), tableField(deviceSSHStatus(d)), secureState(d.Secure), tableField(exitState(d)), tableField(d.SecureTCP)); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if len(devices) == 0 {
		_, err := fmt.Fprintln(out, "No Mesh devices found.")
		return err
	}
	for _, d := range devices {
		if len(d.Routes) > 0 {
			if _, err := fmt.Fprintf(out, "Subnet routes via %s: %s\n", tableField(d.Name), tableField(strings.Join(d.Routes, ", "))); err != nil {
				return err
			}
		}
	}
	return nil
}

// tableField also blanks bidirectional controls, which can make a hostile
// account name display as a different one.
func tableField(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return ' '
		}
		return r
	}, s)
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func deviceState(d meshDevice, now time.Time) string {
	if d.Online {
		if d.ConnectionState == "degraded" {
			return "online (degraded)"
		}
		return "online"
	}
	if d.LastSeenAt == nil {
		return "offline"
	}
	age := now.Sub(*d.LastSeenAt)
	if age < time.Minute {
		return "last seen just now"
	}
	if age < time.Hour {
		return fmt.Sprintf("last seen %dm ago", int(age/time.Minute))
	}
	if age < 24*time.Hour {
		return fmt.Sprintf("last seen %dh ago", int(age/time.Hour))
	}
	return fmt.Sprintf("last seen %dd ago", int(age/(24*time.Hour)))
}

func deviceSSHStatus(d meshDevice) string {
	if d.SSHPolicy != "" && d.SSHPolicy != "configured" {
		return "SSH: " + d.SSHPolicy
	}
	return d.SSHMode
}
