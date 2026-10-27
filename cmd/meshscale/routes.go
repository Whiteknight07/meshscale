package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
	"github.com/Whiteknight07/meshscale/internal/routes"
)

func init() {
	register(&command{name: "routes", short: "advertise, list, or remove Mesh subnet routes", run: runRoutes})
}

func runRoutes(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshscale routes advertise <cidr>[,<cidr>] [--node name] [--dry-run] | list | remove <cidr> [--dry-run]")
	}
	action := args[0]
	fs := flag.NewFlagSet("routes "+action, flag.ContinueOnError)
	node := ""
	dry := false
	switch action {
	case "advertise":
		fs.StringVar(&node, "node", "", "Mesh node name (default: this machine)")
		fs.BoolVar(&dry, "dry-run", false, "show the API request without writing")
	case "remove":
		fs.BoolVar(&dry, "dry-run", false, "show the route without deleting")
	case "list":
	default:
		return fmt.Errorf("unknown routes command %q", action)
	}
	// Accept flags on either side of the CIDR, matching the documented syntax.
	rest := args[1:]
	cidr := ""
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		cidr = rest[0]
		rest = rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if cidr == "" && fs.NArg() == 1 {
		cidr = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return fmt.Errorf("unexpected routes arguments")
	}
	if action == "list" && cidr != "" || action != "list" && cidr == "" {
		return fmt.Errorf("routes %s: expected %s", action, map[bool]string{true: "no CIDR", false: "a CIDR"}[action == "list"])
	}
	var prefixesValue string
	if action != "list" {
		prefixesValue = cidr
		if _, err := routes.Parse(cidr); err != nil {
			return err
		}
	}
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	client := cfapi.New(tokens, version)
	existing, err := client.ListRoutes(ctx, account)
	if err != nil {
		return err
	}
	if action == "list" {
		return writeRoutes(os.Stdout, existing)
	}
	prefixes, _ := routes.Parse(prefixesValue)
	if action == "remove" {
		if len(prefixes) != 1 {
			return fmt.Errorf("routes remove accepts one CIDR")
		}
		route, err := routes.Removal(prefixes[0], existing)
		if err != nil {
			return err
		}
		if dry {
			return writeRuleJSON(os.Stdout, route)
		}
		if err := client.DeleteRoute(ctx, account, route.ID); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "Removed route:", route.Network)
		return nil
	}
	devices, settings, err := routeDevices(ctx, client, account)
	if err != nil {
		return err
	}
	selected, err := routeNode(devices, node)
	if err != nil {
		return err
	}
	if selected.ThisMachine {
		if settings.Backend == "native" && settings.Userspace {
			return fmt.Errorf("native userspace mode cannot forward a subnet; use a Linux TUN or official Mesh node")
		}
		if runtime.GOOS != "linux" {
			return fmt.Errorf("subnet advertisement requires a Linux Mesh node")
		}
		for _, p := range prefixes {
			if settings.Backend == "native" && p.Addr().Is6() {
				return fmt.Errorf("IPv6 subnet routes require an official MASQUE node; native uses WireGuard")
			}
			if err := checkForwarding(os.Stderr, p.Addr().Is6(), os.ReadFile); err != nil {
				return err
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "On node %s, check IPv4 forwarding: sysctl net.ipv4.ip_forward (enable with sudo sysctl -w net.ipv4.ip_forward=1). For IPv6 use sudo sysctl -w net.ipv6.conf.all.forwarding=1.\n", tableField(selected.Name))
	}
	creates, err := routes.Plan(prefixes, selected.ID, existing)
	if err != nil {
		return err
	}
	if dry {
		if creates == nil {
			creates = []cfapi.CreateRouteParams{}
		}
		return writeRuleJSON(os.Stdout, creates)
	}
	for _, p := range creates {
		route, err := client.CreateRoute(ctx, account, p)
		if err != nil {
			return fmt.Errorf("advertise %s: %w; earlier creates may have succeeded (routes list / routes remove)", p.Network, err)
		}
		fmt.Fprintf(os.Stdout, "Advertised %s via %s (route %s).\n", route.Network, tableField(selected.Name), route.ID)
	}
	if len(creates) == 0 {
		fmt.Fprintln(os.Stdout, "Routes already advertised; no changes.")
	}
	fmt.Fprintf(os.Stdout, "Return route: on the subnet's gateway, route %s via this Mesh node's LAN IP. Include the advertised subnet in the node's and clients' Cloudflare Split Tunnels. See docs/routes.md.\n", meshaddr.IPv4Range)
	return nil
}

func routeDevices(ctx context.Context, client *cfapi.Client, account string) ([]meshDevice, *config.BackendSettings, error) {
	state, err := config.LoadMeshState()
	if err != nil {
		return nil, nil, err
	}
	local, settings, err := selectedBackend()
	if err != nil {
		return nil, nil, err
	}
	devices, err := loadMeshDevices(ctx, client, account, local, time.Now(), state)
	return devices, settings, err
}

func routeNode(devices []meshDevice, name string) (meshDevice, error) {
	var candidates []meshDevice
	for _, d := range devices {
		if d.Kind == "node" && (name != "" && d.Name == name || name == "" && d.ThisMachine) {
			candidates = append(candidates, d)
		}
	}
	if len(candidates) != 1 {
		return meshDevice{}, fmt.Errorf("expected one Mesh node for %q, found %d; use --node with a unique name from status", name, len(candidates))
	}
	return candidates[0], nil
}

func checkForwarding(out io.Writer, ipv6 bool, readFile func(string) ([]byte, error)) error {
	path, key := "/proc/sys/net/ipv4/ip_forward", "net.ipv4.ip_forward"
	if ipv6 {
		path, key = "/proc/sys/net/ipv6/conf/all/forwarding", "net.ipv6.conf.all.forwarding"
	}
	data, err := readFile(path)
	if err != nil {
		return fmt.Errorf("check forwarding (%s): %w; verify on the subnet router with sysctl %s", path, err, key)
	}
	if strings.TrimSpace(string(data)) != "1" {
		_, err = fmt.Fprintf(out, "IP forwarding is disabled. Enable it on this subnet router with: sudo sysctl -w %s=1\n", key)
	}
	return err
}

func writeRoutes(out io.Writer, entries []cfapi.Route) error {
	entries = append([]cfapi.Route(nil), entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Network < entries[j].Network })
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SUBNET\tNODE\tMANAGED\tROUTE ID\tCOMMENT")
	for _, r := range entries {
		if r.DeletedAt != nil {
			continue
		}
		node := r.TunnelName
		if node == "" {
			node = r.TunnelID
		}
		fmt.Fprintf(w, "%s\t%s\t%t\t%s\t%s\n", tableField(r.Network), tableField(node), routes.Owned(r), tableField(r.ID), tableField(r.Comment))
	}
	return w.Flush()
}

func assignRoutes(devices []meshDevice, entries []cfapi.Route) {
	for i := range devices {
		if devices[i].Kind != "node" {
			continue
		}
		for _, r := range entries {
			if r.DeletedAt == nil && r.TunnelID == devices[i].ID {
				devices[i].Routes = append(devices[i].Routes, r.Network)
			}
		}
		sort.Strings(devices[i].Routes)
	}
}
