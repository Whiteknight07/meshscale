package exitnode

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
	"github.com/Whiteknight07/meshscale/internal/secure"
)

// Manager is owned by one supervisor goroutine. Client protection belongs to
// desired selection and is intentionally independent of Transport.Close.
type Manager struct {
	// Mutate serializes changes with CLI intent updates. Read-only health checks
	// and ordinary secure peer updates never acquire it.
	Mutate      func(func() error) error
	Dir         string
	Run         Runner
	NFT         Nftables
	Routes      RouteManager
	Firewall    Firewall
	Forwarding  Forwarding
	Reader      SnapshotReader
	recovery    func(context.Context, Runner, string, string) error
	PeerRoute   func(netip.Addr) error
	plan        *Plan
	forwardPlan *ForwardPlan
	forwarding  bool
	prepared    bool
}

func (m *Manager) mutate(apply func() error) error {
	if m.Mutate != nil {
		return m.Mutate(apply)
	}
	return apply()
}

func New(dir string) *Manager {
	run := Commands{}
	return &Manager{Dir: dir, Run: run, NFT: NFT{Run: run}, Routes: Routing{Run: run}, Firewall: Firewall{DBus: FirewalldDBus{}}, Forwarding: SysctlForwarding{}}
}

func (m *Manager) load() error {
	if m.plan != nil {
		return nil
	}
	var p Plan
	if err := localstate.Read(filepath.Join(m.Dir, "exit-routing.json"), &p); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if p.Table < 51840 || p.Table >= 52000 || p.Priority < 1 || p.Priority >= 32766 {
		return fmt.Errorf("invalid persisted exit routing ownership")
	}
	m.plan = &p
	return nil
}
func resolverIPs() ([]netip.Addr, error) {
	return resolverIPsFrom("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf")
}

func resolverIPsFrom(path, upstream string) ([]netip.Addr, error) {
	ips, err := readResolverIPs(path)
	if err != nil {
		return nil, err
	}
	stubOnly := len(ips) > 0
	for _, ip := range ips {
		if ip.String() != "127.0.0.53" && ip.String() != "127.0.0.54" {
			stubOnly = false
		}
	}
	if stubOnly {
		upstreams, err := readResolverIPs(upstream)
		if err != nil {
			return nil, err
		}
		ips = append(ips, upstreams...)
	}
	return ips, nil
}

func readResolverIPs(path string) ([]netip.Addr, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read existing resolver: %w", err)
	}
	var ips []netip.Addr
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) > 1 && f[0] == "nameserver" {
			ip, err := netip.ParseAddr(f[1])
			if err != nil {
				return nil, fmt.Errorf("existing resolver address: %w", err)
			}
			ips = append(ips, ip)
		}
	}
	return ips, nil
}
func (m *Manager) Prepare(ctx context.Context, c secure.Config) error {
	if err := m.load(); err != nil {
		return err
	}
	if c.ExitID == "" {
		return m.deselect(ctx)
	}
	return m.prepareSelection(ctx, c)
}

func (m *Manager) deselect(ctx context.Context) error {
	if m.plan == nil {
		return nil
	}
	return m.mutate(func() error { return m.removeSelection(ctx) })
}

func (m *Manager) removeSelection(ctx context.Context) error {
	// Explicit deselection removes capture first, then guard and recovery state.
	if err := m.Routes.Remove(ctx, *m.plan); err != nil {
		return err
	}
	if err := m.NFT.Remove(ctx, GuardTable); err != nil {
		return err
	}
	if err := removeRecovery(ctx, m.Run, m.Dir); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(m.Dir, "exit-routing.json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	m.plan = nil
	m.prepared = false
	return nil
}

func (m *Manager) prepareSelection(ctx context.Context, c secure.Config) error {
	p, err := m.selectionPlan(ctx, c)
	if err != nil {
		return err
	}
	return m.protectSelection(ctx, p)
}

func (m *Manager) selectionPlan(ctx context.Context, c secure.Config) (Plan, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || c.Userspace || c.Engine == "go" {
		return Plan{}, fmt.Errorf("exit nodes on Linux require root and kernel WireGuard; private userspace mode cannot route host traffic")
	}
	if !c.Enabled || c.AdvertiseExit {
		return Plan{}, fmt.Errorf("exit selection requires secure mode and cannot also advertise an exit")
	}
	endpoint, err := netip.ParseAddr(c.ExitMeshIP)
	if err != nil {
		return Plan{}, fmt.Errorf("persisted exit endpoint: %w", err)
	}
	if !meshaddr.IsIPv4(endpoint) {
		return Plan{}, fmt.Errorf("selected endpoint is outside Mesh")
	}
	// The validated local binding is supplied at selection and retained offline.
	source, err := netip.ParseAddr(c.IPv4)
	if err != nil {
		return Plan{}, fmt.Errorf("persisted local exit source: %w", err)
	}
	snapshot, err := inspect(ctx, m.Reader, m.Run)
	if err != nil {
		return Plan{}, err
	}
	snapshot.DNS, err = resolverIPs()
	if err != nil {
		return Plan{}, err
	}
	p, err := PlanRouting(snapshot, source, endpoint, c.AllowLAN, m.plan)
	if err != nil {
		return Plan{}, err
	}
	if m.plan != nil {
		p.Identities4 = append([]netip.Addr(nil), m.plan.Identities4...)
		p.Identities6 = append([]netip.Addr(nil), m.plan.Identities6...)
	}
	p.Source6, err = netip.ParseAddr(c.IPv6)
	if err != nil {
		return Plan{}, fmt.Errorf("persisted local IPv6 source: %w", err)
	}
	if !secure.IsIP(p.Source6) {
		return Plan{}, fmt.Errorf("selected exit source is outside secure IPv6 identities")
	}
	p.Control, err = m.selectionControls(ctx, snapshot, p)
	if err != nil {
		return Plan{}, err
	}
	if err := m.pinManagement(ctx, &p); err != nil {
		return Plan{}, err
	}

	return p, nil
}

func (m *Manager) selectionControls(ctx context.Context, snapshot Snapshot, p Plan) ([]Exception, error) {
	// On resolver replacement, first install the new DNS exception with the
	// previously authorized control endpoints. The next refresh resolves them
	// through that resolver; startup never depends on a still-blocked DNS path.
	if m.plan != nil && !reflect.DeepEqual(p.DNS, m.plan.DNS) && len(m.plan.Control) > 0 {
		return append([]Exception(nil), m.plan.Control...), nil
	}
	controls, err := selectionControlRoutes(ctx, snapshot, len(p.WARP) > 0)
	if err != nil && m.plan != nil && len(m.plan.Control) > 0 {
		controls = append([]Exception(nil), m.plan.Control...)
		err = nil
	}
	if err != nil {
		return nil, err
	}

	return controls, nil
}

func selectionControlRoutes(ctx context.Context, snapshot Snapshot, warp bool) ([]Exception, error) {
	// Directory/auth access remains available while the exit is unreachable.
	// These exact HTTPS destination exceptions are exposed in local status.
	var controls []netip.Addr
	for _, host := range []string{"api.cloudflare.com", "dash.cloudflare.com"} {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve exit control destination %s: %w", host, err)
		}
		for _, ip := range ips {
			// /etc/hosts answers arrive as IPv4-mapped IPv6; route the real family.
			controls = append(controls, ip.Unmap())
		}
	}
	if warp {
		controls = append(controls, warpControlIPs()...)
	}
	sort.Slice(controls, func(i, j int) bool { return controls[i].Less(controls[j]) })
	return ControlRoutes(snapshot, controls)
}

func (m *Manager) protectSelection(ctx context.Context, p Plan) error {
	if m.prepared && reflect.DeepEqual(m.plan, &p) {
		snapshot, err := inspect(ctx, m.Reader, m.Run)
		if err != nil {
			return err
		}
		installed, err := m.NFT.Installed(ctx, GuardTable)
		if err != nil {
			return fmt.Errorf("inspect exit guard table: %w", err)
		}
		if installed && p.installed(snapshot) {
			return nil
		}
	}
	return m.mutate(func() error { return m.installProtection(ctx, p) })
}

func (m *Manager) installProtection(ctx context.Context, p Plan) error {
	m.plan = nil
	m.prepared = false
	if err := localstate.Write(filepath.Join(m.Dir, "exit-routing.json"), p); err != nil {
		return err
	}
	body := GuardRules(p)
	// Persist recovery before activating capture; the runtime guard commits before
	// any route which might fall through to the physical default.
	recover := m.recovery
	if recover == nil {
		recover = installRecovery
	}
	if err := recover(ctx, m.Run, m.Dir, body); err != nil {
		return err
	}
	if err := m.NFT.Apply(ctx, GuardTable, body); err != nil {
		return err
	}
	if err := m.Routes.Exceptions(ctx, p); err != nil {
		return err
	}
	if err := m.Routes.Block(ctx, p); err != nil {
		return err
	}
	m.plan = &p
	m.prepared = true
	return nil
}

func (m *Manager) pinManagement(ctx context.Context, p *Plan) error {
	// Pin SSH paths before flushing any owned exception table. Refresh removes
	// obsolete sessions without changing the route of an existing one.
	for _, ip := range p.SSH {
		found := false
		if m.plan != nil {
			for _, e := range m.plan.Management {
				if e.Route.Dst == ip.String() {
					p.Management = append(p.Management, e)
					found = true
					break
				}
			}
		}
		if found {
			continue
		}
		family := "-4"
		if ip.Is6() {
			family = "-6"
		}
		out, err := m.Run.Run(ctx, "", "ip", "-j", family, "route", "get", ip.String())
		if err != nil {
			return err
		}
		route, err := decodeLookup(out)
		if err != nil {
			return err
		}
		if route.Dev == "meshsecure0" {
			return fmt.Errorf("cannot preserve SSH peer %s: original path is unavailable", ip)
		}
		route.Dst = ip.String()
		p.Management = append(p.Management, Exception{family, route})
	}

	return nil
}

func (m *Manager) Configure(ctx context.Context, engine secure.Engine, self secure.Peer, c secure.Config, peers []secure.Peer) error {
	tr, ok := engine.(*secure.Transport)
	if !ok {
		return fmt.Errorf("exit configuration requires a secure transport")
	}
	enabledV2 := self.ExitVersion == 2
	if !enabledV2 {
		return tr.Reconcile(peers)
	}
	return m.mutate(func() error { return m.configureV2(ctx, tr, self, c, peers) })
}

func (m *Manager) configureV2(ctx context.Context, tr *secure.Transport, self secure.Peer, c secure.Config, peers []secure.Peer) error {
	if tr.Mode != "kernel" {
		return fmt.Errorf("exit v2 needs Linux kernel WireGuard")
	}
	if !self.IPv4.Is4() {
		return fmt.Errorf("missing validated local IPv4 binding")
	}
	if err := m.configureSource(ctx, peers, self); err != nil {
		return err
	}
	if c.ExitID != "" && (self.IPv4.String() != c.IPv4 || self.IP.String() != c.IPv6) {
		return fmt.Errorf("local exit source binding changed; select the exit again")
	}
	selected := selectedExit(peers, self, c)
	configured, err := m.configurePeerRoutes(ctx, peers, self, selected)
	if err != nil {
		return err
	}
	tr.AuthorizeExit(configured, selected)
	if err := tr.Reconcile(configured); err != nil {
		return err
	}
	if c.ExitID != "" {
		if err := m.activateSelection(ctx, peers, self, selected); err != nil {
			return err
		}
	}
	if c.AdvertiseExit {
		hook := secure.ForwardingHook(func(ctx context.Context, _ string, peers []secure.Peer) (func(), error) {
			if err := m.Forward(ctx, self, peers, tr.MSS); err != nil {
				return nil, err
			}
			return func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				_ = m.StopForwarding(cleanup)
			}, nil
		})
		return tr.SetForwarding(ctx, hook, configured)
	}
	return nil
}

func (m *Manager) configureSource(ctx context.Context, peers []secure.Peer, self secure.Peer) error {
	snapshot, err := inspect(ctx, m.Reader, m.Run)
	if err != nil {
		return err
	}
	for _, peer := range peers {
		if !peer.IPv4.Is4() {
			continue
		}
		for _, route := range snapshot.V4.Routes {
			if route.Dev == "meshsecure0" {
				continue
			}
			prefix, err := route.prefix(false)
			if err == nil && prefix.Bits() > 0 && prefix.Contains(peer.IPv4) {
				return fmt.Errorf("secure source %s conflicts with route %s", peer.IPv4, route.Dst)
			}
		}
	}
	return configureSourceAddress(self)
}

func selectedExit(peers []secure.Peer, self secure.Peer, c secure.Config) string {
	selected := ""
	if c.ExitID != "" {
		for _, p := range peers {
			if p.RegistrationID == c.ExitID && p.PublicKey == c.ExitKey && p.OffersExit && secure.SameOwner(p, self) && p.MeshIP.String() == c.ExitMeshIP {
				selected = p.PublicKey
			}
		}
	}
	return selected
}

func (m *Manager) configurePeerRoutes(ctx context.Context, peers []secure.Peer, self secure.Peer, selected string) ([]secure.Peer, error) {
	configured := append([]secure.Peer(nil), peers...)
	ensureRoute := m.PeerRoute
	if ensureRoute == nil {
		var err error
		if ensureRoute, err = systemPeerRoute(); err != nil {
			return nil, err
		}
	}
	for i, p := range configured {
		configured[i].AllowedIPs = secure.ExitAllowedIPs(p, selected)
		if p.IPv4.Is4() && p.PublicKey != self.PublicKey {
			if err := ensureRoute(p.IPv4); err != nil {
				return nil, err
			}
		}
	}
	return configured, nil
}

func (m *Manager) activateSelection(ctx context.Context, peers []secure.Peer, self secure.Peer, selected string) error {
	if m.plan == nil {
		return fmt.Errorf("exit leak guard has not been installed")
	}
	next := *m.plan
	next.Identities4 = nil
	next.Identities6 = nil
	for _, peer := range peers {
		if peer.PublicKey == self.PublicKey {
			continue
		}
		if peer.IPv4.Is4() {
			next.Identities4 = append(next.Identities4, peer.IPv4)
		}
		next.Identities6 = append(next.Identities6, peer.IP)
	}
	if !reflect.DeepEqual(&next, m.plan) {
		body := GuardRules(next)
		if err := installRecovery(ctx, m.Run, m.Dir, body); err != nil {
			return err
		}
		if err := m.NFT.Apply(ctx, GuardTable, body); err != nil {
			return err
		}
		if err := localstate.Write(filepath.Join(m.Dir, "exit-routing.json"), next); err != nil {
			return err
		}
		m.plan = &next
	}

	// Even an unavailable exit keeps the terminal routes and guard. Never remove
	// desired selection or redirect to a same-name replacement.
	if selected != "" {
		if err := m.Routes.Activate(ctx, *m.plan, true); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Forward(ctx context.Context, self secure.Peer, peers []secure.Peer, mss int) error {
	if err := m.Forwarding.Check(ctx); err != nil {
		return err
	}
	snapshot, err := inspect(ctx, m.Reader, m.Run)
	if err != nil {
		return err
	}
	p := ForwardPlan{MSS: mss, Identity4: self.IPv4, Identity6: self.IP}
	for _, f := range []struct {
		family  Family
		uplink  *string
		blocked *[]netip.Prefix
		v6      bool
	}{{snapshot.V4, &p.Uplink4, &p.Block4, false}, {snapshot.V6, &p.Uplink6, &p.Block6, true}} {
		metric := 0
		for _, r := range f.family.Routes {
			if r.table() != "main" {
				continue
			}
			if r.Dst == "default" && snapshot.tunnelDefault(r.Dev) {
				return fmt.Errorf("exit uplink %s is a competing VPN", r.Dev)
			}
			if r.Dst == "default" && r.Dev != "CloudflareWARP" && r.Dev != "tailscale0" && r.Dev != "meshsecure0" {
				if *f.uplink == "" || r.Metric < metric {
					*f.uplink = r.Dev
					metric = r.Metric
				}
			}
			if r.Dst != "default" && r.Gateway == "" && r.Dev != "meshsecure0" {
				if prefix, err := r.prefix(f.v6); err == nil {
					*f.blocked = append(*f.blocked, prefix)
				}
			}
		}
	}
	if p.Uplink4 == "" {
		return fmt.Errorf("exit has no physical IPv4 uplink")
	}
	if !m.Forwarding.IPv6(ctx) {
		p.Uplink6 = ""
	}

	for _, peer := range peers {
		if peer.PublicKey != self.PublicKey && secure.SameOwner(self, peer) {
			if peer.IPv4.Is4() {
				p.Sources4 = append(p.Sources4, peer.IPv4)
			}
			p.Sources6 = append(p.Sources6, peer.IP)
		}
	}
	if m.forwarding && m.forwardPlan != nil && reflect.DeepEqual(*m.forwardPlan, p) {
		installed, err := m.NFT.Installed(ctx, ForwardTable)
		if err != nil {
			return fmt.Errorf("inspect exit forwarding table: %w", err)
		}
		if installed {
			return nil
		}
	}
	if err := m.NFT.Apply(ctx, ForwardTable, ForwardRules(p)); err != nil {
		return err
	}
	m.forwarding = true
	forwardPlan := p
	m.forwardPlan = &forwardPlan
	if err := m.Firewall.Reconcile(ctx, p); err != nil {
		_ = m.StopForwarding(ctx)
		return fmt.Errorf("exit firewall readiness: %w", err)
	}
	return nil
}
func (m *Manager) StopForwarding(ctx context.Context) error {
	if !m.forwarding {
		return nil
	}
	err := errors.Join(m.Firewall.Close(ctx), m.NFT.Remove(ctx, ForwardTable))
	if err == nil {
		m.forwarding = false
		m.forwardPlan = nil
	}
	return err
}

func (m *Manager) Exceptions() []string {
	if m.plan == nil {
		return nil
	}
	var result []string
	for _, e := range m.plan.Exceptions {
		result = append(result, e.Route.Dst+" via "+e.Route.Dev)
	}
	for _, e := range m.plan.Control {
		result = append(result, e.Route.Dst+" HTTPS control via "+e.Route.Dev)
	}
	for _, e := range m.plan.WARP {
		if e.Route.Type == "unreachable" {
			result = append(result, e.Route.Dst+" WARP transport blocked: no physical uplink")
			continue
		}
		result = append(result, e.Route.Dst+" WARP UDP transport/probes via "+e.Route.Dev+" (443,500,1701,4500,4443,8095,8443)")
	}
	for _, e := range m.plan.Management {
		result = append(result, e.Route.Dst+" SSH management via "+e.Route.Dev)
	}
	for _, ip := range m.plan.DNS {
		result = append(result, ip.String()+" existing DNS")
	}
	return result
}
