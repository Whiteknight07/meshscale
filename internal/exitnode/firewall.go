package exitnode

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Whiteknight07/meshscale/internal/secure"
)

func nftSet(values []string) string { sort.Strings(values); return strings.Join(values, ", ") }
func GuardRules(p Plan) string {
	var b strings.Builder
	for _, chain := range []string{"output", "forward"} {
		fmt.Fprintf(&b, " chain %s {\n type filter hook %s priority -150; policy accept;\n", chain, chain)
		if chain == "forward" {
			// Only tunnel replies may return to a client container outside the tunnel.
			b.WriteString(" iifname \"meshsecure0\" ct state established,related accept\n")
		}
		b.WriteString(guardEgress(p))
		b.WriteString(" }\n")
	}
	// Defaults authorize Internet reply sources, never arbitrary secure identities.
	for _, f := range []struct {
		name, kind string
		ips        []netip.Addr
	}{{"identities4", "ip", p.Identities4}, {"identities6", "ip6", p.Identities6}} {
		dataType := "ipv4_addr"
		if f.kind == "ip6" {
			dataType = "ipv6_addr"
		}
		fmt.Fprintf(&b, " set %s { type %s;", f.name, dataType)
		values := []string{}
		for _, ip := range f.ips {
			values = append(values, ip.String())
		}
		if len(values) > 0 {
			fmt.Fprintf(&b, " elements = { %s };", nftSet(values))
		}
		b.WriteString(" }\n")
	}
	b.WriteString(" chain identity_input { type filter hook input priority -200; policy accept;\n")
	b.WriteString(" iifname \"meshsecure0\" ip saddr 10.192.0.0/10 ip saddr != @identities4 counter drop\n")
	fmt.Fprintf(&b, " iifname \"meshsecure0\" ip6 saddr %s ip6 saddr != @identities6 counter drop\n", secure.OverlayRange)
	b.WriteString(" }\n")
	return b.String()
}

func guardEgress(p Plan) string {
	var b strings.Builder
	b.WriteString(" oifname \"lo\" accept\n oifname \"meshsecure0\" accept\n")
	for _, m := range p.Marks {
		fmt.Fprintf(&b, " meta mark & %s == %s accept\n", m.Mask, m.Value)
	}
	for _, e := range p.Exceptions {
		family := "ip"
		if e.Family == "-6" {
			family = "ip6"
		}
		fmt.Fprintf(&b, " %s daddr %s oifname %s accept\n", family, e.Route.Dst, strconv.Quote(e.Route.Dev))
	}
	for _, e := range p.Control {
		family := "ip"
		if e.Family == "-6" {
			family = "ip6"
		}
		fmt.Fprintf(&b, " %s daddr %s oifname %s tcp dport 443 accept\n", family, e.Route.Dst, strconv.Quote(e.Route.Dev))
	}
	for _, e := range p.WARP {
		if e.Route.Type == "unreachable" {
			continue
		}
		family := "ip"
		if e.Family == "-6" {
			family = "ip6"
		}
		fmt.Fprintf(&b, " %s daddr %s oifname %s udp dport { 443, 500, 1701, 4500, 4443, 8095, 8443 } accept\n", family, e.Route.Dst, strconv.Quote(e.Route.Dev))
	}
	for _, ip := range p.SSH {
		family := "ip"
		if ip.Is6() {
			family = "ip6"
		}
		fmt.Fprintf(&b, " %s daddr %s accept\n", family, ip)
	}
	for _, ip := range p.DNS {
		family := "ip"
		if ip.Is6() {
			family = "ip6"
		}
		fmt.Fprintf(&b, " %s daddr %s meta l4proto { tcp, udp } th dport 53 accept\n", family, ip)
	}
	// Essential address/underlay maintenance does not grant general LAN access.
	b.WriteString(" udp sport 68 udp dport 67 accept\n udp sport 546 udp dport 547 accept\n meta l4proto ipv6-icmp icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept\n counter reject with icmpx type admin-prohibited\n")
	return b.String()
}

type ForwardPlan struct {
	Uplink4, Uplink6     string
	Identity4, Identity6 netip.Addr
	Sources4, Sources6   []netip.Addr
	Block4, Block6       []netip.Prefix
	MSS                  int
}

func ForwardRules(p ForwardPlan) string {
	var b strings.Builder
	for _, f := range []struct {
		name, kind string
		ips        []netip.Addr
	}{{"clients4", "ipv4_addr", p.Sources4}, {"clients6", "ipv6_addr", p.Sources6}} {
		values := []string{}
		for _, ip := range f.ips {
			values = append(values, ip.String())
		}
		fmt.Fprintf(&b, " set %s { type %s;", f.name, f.kind)
		if len(values) > 0 {
			fmt.Fprintf(&b, " elements = { %s };", nftSet(values))
		}
		b.WriteString(" }\n")
	}
	b.WriteString(" chain forward {\n type filter hook forward priority -200; policy accept;\n")
	// Exit access never exposes private/metadata/LAN networks at the exit.
	b.WriteString(" iifname \"meshsecure0\" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } counter drop\n iifname \"meshsecure0\" ip6 daddr { ::/128, ::1/128, fc00::/7, fe80::/10, ff00::/8 } counter drop\n")
	for _, f := range []struct {
		kind     string
		prefixes []netip.Prefix
	}{{"ip", p.Block4}, {"ip6", p.Block6}} {
		for _, prefix := range f.prefixes {
			fmt.Fprintf(&b, " iifname \"meshsecure0\" %s daddr %s counter drop\n", f.kind, prefix)
		}
	}
	for _, f := range []struct{ kind, set, uplink string }{{"ip", "clients4", p.Uplink4}, {"ip6", "clients6", p.Uplink6}} {
		fmt.Fprintf(&b, " iifname != \"meshsecure0\" %s saddr @%s counter drop\n", f.kind, f.set)
		if f.uplink != "" {
			fmt.Fprintf(&b, " iifname \"meshsecure0\" oifname %s %s saddr @%s counter accept\n", strconv.Quote(f.uplink), f.kind, f.set)
			fmt.Fprintf(&b, " iifname %s oifname \"meshsecure0\" %s daddr @%s ct state established,related counter accept\n", strconv.Quote(f.uplink), f.kind, f.set)
		}
	}
	b.WriteString(" iifname \"meshsecure0\" counter drop\n oifname \"meshsecure0\" counter drop\n }\n")
	b.WriteString(" chain input { type filter hook input priority -200; policy accept;\n ip saddr @clients4 iifname != \"meshsecure0\" drop\n ip6 saddr @clients6 iifname != \"meshsecure0\" drop\n")
	if p.Identity4.Is4() {
		fmt.Fprintf(&b, " iifname \"meshsecure0\" ip daddr %s accept\n", p.Identity4)
	}
	if p.Identity6.Is6() {
		fmt.Fprintf(&b, " iifname \"meshsecure0\" ip6 daddr %s accept\n", p.Identity6)
	}
	b.WriteString(" iifname \"meshsecure0\" ip daddr { 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } counter drop\n iifname \"meshsecure0\" ip6 daddr { ::1/128, fc00::/7, fe80::/10 } counter drop\n }\n")
	b.WriteString(" chain postrouting { type nat hook postrouting priority srcnat; policy accept;\n")
	for _, f := range []struct{ kind, set, uplink string }{{"ip", "clients4", p.Uplink4}, {"ip6", "clients6", p.Uplink6}} {
		if f.uplink != "" {
			fmt.Fprintf(&b, " iifname \"meshsecure0\" oifname %s %s saddr @%s counter masquerade\n", strconv.Quote(f.uplink), f.kind, f.set)
		}
	}
	b.WriteString(" }\n chain mss { type filter hook forward priority mangle; policy accept;\n")
	for _, dir := range []string{"iifname", "oifname"} {
		fmt.Fprintf(&b, " %s \"meshsecure0\" tcp flags & (syn | rst) == syn tcp option maxseg size > %d tcp option maxseg size set %d\n", dir, p.MSS, p.MSS)
	}
	b.WriteString(" }\n")
	return b.String()
}

// ErrFirewalldUnavailable means firewalld is not running, so it imposes no
// zone or forwarding requirements.
var ErrFirewalldUnavailable = errors.New("firewalld is unavailable")

// Firewall checks existing firewalld runtime readiness without reloading it or
// changing administrator zones. The owned nft chain authenticates source and
// interface, limits uplinks/destinations and installs NAT/MSS independently.
//
// Lookups are cached only while Watch runs, because firewalld's signals are
// what invalidate the cache.
type Firewall struct {
	DBus FirewalldClient

	mu         sync.Mutex
	watching   bool
	generation uint64
	zones      map[string]string
	forwarding map[string]bool
}

func (f *Firewall) client() FirewalldClient {
	if f.DBus == nil {
		f.DBus = FirewalldDBus{}
	}
	return f.DBus
}

// Watch reports firewalld changes until ctx ends and caches lookups while the
// signal connection is alive.
func (f *Firewall) Watch(ctx context.Context) (<-chan struct{}, error) {
	signals, err := f.client().Watch(ctx)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.watching = true
	f.mu.Unlock()
	out := make(chan struct{}, 1)
	go func() {
		defer close(out)
		for range signals {
			f.Invalidate()
			queueEvent(out)
		}
		// The bus connection died: stop caching, but leave out open so callers
		// merging it with other sources keep those.
		f.mu.Lock()
		f.watching = false
		f.mu.Unlock()
		f.Invalidate()
		<-ctx.Done()
	}()
	return out, nil
}

// Invalidate clears cached D-Bus state after any firewalld change.
func (f *Firewall) Invalidate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.generation++
	f.zones = nil
	f.forwarding = nil
}

func (f *Firewall) Reconcile(ctx context.Context, p ForwardPlan) error {
	ingress, err := f.zone(ctx, "meshsecure0")
	if err != nil {
		if errors.Is(err, ErrFirewalldUnavailable) {
			return nil
		}
		return err
	}
	for _, uplink := range []string{p.Uplink4, p.Uplink6} {
		if uplink == "" {
			continue
		}
		egress, err := f.zone(ctx, uplink)
		if err != nil {
			return err
		}
		if egress != ingress {
			return fmt.Errorf("firewalld requires meshsecure0 and uplink %s to share a zone with intra-zone forwarding (currently %s and %s); configure zones explicitly", uplink, ingress, egress)
		}
	}
	forwarding, err := f.zoneForwarding(ctx, ingress)
	if err != nil || !forwarding {
		if err != nil {
			return fmt.Errorf("firewalld zone %s needs intra-zone forwarding: %w", ingress, err)
		}
		return fmt.Errorf("firewalld zone %s needs administrator-enabled intra-zone forwarding", ingress)
	}
	return nil
}

func (f *Firewall) zone(ctx context.Context, dev string) (string, error) {
	zone, err := cachedLookup(f, &f.zones, dev, func() (string, error) { return f.client().Zone(ctx, dev) })
	if err != nil {
		return "", fmt.Errorf("inspect firewalld zone of %s: %w", dev, err)
	}
	if zone == "" {
		return "", fmt.Errorf("missing firewalld zone for %s", dev)
	}
	return zone, nil
}

func (f *Firewall) zoneForwarding(ctx context.Context, zone string) (bool, error) {
	return cachedLookup(f, &f.forwarding, zone, func() (bool, error) { return f.client().QueryForward(ctx, zone) })
}

// cachedLookup serves key from cache while Watch runs. A result loaded across
// an invalidation is returned but not stored.
func cachedLookup[K comparable, V any](f *Firewall, cache *map[K]V, key K, load func() (V, error)) (V, error) {
	f.mu.Lock()
	value, ok := (*cache)[key]
	watching, generation := f.watching, f.generation
	f.mu.Unlock()
	if ok && watching {
		return value, nil
	}
	value, err := load()
	if err != nil || !watching {
		return value, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.generation == generation {
		if *cache == nil {
			*cache = make(map[K]V)
		}
		(*cache)[key] = value
	}
	return value, nil
}

// Close has no resources to remove: readiness checks never mutate firewalld.
func (*Firewall) Close(context.Context) error { return nil }
