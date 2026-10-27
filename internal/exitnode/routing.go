package exitnode

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/secureroute"
)

type Exception struct {
	Family string
	Route  Route
}
type Mark struct{ Value, Mask string }
type Plan struct {
	Source6                  netip.Addr
	Table, Priority          int
	Exceptions               []Exception
	Management               []Exception
	Control                  []Exception
	WARP                     []Exception
	Gateways                 []Exception
	Marks                    []Mark
	DNS, SSH                 []netip.Addr
	Identities4, Identities6 []netip.Addr
	LAN                      []netip.Prefix
	Source                   netip.Addr
	Endpoint                 netip.Addr
}

// PlanRouting allocates an unused table pair and priority block. All underlay
// destinations are copied explicitly; connected LAN routes are opt-in.
func PlanRouting(s Snapshot, source, endpoint netip.Addr, allowLAN bool, owned *Plan) (Plan, error) {
	p := Plan{Source: source, Endpoint: endpoint, DNS: s.DNS, SSH: s.SSH}
	if !source.Is4() || !endpoint.Is4() {
		return p, fmt.Errorf("exit routing requires validated IPv4 source and Mesh endpoint")
	}
	used := map[int]bool{}
	priorities := map[int]bool{}
	first := 32766
	for _, f := range []Family{s.V4, s.V6} {
		for _, r := range f.Routes {
			id, _ := strconv.Atoi(r.table())
			used[id] = true
			prefix, err := r.prefix(strings.Contains(r.Dst, ":"))
			if err != nil {
				continue
			}
			if r.Dev != "meshsecure0" && prefix.Bits() > 0 && prefix.Contains(source) && (owned == nil || id != owned.Table && id != owned.Table+1) {
				return p, fmt.Errorf("secure IPv4 %s conflicts with existing route %s", source, r.Dst)
			}
			if r.Dst == "default" && (s.tunnelDefault(r.Dev) && r.Dev != "meshsecure0" || r.Dev == "tailscale0" || r.Dev == "CloudflareWARP" || r.table() != "main" && (owned == nil || id != owned.Table+1)) {
				return p, fmt.Errorf("competing default route in table %s on %s", r.table(), r.Dev)
			}
		}
		for _, r := range f.Rules {
			if owned != nil && r.Priority >= owned.Priority && r.Priority < owned.Priority+16 {
				if r.Protocol != "242" {
					return p, fmt.Errorf("exit rule priority %d was claimed by another owner", r.Priority)
				}
				continue
			}
			id, _ := strconv.Atoi(fmt.Sprint(r.Table))
			used[id] = true
			priorities[r.Priority] = true
			if r.Priority > 0 && r.Priority < first {
				first = r.Priority
			}
			if r.FWMark != "" && (len(r.Not) > 0 || fmt.Sprint(r.Table) == "main") {
				mask := r.FWMask
				if mask == "" {
					mask = "0xffffffff"
				}
				m := Mark{r.FWMark, mask}
				if !slices.Contains(p.Marks, m) {
					p.Marks = append(p.Marks, m)
				}
			}
		}
	}
	if owned != nil {
		p.Table, p.Priority = owned.Table, owned.Priority
	} else {
		for id := 51840; id < 52000; id += 2 {
			if !used[id] && !used[id+1] {
				p.Table = id
				break
			}
		}
		for pr := first - 32; pr > 0; pr -= 16 {
			free := true
			for i := 0; i < 16; i++ {
				if priorities[pr+i] {
					free = false
				}
			}
			if free {
				p.Priority = pr
				break
			}
		}
	}
	// WARP removes its own policy rules while reconnecting. Keep the previously
	// validated carrier marks so its sockets can still rebuild the tunnel.
	if owned != nil {
		for _, mark := range owned.Marks {
			if !slices.Contains(p.Marks, mark) {
				p.Marks = append(p.Marks, mark)
			}
		}
	}
	if p.Table == 0 || p.Priority == 0 || len(p.Marks) > 4 {
		return p, fmt.Errorf("no free exit routing resources or too many carrier marks")
	}
	for _, f := range []struct {
		family Family
		flag   string
		v6     bool
	}{{s.V4, "-4", false}, {s.V6, "-6", true}} {
		for _, r := range f.family.Routes {
			if r.table() == strconv.Itoa(p.Table) || r.table() == strconv.Itoa(p.Table+1) {
				continue
			}
			if r.table() == "local" || r.Type != "" && r.Type != "unicast" || r.Dst == "default" {
				continue
			}
			prefix, err := r.prefix(f.v6)
			if err != nil {
				continue
			}
			trusted := r.Dev == "CloudflareWARP" || r.Dev == "tailscale0" || r.Dev == "meshscale0" || r.Dev == "meshsecure0"
			lan := allowLAN && r.table() == "main" && r.Gateway == "" && r.Dev != "lo" && r.Dev != "" && !trusted
			if trusted || lan {
				p.Exceptions = append(p.Exceptions, Exception{f.flag, r})
				if lan {
					p.LAN = append(p.LAN, prefix)
				}
			}
		}
	}
	p.Gateways = physicalGateways(s)
	p.WARP = warpUnderlay(s, owned)
	return p, nil
}

// RouteManager owns only the resources allocated by a persisted plan.
type RouteManager interface {
	Block(context.Context, Plan) error
	Exceptions(context.Context, Plan) error
	Activate(context.Context, Plan, bool) error
	Remove(context.Context, Plan) error
}

type Routing struct {
	Run    Runner
	Reader SnapshotReader
}

func (r Routing) command(ctx context.Context, family string, args ...string) error {
	_, err := r.Run.Run(ctx, "", "ip", append([]string{family}, args...)...)
	return err
}

// installSecureRoute makes route-local tuning an explicit choice at each call site.
func (r Routing) installSecureRoute(ctx context.Context, family string, args ...string) error {
	return secureroute.Install(secureroute.FromRunner(ctx, r.Run), append([]string{family}, args...)...)
}
func (r Routing) installException(ctx context.Context, family, dev string, args ...string) error {
	if dev == "meshsecure0" {
		return r.installSecureRoute(ctx, family, args...)
	}
	return r.command(ctx, family, args...)
}
func (rule Rule) args() []string {
	args := []string{"priority", strconv.Itoa(rule.Priority), "protocol", "242"}
	if rule.FWMark != "" {
		mask := rule.FWMask
		if mask == "" {
			mask = "0xffffffff"
		}
		args = append(args, "fwmark", rule.FWMark+"/"+mask)
	}
	if rule.Dst != "" {
		dst := rule.Dst
		if rule.DstLen != 0 {
			dst += "/" + strconv.Itoa(rule.DstLen)
		}
		args = append(args, "to", dst)
	}
	if rule.IPProto != "" {
		args = append(args, "ipproto", rule.IPProto, "dport", strconv.Itoa(int(rule.DPort)))
	}
	if rule.Action != "" {
		return append(args, rule.Action)
	}
	return append(args, "lookup", fmt.Sprint(rule.Table))
}

func (p Plan) rules(family string) []Rule {
	var rules []Rule
	priority := p.Priority
	for _, mark := range p.Marks {
		mask := mark.Mask
		if mask == "0xffffffff" {
			mask = "" // ip -j omits a full mask
		}
		rules = append(rules, Rule{Priority: priority, Protocol: "242", Table: "main", FWMark: mark.Value, FWMask: mask})
		priority++
		rules = append(rules, Rule{Priority: priority, Protocol: "242", Action: "unreachable", FWMark: mark.Value, FWMask: mask})
		priority++
	}
	// Multiple resolvers share each protocol's priority in the reserved block.
	for _, proto := range []string{"udp", "tcp"} {
		for _, ip := range p.DNS {
			if ip.Is6() == (family == "-6") {
				rule := Rule{Priority: priority, Protocol: "242", Table: "main", Dst: ip.String(), IPProto: proto, DPort: 53}
				if !slices.ContainsFunc(rules, func(r Rule) bool { return reflect.DeepEqual(r, rule) }) {
					rules = append(rules, rule)
				}
			}
		}
		priority++
	}
	rules = append(rules, Rule{Priority: priority, Protocol: "242", Table: strconv.Itoa(p.Table)},
		Rule{Priority: priority + 1, Protocol: "242", Table: strconv.Itoa(p.Table + 1)},
		Rule{Priority: priority + 2, Protocol: "242", Action: "unreachable"})
	return rules
}

func (p Plan) owns(rule Rule) bool {
	return rule.Protocol == "242" && rule.Priority >= p.Priority && rule.Priority < p.Priority+16
}

func (r Routing) replaceRules(ctx context.Context, family string, p Plan, old []Rule) error {
	// Retain identical rules: adding a duplicate can return EEXIST. Commit all
	// changed replacements before deleting old rules, preserving terminal denial.
	old = append([]Rule(nil), old...)
	for _, rule := range p.rules(family) {
		i := slices.IndexFunc(old, func(r Rule) bool { return reflect.DeepEqual(r, rule) })
		if i >= 0 {
			old = slices.Delete(old, i, i+1)
			continue
		}
		if err := r.command(ctx, family, append([]string{"rule", "add"}, rule.args()...)...); err != nil {
			return err
		}
	}
	for _, rule := range old {
		if p.owns(rule) {
			if err := r.command(ctx, family, append([]string{"rule", "del"}, rule.args()...)...); err != nil {
				return err
			}
		}
	}
	return nil
}

// Block installs terminal defaults before any catch-all. It deliberately survives
// interface deletion and daemon shutdown. Activate only adds a lower-metric route.
func (r Routing) Block(ctx context.Context, p Plan) error {
	snapshot, err := inspect(ctx, r.Reader, r.Run)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		flag, def string
		family    Family
	}{{"-4", "0.0.0.0/0", snapshot.V4}, {"-6", "::/0", snapshot.V6}} {
		if err := r.command(ctx, f.flag, "route", "replace", "unreachable", f.def, "table", strconv.Itoa(p.Table+1), "metric", "42760"); err != nil {
			return err
		}
		if err := r.replaceRules(ctx, f.flag, p, f.family.Rules); err != nil {
			return err
		}
	}
	return nil
}

// installed checks only owned resources; physical defaults remain administrator state.
func (p Plan) installed(s Snapshot) bool {
	for _, f := range []struct {
		flag, blocked string
		family        Family
	}{{"-4", "100.64.0.0/10", s.V4}, {"-6", "fd7a:115c:a1e0::/48", s.V6}} {
		var owned []Rule
		for _, rule := range f.family.Rules {
			if p.owns(rule) {
				owned = append(owned, rule)
			}
		}
		wanted := p.rules(f.flag)
		if len(owned) != len(wanted) {
			return false
		}
		for _, rule := range wanted {
			if !slices.ContainsFunc(owned, func(r Rule) bool { return reflect.DeepEqual(r, rule) }) {
				return false
			}
		}
		for _, route := range []Route{
			{Dst: "default", Table: strconv.Itoa(p.Table + 1), Type: "unreachable", Metric: 42760},
			{Dst: f.blocked, Table: strconv.Itoa(p.Table), Type: "unreachable", Metric: 42760},
		} {
			if !slices.ContainsFunc(f.family.Routes, func(r Route) bool { return routePresent(r, route) && r.Metric == route.Metric }) {
				return false
			}
		}
		for _, exceptions := range [][]Exception{p.Gateways, p.Management, p.Control, p.WARP, p.Exceptions} {
			for _, e := range exceptions {
				if e.Family != f.flag {
					continue
				}
				route := e.Route
				route.Table = strconv.Itoa(p.Table)
				if !slices.ContainsFunc(f.family.Routes, func(r Route) bool { return routePresent(r, route) }) {
					return false
				}
			}
		}
	}
	return true
}

func routePresent(got, want Route) bool {
	kind := func(r Route) string {
		if r.Type == "unicast" {
			return ""
		}
		return r.Type
	}
	// Kernel snapshots use bare host addresses and "default" for zero prefixes.
	v6 := strings.Contains(want.Dst, ":")
	gp, ge := got.prefix(v6)
	wp, we := want.prefix(v6)
	return ge == nil && we == nil && gp == wp && got.table() == want.table() && kind(got) == kind(want) && got.Dev == want.Dev && got.Gateway == want.Gateway
}

func (r Routing) Exceptions(ctx context.Context, p Plan) error {
	for _, family := range []string{"-4", "-6"} {
		if err := r.flush(ctx, family, p.Table); err != nil {
			return err
		}
		// Never let a vanished Mesh/Tailscale interface fall back to physical egress.
		prefix := "100.64.0.0/10"
		if family == "-6" {
			prefix = "fd7a:115c:a1e0::/48"
		}
		if err := r.command(ctx, family, "route", "replace", "unreachable", prefix, "table", strconv.Itoa(p.Table), "metric", "42760"); err != nil {
			return err
		}
	}
	// Restore physical control/carrier routes first: a vanished Mesh interface
	// must not prevent the WARP connection probes from rebuilding that interface.
	for _, e := range append(append(append(append([]Exception(nil), p.Gateways...), p.Management...), p.Control...), p.WARP...) {
		if e.Route.Type == "unreachable" {
			if err := r.command(ctx, e.Family, "route", "replace", "unreachable", e.Route.Dst, "table", strconv.Itoa(p.Table)); err != nil {
				return err
			}
			continue
		}
		args := []string{"route", "replace", e.Route.Dst, "table", strconv.Itoa(p.Table), "dev", e.Route.Dev}
		if e.Route.Gateway != "" {
			args = append(args, "via", e.Route.Gateway, "onlink")
		}
		if err := r.installException(ctx, e.Family, e.Route.Dev, args...); err != nil {
			return err
		}
	}
	for _, e := range p.Exceptions {
		args := []string{"route", "replace", e.Route.Dst, "table", strconv.Itoa(p.Table)}
		if e.Route.Gateway != "" {
			args = append(args, "via", e.Route.Gateway, "onlink")
		}
		args = append(args, "dev", e.Route.Dev)
		if err := r.installException(ctx, e.Family, e.Route.Dev, args...); err != nil {
			return err
		}
	}

	return nil
}
func (r Routing) Activate(ctx context.Context, p Plan, v6 bool) error {
	if err := r.installSecureRoute(ctx, "-4", "route", "replace", "default", "dev", "meshsecure0", "src", p.Source.String(), "table", strconv.Itoa(p.Table+1), "metric", "10"); err != nil {
		return err
	}
	if v6 {
		if !p.Source6.Is6() {
			return fmt.Errorf("missing secure IPv6 source for selected exit")
		}
		return r.installSecureRoute(ctx, "-6", "route", "replace", "default", "dev", "meshsecure0", "src", p.Source6.String(), "table", strconv.Itoa(p.Table+1), "metric", "10")
	}
	return nil
}
func (r Routing) Remove(ctx context.Context, p Plan) error {
	snapshot, err := inspect(ctx, r.Reader, r.Run)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		flag   string
		family Family
	}{{"-4", snapshot.V4}, {"-6", snapshot.V6}} {
		for _, rule := range f.family.Rules {
			if p.owns(rule) {
				if err := r.command(ctx, f.flag, append([]string{"rule", "del"}, rule.args()...)...); err != nil {
					return err
				}
			}
		}
		for _, table := range []int{p.Table, p.Table + 1} {
			if err := r.flush(ctx, f.flag, table); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r Routing) flush(ctx context.Context, family string, table int) error {
	out, err := r.Run.Run(ctx, "", "ip", family, "route", "flush", "table", strconv.Itoa(table))
	if err != nil && strings.Contains(string(out), "FIB table does not exist") {
		return nil
	}
	return err
}

func physicalGateways(s Snapshot) []Exception {
	var routes []Exception
	// ARP's route validation needs a physical route back to the uplink gateway.
	// This host route grants no IP access: GuardRules does not exempt Gateways.
	for _, f := range []struct {
		family Family
		flag   string
	}{{s.V4, "-4"}, {s.V6, "-6"}} {
		for _, r := range f.family.Routes {
			if r.table() == "main" && r.Dst == "default" && r.Gateway != "" && r.Dev != "CloudflareWARP" && r.Dev != "meshsecure0" && r.Dev != "tailscale0" && r.Dev != "meshscale0" {
				routes = append(routes, Exception{f.flag, Route{Dst: r.Gateway, Dev: r.Dev}})
			}
		}
	}

	return routes
}
