//go:build linux

package exitnode

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

type snapshotNetlink interface {
	RouteList(family int) ([]netlink.Route, error)
	RuleList(int) ([]netlink.Rule, error)
	LinkList() ([]netlink.Link, error)
}

type systemSnapshotNetlink struct{}

// RouteList returns routes from every table, like `ip route show table all`.
func (systemSnapshotNetlink) RouteList(family int) ([]netlink.Route, error) {
	return netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
}
func (systemSnapshotNetlink) RuleList(family int) ([]netlink.Rule, error) {
	// netlink.RuleList omits the action and decodes the byte IP protocol as a
	// uint32. Read the fields our snapshot needs directly from the same dump.
	req := nl.NewNetlinkRequest(unix.RTM_GETRULE, unix.NLM_F_DUMP|unix.NLM_F_REQUEST)
	req.AddData(nl.NewIfInfomsg(family))
	messages, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWRULE)
	if err != nil {
		return nil, err
	}
	var rules []netlink.Rule
	for _, message := range messages {
		rule, err := ruleFromMessage(message)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func ruleFromMessage(data []byte) (netlink.Rule, error) {
	if len(data) < unix.SizeofRtMsg {
		return netlink.Rule{}, fmt.Errorf("short policy rule message")
	}
	msg := nl.DeserializeRtMsg(data)
	attrs, err := nl.ParseRouteAttr(data[msg.Len():])
	if err != nil {
		return netlink.Rule{}, err
	}
	r := netlink.Rule{Type: msg.Type, Table: int(msg.Table), Invert: msg.Flags&netlink.FibRuleInvert != 0}
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case nl.FRA_PRIORITY:
			r.Priority = int(binary.NativeEndian.Uint32(attr.Value))
		case unix.RTA_TABLE:
			r.Table = int(binary.NativeEndian.Uint32(attr.Value))
		case nl.FRA_DST:
			r.Dst = &net.IPNet{IP: attr.Value, Mask: net.CIDRMask(int(msg.Dst_len), len(attr.Value)*8)}
		case nl.FRA_FWMARK:
			r.Mark = binary.NativeEndian.Uint32(attr.Value)
		case nl.FRA_FWMASK:
			mask := binary.NativeEndian.Uint32(attr.Value)
			r.Mask = &mask
		case nl.FRA_PROTOCOL:
			r.Protocol = attr.Value[0]
		case nl.FRA_IP_PROTO:
			r.IPProto = int(attr.Value[0])
		case nl.FRA_DPORT_RANGE:
			r.Dport = netlink.NewRulePortRange(binary.NativeEndian.Uint16(attr.Value[:2]), binary.NativeEndian.Uint16(attr.Value[2:]))
		}
	}
	return r, nil
}
func (systemSnapshotNetlink) LinkList() ([]netlink.Link, error) { return netlink.LinkList() }

// Inspect reads routes, rules, links and sshd peers over netlink and /proc
// instead of shelling out to ip and ss. The snapshot keeps the vocabulary of
// `ip -j` (tables "main"/"local", dst "default", bare host addresses, link
// kinds "tun"/"tap") because the planners match on it.
func Inspect(ctx context.Context, _ Runner) (Snapshot, error) {
	return (netlinkSnapshotReader{}).Inspect(ctx)
}

type netlinkSnapshotReader struct {
	kernel   snapshotNetlink
	procRoot string
}

func (r netlinkSnapshotReader) Inspect(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	kernel := r.kernel
	if kernel == nil {
		kernel = systemSnapshotNetlink{}
	}
	var s Snapshot
	links, err := kernel.LinkList()
	if err != nil {
		return s, fmt.Errorf("list links: %w", err)
	}
	linkNames := make(map[int]string, len(links))
	for _, link := range links {
		if attrs := link.Attrs(); attrs != nil {
			linkNames[attrs.Index] = attrs.Name
			item := Link{Name: attrs.Name}
			item.Info.Kind = linkKind(link)
			s.Links = append(s.Links, item)
		}
	}
	for _, f := range []struct {
		family int
		dst    *Family
	}{{unix.AF_INET, &s.V4}, {unix.AF_INET6, &s.V6}} {
		routes, err := kernel.RouteList(f.family)
		if err != nil {
			return s, fmt.Errorf("list routes: %w", err)
		}
		for _, route := range routes {
			f.dst.Routes = append(f.dst.Routes, routeFromNetlink(route, linkNames))
		}
		rules, err := kernel.RuleList(f.family)
		if err != nil {
			return s, fmt.Errorf("list policy rules: %w", err)
		}
		for _, rule := range rules {
			f.dst.Rules = append(f.dst.Rules, ruleFromNetlink(rule))
		}
	}
	root := r.procRoot
	if root == "" {
		root = "/proc"
	}
	s.SSH, err = establishedSSHPeers(root)
	if err != nil {
		return s, fmt.Errorf("inspect established SSH peers: %w", err)
	}
	return s, nil
}

func routeFromNetlink(route netlink.Route, linkNames map[int]string) Route {
	r := Route{Table: tableName(route.Table), Type: routeType(route.Type), Protocol: strconv.Itoa(int(route.Protocol)), Scope: route.Scope.String(), Metric: route.Priority}
	r.Dst = destination(route.Dst)
	r.Dev = linkNames[route.LinkIndex]
	if route.Gw != nil {
		r.Gateway = route.Gw.String()
	}
	if route.Src != nil {
		r.PrefSrc = route.Src.String()
	}
	return r
}

// tableName names the reserved tables as ip does; nil means no table.
func tableName(id int) any {
	switch id {
	case unix.RT_TABLE_UNSPEC:
		return nil
	case unix.RT_TABLE_MAIN:
		return "main"
	case unix.RT_TABLE_LOCAL:
		return "local"
	case unix.RT_TABLE_DEFAULT:
		return "default"
	default:
		return strconv.Itoa(id)
	}
}

// destination prints a route destination as ip does: "default" for a
// zero-length prefix and a bare address for a host route.
func destination(dst *net.IPNet) string {
	if dst == nil {
		return "default"
	}
	ones, bits := dst.Mask.Size()
	switch {
	case ones == 0:
		return "default"
	case ones == bits:
		return dst.IP.String()
	default:
		return dst.String()
	}
}

// linkKind reports a link's kind as ip's info_kind does: netlink calls tun and
// tap devices "tuntap" and physical devices "device".
func linkKind(link netlink.Link) string {
	if t, ok := link.(*netlink.Tuntap); ok {
		if t.Mode == netlink.TUNTAP_MODE_TAP {
			return "tap"
		}
		return "tun"
	}
	if kind := link.Type(); kind != "device" {
		return kind
	}
	return "" // ip prints no info_kind for physical devices
}

func routeType(value int) string {
	switch value {
	case unix.RTN_UNSPEC:
		return ""
	case unix.RTN_UNICAST:
		return "unicast"
	case unix.RTN_UNREACHABLE:
		return "unreachable"
	case unix.RTN_LOCAL:
		return "local"
	case unix.RTN_BLACKHOLE:
		return "blackhole"
	case unix.RTN_PROHIBIT:
		return "prohibit"
	case unix.RTN_BROADCAST:
		return "broadcast"
	case unix.RTN_ANYCAST:
		return "anycast"
	case unix.RTN_MULTICAST:
		return "multicast"
	case unix.RTN_THROW:
		return "throw"
	default:
		return strconv.Itoa(value)
	}
}

func ruleFromNetlink(rule netlink.Rule) Rule {
	r := Rule{Priority: rule.Priority, Table: tableName(rule.Table), Protocol: strconv.Itoa(int(rule.Protocol))}
	if rule.Dst != nil {
		r.Dst = rule.Dst.IP.String()
		ones, bits := rule.Dst.Mask.Size()
		if ones != bits {
			r.DstLen = ones
		}
	}
	switch rule.IPProto {
	case unix.IPPROTO_TCP:
		r.IPProto = "tcp"
	case unix.IPPROTO_UDP:
		r.IPProto = "udp"
	default:
		if rule.IPProto != 0 {
			r.IPProto = strconv.Itoa(rule.IPProto)
		}
	}
	if rule.Dport != nil && rule.Dport.Start == rule.Dport.End {
		r.DPort = rule.Dport.Start
	}
	if rule.Type == unix.RTN_UNREACHABLE {
		r.Action = "unreachable"
	}
	if rule.Mark != 0 {
		r.FWMark = fmt.Sprintf("0x%x", rule.Mark)
		if rule.Mask != nil && *rule.Mask != 0xffffffff {
			r.FWMask = fmt.Sprintf("0x%x", *rule.Mask)
		}
	}
	if rule.Invert {
		r.Not = json.RawMessage("true")
	}
	return r
}

func establishedSSHPeers(procRoot string) ([]netip.Addr, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	owned := make(map[string]struct{})
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		pidDir := filepath.Join(procRoot, entry.Name())
		comm, err := os.ReadFile(filepath.Join(pidDir, "comm"))
		if err != nil || !strings.HasPrefix(strings.TrimSpace(string(comm)), "sshd") {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(pidDir, "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(pidDir, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			owned[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = struct{}{}
		}
	}
	// Only sessions accepted on a port sshd listens on count. Its other sockets
	// carry port forwarding (ssh -L/-D) to arbitrary destinations.
	type socket struct {
		localPort string
		remote    netip.Addr
	}
	var sockets []socket
	listening := make(map[string]bool)
	for _, table := range []string{"tcp", "tcp6"} {
		data, err := os.ReadFile(filepath.Join(procRoot, "net", table))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			if _, ok := owned[fields[9]]; !ok {
				continue
			}
			_, localPort, _ := strings.Cut(fields[1], ":")
			switch fields[3] {
			case tcpListen:
				listening[localPort] = true
			case tcpEstablished:
				remoteIP, _, _ := strings.Cut(fields[2], ":")
				if address, err := procAddress(remoteIP, table == "tcp6"); err == nil {
					sockets = append(sockets, socket{localPort, address.Unmap()})
				}
			}
		}
	}
	var peers []netip.Addr
	for _, s := range sockets {
		if listening[s.localPort] && !slices.Contains(peers, s.remote) {
			peers = append(peers, s.remote)
		}
	}
	slices.SortFunc(peers, netip.Addr.Compare) // stable plans compare equal
	return peers, nil
}

// TCP states in /proc/net/tcp.
const (
	tcpEstablished = "01"
	tcpListen      = "0A"
)

func procAddress(value string, v6 bool) (netip.Addr, error) {
	if !v6 {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 4 {
			return netip.Addr{}, fmt.Errorf("invalid proc IPv4 address %q", value)
		}
		return netip.AddrFrom4([4]byte{decoded[3], decoded[2], decoded[1], decoded[0]}), nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 16 {
		return netip.Addr{}, fmt.Errorf("invalid proc IPv6 address %q", value)
	}
	var address [16]byte
	for i := 0; i < 16; i += 4 {
		binary.LittleEndian.PutUint32(address[i:i+4], binary.BigEndian.Uint32(decoded[i:i+4]))
	}
	return netip.AddrFrom16(address), nil
}
