//go:build linux

package exitnode

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

type fakeSnapshotNetlink struct {
	routes map[int][]netlink.Route
	rules  map[int][]netlink.Rule
	links  []netlink.Link
	err    error
}

func (f fakeSnapshotNetlink) RouteList(family int) ([]netlink.Route, error) {
	return f.routes[family], f.err
}
func (f fakeSnapshotNetlink) RuleList(family int) ([]netlink.Rule, error) {
	return f.rules[family], f.err
}
func (f fakeSnapshotNetlink) LinkList() ([]netlink.Link, error) { return f.links, f.err }

func TestNetlinkSnapshotSpeaksIPJSON(t *testing.T) {
	cidr := func(s string) *net.IPNet { _, n, _ := net.ParseCIDR(s); return n }
	full, partial := uint32(0xffffffff), uint32(0xff0000)
	secure, tun := netlink.NewLinkAttrs(), netlink.NewLinkAttrs()
	secure.Index, secure.Name = 2, "meshsecure0"
	tun.Index, tun.Name = 3, "tun0"
	root := t.TempDir()
	writeProcFixture(t, root)
	reader := netlinkSnapshotReader{
		kernel: fakeSnapshotNetlink{
			routes: map[int][]netlink.Route{unix.AF_INET: {
				{Dst: cidr("0.0.0.0/0"), LinkIndex: 2, Table: unix.RT_TABLE_MAIN, Type: unix.RTN_UNICAST, Protocol: 2, Priority: 100},
				{LinkIndex: 3, Table: 52, Type: unix.RTN_UNICAST},
				{Dst: cidr("100.96.0.7/32"), LinkIndex: 2, Table: unix.RT_TABLE_LOCAL, Type: unix.RTN_LOCAL},
				{Dst: cidr("100.96.0.0/12"), LinkIndex: 3, Table: 65743, Type: unix.RTN_UNREACHABLE},
			}},
			rules: map[int][]netlink.Rule{unix.AF_INET: {
				{Priority: 5209, Table: 65743, Mark: 0x100cf, Mask: &full, Protocol: 243, Invert: true},
				{Priority: 5270, Table: unix.RT_TABLE_MAIN, Mark: 0x80000, Mask: &partial},
			}},
			links: []netlink.Link{&netlink.Device{LinkAttrs: secure}, &netlink.Tuntap{LinkAttrs: tun, Mode: netlink.TUNTAP_MODE_TUN}},
		},
		procRoot: root,
	}
	snapshot, err := reader.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	routes := []Route{
		{Dst: "default", Dev: "meshsecure0", Table: "main", Type: "unicast", Protocol: "2", Scope: "universe", Metric: 100},
		{Dst: "default", Dev: "tun0", Table: "52", Type: "unicast", Protocol: "0", Scope: "universe"},
		{Dst: "100.96.0.7", Dev: "meshsecure0", Table: "local", Type: "local", Protocol: "0", Scope: "universe"},
		{Dst: "100.96.0.0/12", Dev: "tun0", Table: "65743", Type: "unreachable", Protocol: "0", Scope: "universe"},
	}
	if !reflect.DeepEqual(snapshot.V4.Routes, routes) {
		t.Fatalf("routes:\n got %+v\nwant %+v", snapshot.V4.Routes, routes)
	}
	rules := []Rule{
		{Priority: 5209, Table: "65743", FWMark: "0x100cf", Protocol: "243", Not: json.RawMessage("true")},
		{Priority: 5270, Table: "main", FWMark: "0x80000", FWMask: "0xff0000", Protocol: "0"},
	}
	if !reflect.DeepEqual(snapshot.V4.Rules, rules) {
		t.Fatalf("rules:\n got %+v\nwant %+v", snapshot.V4.Rules, rules)
	}
	if len(snapshot.Links) != 2 || snapshot.Links[1].Info.Kind != "tun" {
		t.Fatalf("links: %+v", snapshot.Links)
	}
	if len(snapshot.SSH) != 1 || snapshot.SSH[0].String() != "100.96.0.2" {
		t.Fatalf("SSH peers: %v", snapshot.SSH)
	}
}

// TestNetlinkSnapshotMatchesIPLive compares the reader with iproute2 on this
// host. It only reads kernel state.
func TestNetlinkSnapshotMatchesIPLive(t *testing.T) {
	if os.Getenv("MESHSCALE_LIVE_SNAPSHOT") != "1" {
		t.Skip("set MESHSCALE_LIVE_SNAPSHOT=1 to compare with ip -j on this host")
	}
	snapshot, err := netlinkSnapshotReader{}.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{ForwardTable, GuardTable} {
		_, owned, err := NFT{Run: Commands{}}.owner(context.Background(), table)
		if err != nil {
			t.Fatal(err)
		}
		if installed, err := (NFT{}).Installed(context.Background(), table); err != nil || installed != owned {
			t.Errorf("Installed(%s) = %v, %v; nft comment says owned=%v", table, installed, err, owned)
		}
	}
	out, err := exec.Command("ip", "-j", "-d", "link", "show").Output()
	if err != nil {
		t.Fatal(err)
	}
	var links []Link
	if err := json.Unmarshal(out, &links); err != nil {
		t.Fatal(err)
	}
	if extra, missing := difference(linkKeys(snapshot.Links), linkKeys(links)); len(extra)+len(missing) > 0 {
		t.Errorf("links: extra %v, missing %v", extra, missing)
	}
	for _, f := range []struct {
		flag   string
		family Family
	}{{"-4", snapshot.V4}, {"-6", snapshot.V6}} {
		var want Family
		for _, q := range []struct {
			args []string
			into any
		}{{[]string{"-j", f.flag, "route", "show", "table", "all"}, &want.Routes}, {[]string{"-j", f.flag, "rule", "show"}, &want.Rules}} {
			out, err := exec.Command("ip", q.args...).Output()
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(out, q.into); err != nil {
				t.Fatal(err)
			}
		}
		if extra, missing := difference(routeKeys(f.family.Routes), routeKeys(want.Routes)); len(extra)+len(missing) > 0 {
			t.Errorf("ip %s routes: extra %v, missing %v", f.flag, extra, missing)
		}
		if extra, missing := difference(ruleKeys(f.family.Rules), ruleKeys(want.Rules)); len(extra)+len(missing) > 0 {
			t.Errorf("ip %s rules: extra %v, missing %v", f.flag, extra, missing)
		}
	}
}

func difference(got, want []string) (extra, missing []string) {
	for _, k := range got {
		if !slices.Contains(want, k) {
			extra = append(extra, k)
		}
	}
	for _, k := range want {
		if !slices.Contains(got, k) {
			missing = append(missing, k)
		}
	}
	return extra, missing
}

// routeKeys and ruleKeys keep only the fields the planners read.
func routeKeys(routes []Route) []string {
	var keys []string
	for _, r := range routes {
		kind := r.Type
		if kind == "unicast" {
			kind = ""
		}
		keys = append(keys, fmt.Sprintf("%s dev=%s via=%s table=%s type=%s metric=%d", r.Dst, r.Dev, r.Gateway, r.table(), kind, r.Metric))
	}
	slices.Sort(keys)
	return keys
}

func linkKeys(links []Link) []string {
	var keys []string
	for _, l := range links {
		keys = append(keys, l.Name+" kind="+l.Info.Kind)
	}
	return keys
}

func ruleKeys(rules []Rule) []string {
	var keys []string
	for _, r := range rules {
		keys = append(keys, fmt.Sprintf("%d table=%v mark=%s/%s not=%t dst=%s/%d ipproto=%s dport=%d action=%s", r.Priority, r.Table, r.FWMark, r.FWMask, len(r.Not) > 0, r.Dst, r.DstLen, r.IPProto, r.DPort, r.Action))
	}
	slices.Sort(keys)
	return keys
}

func TestNetlinkSnapshotReaderReturnsKernelErrors(t *testing.T) {
	want := errors.New("netlink fixture failed")
	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	attrs := netlink.NewLinkAttrs()
	attrs.Index = 2
	reader := netlinkSnapshotReader{kernel: fakeSnapshotNetlink{links: []netlink.Link{&netlink.Device{LinkAttrs: attrs}}, routes: map[int][]netlink.Route{unix.AF_INET: {{Dst: dst, LinkIndex: 2}}}, err: want}, procRoot: t.TempDir()}
	_, err := reader.Inspect(context.Background())
	if !errors.Is(err, want) {
		t.Fatalf("error=%v", err)
	}
}

func TestProcAddress(t *testing.T) {
	for _, tc := range []struct {
		value string
		v6    bool
		want  string
	}{
		{"02006064", false, "100.96.0.2"},
		{"00000000000000000000000001000000", true, "::1"},
	} {
		got, err := procAddress(tc.value, tc.v6)
		if err != nil || got.String() != tc.want {
			t.Fatalf("procAddress(%q) = %v, %v; want %s", tc.value, got, err, tc.want)
		}
	}
}

func writeProcFixture(t *testing.T, root string) {
	t.Helper()
	pidDir := filepath.Join(root, "1234")
	if err := os.MkdirAll(filepath.Join(pidDir, "fd"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "net"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("sshd: user\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for fd, inode := range map[string]string{"3": "54", "4": "55", "5": "56"} {
		if err := os.Symlink("socket:["+inode+"]", filepath.Join(pidDir, "fd", fd)); err != nil {
			t.Fatal(err)
		}
	}
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	// sshd listens on :22 (54), has one session from 100.96.0.2 (55), and one
	// ssh -L forward to 8.8.8.8:80 (56), which must not count as a peer.
	const established = "   0: 00000000:0016 00000000:0000 0A 00000000:0000 00:00000000 00000000 0 0 54\n" +
		"   1: 0100007F:0016 02006064:3039 01 00000000:0000 00:00000000 00000000 1000 0 55\n" +
		"   2: 0100007F:9C40 08080808:0050 01 00000000:0000 00:00000000 00000000 1000 0 56\n"
	for _, name := range []string{"tcp", "tcp6"} {
		content := header
		if name == "tcp" {
			content += established
		}
		if err := os.WriteFile(filepath.Join(root, "net", name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOwnedPolicyRuleSnapshotMatchesIPJSON(t *testing.T) {
	_, dst, _ := net.ParseCIDR("1.1.1.1/32")
	cases := []struct {
		rule netlink.Rule
		json string
		args string
	}{
		{netlink.Rule{Priority: 5000, Protocol: 242, Table: unix.RT_TABLE_MAIN, Dst: dst, IPProto: unix.IPPROTO_UDP, Dport: netlink.NewRulePortRange(53, 53)}, `{"priority":5000,"protocol":"242","table":"main","dst":"1.1.1.1","ipproto":"udp","dport":53}`, "priority 5000 protocol 242 to 1.1.1.1 ipproto udp dport 53 lookup main"},
		{netlink.Rule{Priority: 5004, Protocol: 242, Type: unix.RTN_UNREACHABLE}, `{"priority":5004,"protocol":"242","action":"unreachable"}`, "priority 5004 protocol 242 unreachable"},
	}
	for _, tc := range cases {
		var want Rule
		if err := json.Unmarshal([]byte(tc.json), &want); err != nil {
			t.Fatal(err)
		}
		got := ruleFromNetlink(tc.rule)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("snapshot=%+v, ip -j=%+v", got, want)
		}
		if args := strings.Join(got.args(), " "); args != tc.args {
			t.Fatalf("rule selectors %q, want %q", args, tc.args)
		}
	}
}

func TestRuleDumpPreservesTerminalActionAndDNSSelectors(t *testing.T) {
	for _, dns := range []bool{false, true} {
		msg := nl.NewRtMsg()
		msg.Family, msg.Type, msg.Table = unix.AF_INET, unix.RTN_UNREACHABLE, 0
		priority := make([]byte, 4)
		binary.NativeEndian.PutUint32(priority, 5000)
		data := append(msg.Serialize(), nl.NewRtAttr(nl.FRA_PRIORITY, priority).Serialize()...)
		data = append(data, nl.NewRtAttr(nl.FRA_PROTOCOL, []byte{242}).Serialize()...)
		want := Rule{Priority: 5000, Protocol: "242", Action: "unreachable"}
		if dns {
			msg.Type, msg.Table, msg.Dst_len = unix.RTN_UNICAST, unix.RT_TABLE_MAIN, 32
			copy(data, msg.Serialize())
			ports := make([]byte, 4)
			binary.NativeEndian.PutUint16(ports, 53)
			binary.NativeEndian.PutUint16(ports[2:], 53)
			data = append(data, nl.NewRtAttr(nl.FRA_DST, []byte{1, 1, 1, 1}).Serialize()...)
			data = append(data, nl.NewRtAttr(nl.FRA_IP_PROTO, []byte{unix.IPPROTO_UDP}).Serialize()...)
			data = append(data, nl.NewRtAttr(nl.FRA_DPORT_RANGE, ports).Serialize()...)
			want = Rule{Priority: 5000, Protocol: "242", Table: "main", Dst: "1.1.1.1", IPProto: "udp", DPort: 53}
		}
		rule, err := ruleFromMessage(data)
		if err != nil {
			t.Fatal(err)
		}
		if got := ruleFromNetlink(rule); !reflect.DeepEqual(got, want) {
			t.Fatalf("dump rule=%+v, want %+v", got, want)
		}
	}
}
