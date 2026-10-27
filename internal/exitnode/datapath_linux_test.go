//go:build linux

package exitnode

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/secure"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// This test enters a fresh network namespace before creating any links. Children
// use anonymous namespaces; no host route, firewall manager or daemon is touched.
func TestLinuxExitDataPath(t *testing.T) {
	if os.Getenv("MESHSCALE_EXIT_NETNS_TEST") != "1" {
		t.Skip("set MESHSCALE_EXIT_NETNS_TEST=1 for isolated Linux forwarding test")
	}
	if os.Getenv("MESHSCALE_EXIT_CHILD") != "1" {
		cmd := exec.CommandContext(t.Context(), "unshare", "-n", os.Args[0], "-test.run=^TestLinuxExitDataPath$", "-test.v")
		cmd.Env = append(os.Environ(), "MESHSCALE_EXIT_CHILD=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated data path: %v\n%s", err, out)
		} else {
			t.Log(string(out))
		}
		return
	}
	run := func(pid int, input, name string, args ...string) string {
		t.Helper()
		var helperArgs []string
		if name == "wg" {
			helperArgs = args
			name = os.Args[0]
			args = []string{"-test.run=^TestWGConfigureHelper$"}
		}
		if pid != 0 {
			args = append([]string{"-t", strconv.Itoa(pid), "-n", name}, args...)
			name = "nsenter"
		}
		cmd := exec.CommandContext(t.Context(), name, args...)
		cmd.Stdin = strings.NewReader(input)
		if helperArgs != nil {
			cmd.Env = append(os.Environ(), "MESHSCALE_WG_ARGS="+strings.Join(helperArgs, " "))
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	child := func() int {
		t.Helper()
		cmd := exec.Command("unshare", "-n", "sleep", "120")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		parent, _ := os.Readlink("/proc/self/ns/net")
		for i := 0; i < 100; i++ {
			current, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid))
			if current != "" && current != parent {
				return cmd.Process.Pid
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("namespace child did not start")
		return 0
	}
	exit, internet := child(), child()
	for _, pid := range []int{0, exit, internet} {
		run(pid, "", "ip", "link", "set", "lo", "up")
	}
	// Mesh carrier has no Internet route of its own.
	run(0, "", "ip", "link", "add", "CloudflareWARP", "type", "veth", "peer", "name", "exitcarrier")
	run(0, "", "ip", "link", "set", "exitcarrier", "netns", strconv.Itoa(exit))
	run(exit, "", "ip", "link", "set", "exitcarrier", "name", "CloudflareWARP")
	run(0, "", "ip", "addr", "add", "100.96.0.2/24", "dev", "CloudflareWARP")
	run(exit, "", "ip", "addr", "add", "100.96.0.7/24", "dev", "CloudflareWARP")
	for _, pid := range []int{0, exit} {
		run(pid, "", "ip", "link", "set", "CloudflareWARP", "up")
	}
	link := func(pid int, name, peer, local, remote string) {
		run(pid, "", "ip", "link", "add", name, "type", "veth", "peer", "name", peer)
		run(pid, "", "ip", "link", "set", peer, "netns", strconv.Itoa(internet))
		run(pid, "", "ip", "addr", "add", local, "dev", name)
		run(pid, "", "ip", "link", "set", name, "up")
		run(internet, "", "ip", "addr", "add", remote, "dev", peer)
		run(internet, "", "ip", "link", "set", peer, "up")
	}
	link(0, "eth0", "clientnet", "198.18.1.2/24", "198.18.1.1/24")
	link(exit, "eth0", "exitnet", "198.18.2.2/24", "198.18.2.1/24")
	run(internet, "", "ip", "addr", "add", "198.19.0.1/32", "dev", "lo")
	run(0, "", "ip", "route", "add", "default", "via", "198.18.1.1")
	run(exit, "", "ip", "route", "add", "default", "via", "198.18.2.1")
	run(exit, "", "sysctl", "-w", "net.ipv4.ip_forward=1")
	for _, node := range []struct {
		pid       int
		dev, addr string
	}{{0, "eth0", "2001:db8:1::2/64"}, {internet, "clientnet", "2001:db8:1::1/64"}, {exit, "eth0", "2001:db8:2::2/64"}, {internet, "exitnet", "2001:db8:2::1/64"}, {internet, "lo", "2001:db8:ffff::1/128"}} {
		run(node.pid, "", "ip", "-6", "addr", "add", node.addr, "dev", node.dev, "nodad")
	}
	run(0, "", "ip", "-6", "route", "add", "default", "via", "2001:db8:1::1")
	run(exit, "", "ip", "-6", "route", "add", "default", "via", "2001:db8:2::1")
	run(exit, "", "sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
	server6 := exec.Command("nsenter", "-t", strconv.Itoa(internet), "-n", "python3", "-u", "-c", `from http.server import BaseHTTPRequestHandler,HTTPServer
import socket
class S(HTTPServer): address_family=socket.AF_INET6
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(self.client_address[0].encode())
 def log_message(self,*a): pass
S(('2001:db8:ffff::1',8080),H).serve_forever()`)
	if err := server6.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server6.Process.Kill(); _ = server6.Wait() })
	fetch6 := func() (string, error) {
		out, err := (Commands{}).Run(t.Context(), "", "curl", "--noproxy", "*", "-6fsS", "--connect-timeout", "1", "--max-time", "2", "http://[2001:db8:ffff::1]:8080")
		return strings.TrimSpace(string(out)), err
	}
	server := exec.Command("nsenter", "-t", strconv.Itoa(internet), "-n", "python3", "-u", "-c", `from http.server import BaseHTTPRequestHandler,HTTPServer
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(self.client_address[0].encode())
 def log_message(self,*a): pass
HTTPServer(('198.19.0.1',8080),H).serve_forever()`)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	fetch := func() (string, error) {
		out, err := (Commands{}).Run(t.Context(), "", "curl", "-4fsS", "--connect-timeout", "1", "--max-time", "2", "http://198.19.0.1:8080")
		return strings.TrimSpace(string(out)), err
	}
	// The two HTTP servers start independently. IPv4 readiness does not imply
	// the IPv6 child has bound its socket yet, especially under race testing.
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err4 := fetch()
		_, err6 := fetch6()
		if err4 == nil && err6 == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("HTTP servers not ready: IPv4=%v IPv6=%v", err4, err6)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got, err := fetch(); err != nil || got != "198.18.1.2" {
		t.Fatalf("direct source=%q error=%v", got, err)
	}
	if got, err := fetch6(); err != nil || got != "2001:db8:1::2" {
		t.Fatalf("direct IPv6 source=%q error=%v", got, err)
	}
	ck, _ := secure.GenerateKey()
	ek, _ := secure.GenerateKey()
	cp, _ := ck.Public()
	ep, _ := ek.Public()
	clientIP, exitIP := netip.MustParseAddr("10.200.1.2"), netip.MustParseAddr("10.200.1.1")
	for _, node := range []struct {
		pid     int
		key, ip string
	}{{0, ck.Private, clientIP.String()}, {exit, ek.Private, exitIP.String()}} {
		run(node.pid, "", "ip", "link", "add", "meshsecure0", "type", "wireguard")
		run(node.pid, node.key+"\n", "wg", "set", "meshsecure0", "private-key", "/dev/stdin", "listen-port", "51821")
		run(node.pid, "", "ip", "addr", "add", node.ip+"/32", "dev", "meshsecure0")
		run(node.pid, "", "ip", "link", "set", "meshsecure0", "mtu", "1280", "up")
	}
	run(0, "", "ip", "-6", "addr", "add", "fd6d:6573:6873::2/128", "dev", "meshsecure0", "nodad")
	run(exit, "", "ip", "-6", "addr", "add", "fd6d:6573:6873::1/128", "dev", "meshsecure0", "nodad")
	run(exit, "", "ip", "-6", "route", "add", "fd6d:6573:6873::2/128", "dev", "meshsecure0")
	run(0, "", "wg", "set", "meshsecure0", "peer", ep, "allowed-ips", "0.0.0.0/0,::/0", "endpoint", "100.96.0.7:51821")
	run(exit, "", "wg", "set", "meshsecure0", "peer", cp, "allowed-ips", clientIP.String()+"/32,fd6d:6573:6873::2/128", "endpoint", "100.96.0.2:51821")
	run(exit, "", "ip", "route", "add", clientIP.String()+"/32", "dev", "meshsecure0")
	f := ForwardPlan{Uplink4: "eth0", Uplink6: "eth0", Sources4: []netip.Addr{clientIP}, Sources6: []netip.Addr{netip.MustParseAddr("fd6d:6573:6873::2")}, Identity4: exitIP, Identity6: netip.MustParseAddr("fd6d:6573:6873::1"), MSS: 1172}
	script := "table inet " + ForwardTable + " {\n comment \"" + ownership + "\"\n" + ForwardRules(f) + "}\n"
	run(exit, script, "nft", "-f", "-")
	snapshot, err := Inspect(t.Context(), Commands{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := PlanRouting(snapshot, clientIP, netip.MustParseAddr("100.96.0.7"), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Source6 = netip.MustParseAddr("fd6d:6573:6873::2")
	p.Identities4 = []netip.Addr{exitIP}
	p.Identities6 = []netip.Addr{netip.MustParseAddr("fd6d:6573:6873::1")}
	nft := NFT{Run: Commands{}}
	routes := Routing{Run: Commands{}}
	if err := nft.Apply(t.Context(), GuardTable, GuardRules(p)); err != nil {
		t.Fatal(err)
	}
	if err := routes.Exceptions(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	if err := routes.Block(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	if _, err := fetch(); err == nil {
		t.Fatal("inactive selected exit leaked direct Internet")
	}
	if err := routes.Activate(t.Context(), p, true); err != nil {
		t.Fatal(err)
	}
	run(0, "", "ip", "neigh", "flush", "all")
	if got, err := fetch(); err != nil || got != "198.18.2.2" {
		t.Fatalf("exit source=%q error=%v", got, err)
	}
	if got, err := fetch6(); err != nil || got != "2001:db8:2::2" {
		t.Fatalf("exit IPv6 source=%q error=%v", got, err)
	}
	// The selected peer's defaults authorize Internet replies, not unknown
	// overlay identities. Verify both authenticated and forged inner sources.
	for _, family := range []struct{ flag, good, bad, dst string }{{"-4", exitIP.String(), "10.200.1.99", clientIP.String()}, {"-6", "fd6d:6573:6873::1", "fd6d:6573:6873::99", "fd6d:6573:6873::2"}} {
		run(exit, "", "ping", family.flag, "-c", "1", "-W", "1", "-I", family.good, family.dst)
		bits := "/32"
		if family.flag == "-6" {
			bits = "/128"
		}
		run(exit, "", "ip", family.flag, "addr", "add", family.bad+bits, "dev", "meshsecure0")
		out, err := (Commands{}).Run(t.Context(), "", "nsenter", "-t", strconv.Itoa(exit), "-n", "ping", family.flag, "-c", "1", "-W", "1", "-I", family.bad, family.dst)
		if err == nil {
			t.Fatalf("forged inner identity %s accepted: %s", family.bad, out)
		}
	}
	// Withdrawing NAT/forwarding leaves the client's selection and protection.
	run(exit, "", "ip", "link", "delete", "meshsecure0")
	if _, err := fetch6(); err == nil {
		t.Fatal("offline exit leaked direct IPv6")
	}
	if _, err := fetch(); err == nil {
		t.Fatal("offline exit leaked direct Internet")
	}
	run(0, "", "ip", "link", "delete", "meshsecure0")
	if _, err := fetch6(); err == nil {
		t.Fatal("client engine crash leaked direct IPv6")
	}
	if _, err := fetch(); err == nil {
		t.Fatal("client engine crash leaked direct Internet")
	}
	// Even removing the policy rules cannot bypass the independent output guard.
	if err := routes.Remove(t.Context(), p); err != nil {
		t.Fatal(err)
	}
	if _, err := fetch(); err == nil {
		t.Fatal("removed route table bypassed output guard")
	}
	if err := nft.Remove(t.Context(), GuardTable); err != nil {
		t.Fatal(err)
	}
	if got, err := fetch(); err != nil || got != "198.18.1.2" {
		t.Fatalf("deselection source=%q error=%v", got, err)
	}
	if got, err := fetch6(); err != nil || got != "2001:db8:1::2" {
		t.Fatalf("deselected IPv6 source=%q error=%v", got, err)
	}
	t.Log("PASS direct -> kernel WireGuard/nft masquerade -> offline blocked -> engine loss blocked -> independent guard -> explicit deselection restores direct")
}

// TestWGConfigureHelper replaces the optional wg CLI with the same netlink
// library used by the production kernel engine, inside the child's namespace.
func TestWGConfigureHelper(t *testing.T) {
	text := os.Getenv("MESHSCALE_WG_ARGS")
	if text == "" {
		t.Skip("namespace helper")
	}
	args := strings.Fields(text)
	cfg := wgtypes.Config{}
	var peer *wgtypes.PeerConfig
	for i := 2; i < len(args); i += 2 {
		value := args[i+1]
		switch args[i] {
		case "private-key":
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				t.Fatal(err)
			}
			key, err := wgtypes.ParseKey(strings.TrimSpace(string(data)))
			if err != nil {
				t.Fatal(err)
			}
			cfg.PrivateKey = &key
		case "listen-port":
			port, err := strconv.Atoi(value)
			if err != nil {
				t.Fatal(err)
			}
			cfg.ListenPort = &port
		case "peer":
			key, err := wgtypes.ParseKey(value)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{PublicKey: key})
			peer = &cfg.Peers[len(cfg.Peers)-1]
		case "allowed-ips":
			peer.ReplaceAllowedIPs = true
			for _, text := range strings.Split(value, ",") {
				_, prefix, err := net.ParseCIDR(text)
				if err != nil {
					t.Fatal(err)
				}
				peer.AllowedIPs = append(peer.AllowedIPs, *prefix)
			}
		case "endpoint":
			address, err := net.ResolveUDPAddr("udp4", value)
			if err != nil {
				t.Fatal(err)
			}
			peer.Endpoint = address
		default:
			t.Fatalf("unknown helper setting %s", args[i])
		}
	}
	client, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.ConfigureDevice("meshsecure0", cfg); err != nil {
		t.Fatal(err)
	}
}
