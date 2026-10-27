package secure

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/wgtransport"
	"golang.zx2c4.com/wireguard/device"
)

func loopbackTransport(t *testing.T, key Key, ip netip.Addr) (*Transport, netip.AddrPort) {
	t.Helper()
	b := &PacketBind{Listen: func(uint16) (net.PacketConn, error) {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}}
	tr, err := Start(t.Context(), key, ip, true, b, "auto")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tr.Close)
	b.mu.RLock()
	a := b.socket.LocalAddr().(*net.UDPAddr).AddrPort()
	b.mu.RUnlock()
	return tr, a
}
func testPeer(t *testing.T, id string, key Key, ep netip.AddrPort) Peer {
	t.Helper()
	public, _ := key.Public()
	ip, err := Address("integration", public)
	if err != nil {
		t.Fatal(err)
	}
	return Peer{RegistrationID: id, DeviceID: "device-" + id, Name: id, PublicKey: public, IP: ip, Endpoint: ep, AllowedIPs: []netip.Prefix{netip.PrefixFrom(ip, 128)}, DNSName: id + ".secure"}
}

// This is real WireGuard encryption, handshake, source validation, TCP and IPv6
// between two independent gVisor stacks over loopback UDP, with no host routes.
func TestWireGuardLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ka, _ := GenerateKey()
	kb, _ := GenerateKey()
	pa, pb := testPeer(t, "a", ka, netip.AddrPort{}), testPeer(t, "b", kb, netip.AddrPort{})
	a, ea := loopbackTransport(t, ka, pa.IP)
	b, eb := loopbackTransport(t, kb, pb.IP)
	pa.Endpoint = ea
	pb.Endpoint = eb
	if err := a.Reconcile([]Peer{pa, pb}); err != nil {
		t.Fatal(err)
	}
	if err := b.Reconcile([]Peer{pa, pb}); err != nil {
		t.Fatal(err)
	}
	waitHandshake(t, ctx, a.wg)
	waitHandshake(t, ctx, b.wg)
	l, err := b.Network.ListenTCP(netip.AddrPortFrom(pb.IP, 18080))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	served := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			served <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		source, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		if source != pa.IP.String() {
			served <- fmt.Errorf("lost source identity: %s", source)
			return
		}
		_, err = io.Copy(c, c)
		served <- err
	}()
	c, err := a.Network.DialContext(ctx, "tcp", netip.AddrPortFrom(pb.IP, 18080).String())
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("end-to-end ciphertext over Mesh; "), 4096)
	writeDone := make(chan error, 1)
	go func() { _, err := c.Write(payload); writeDone <- err }()
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, payload) {
		t.Fatal("payload corrupted")
	}
	c.Close()
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	before := a.Peers()
	if len(before) != 1 || before[0].LastHandshake == nil {
		t.Fatalf("no handshake: %+v", before)
	}
	if err := a.Reconcile([]Peer{pa, pb}); err != nil {
		t.Fatal(err)
	}
	after := a.Peers()
	if !after[0].LastHandshake.Equal(*before[0].LastHandshake) {
		t.Fatal("refresh discarded handshake")
	}
	// Removing a key updates the WG engine, not just the presentation snapshot.
	if err := a.Reconcile(nil); err != nil {
		t.Fatal(err)
	}
	if len(a.Peers()) != 0 {
		t.Fatal("revoked peer retained")
	}
	dump, err := a.wg.IpcGet()
	if err != nil || bytes.Contains([]byte(dump), []byte("public_key=")) {
		t.Fatal("revoked peer still installed")
	}
}

func TestWireGuardRejectsSpoofedSource(t *testing.T) {
	ka, _ := GenerateKey()
	kb, _ := GenerateKey()
	kv, _ := GenerateKey()
	pa, pb, victim := testPeer(t, "attacker", ka, netip.AddrPort{}), testPeer(t, "server", kb, netip.AddrPort{}), testPeer(t, "victim", kv, netip.AddrPort{})
	// The attacker controls its own stack, including its chosen source IP, but
	// cannot send victim's source address under its own authenticated WG key.
	a, ea := loopbackTransport(t, ka, victim.IP)
	b, eb := loopbackTransport(t, kb, pb.IP)
	pa.Endpoint = ea
	pb.Endpoint = eb
	if err := a.Reconcile([]Peer{pb}); err != nil {
		t.Fatal(err)
	}
	if err := b.Reconcile([]Peer{pa}); err != nil {
		t.Fatal(err)
	}
	handshakeCtx, stop := context.WithTimeout(t.Context(), 10*time.Second)
	defer stop()
	waitHandshake(t, handshakeCtx, a.wg)
	waitHandshake(t, handshakeCtx, b.wg)
	l, err := b.Network.ListenTCP(netip.AddrPortFrom(pb.IP, 18081))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			c.Close()
			accepted <- struct{}{}
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	c, err := a.Network.DialContext(ctx, "tcp", netip.AddrPortFrom(pb.IP, 18081).String())
	if err == nil {
		c.Close()
		t.Fatal("spoofed IP traversed cryptokey routing")
	}
	select {
	case <-accepted:
		t.Fatal("server accepted spoofed source")
	default:
	}
}

func TestRejectNonHostAllowedIPs(t *testing.T) {
	key, _ := GenerateKey()
	peerKey, _ := GenerateKey()
	self := testPeer(t, "self", key, netip.AddrPort{})
	tr, _ := loopbackTransport(t, key, self.IP)
	for _, prefix := range []string{"::/0", OverlayRange, "100.64.0.0/10"} {
		t.Run(prefix, func(t *testing.T) {
			p := testPeer(t, "peer", peerKey, netip.MustParseAddrPort("127.0.0.1:12345"))
			p.AllowedIPs = []netip.Prefix{netip.MustParsePrefix(prefix)}
			if err := tr.Reconcile([]Peer{p}); err == nil {
				t.Fatal("accepted route outside peer /128")
			}
		})
	}
}

// The outer pair simulates native Mesh (IPv4, MTU 1280) with WireGuard over
// loopback. The inner pair then sends secure UDP through those userspace Mesh
// stacks, exercising double encapsulation and IPv4 fragmentation at this MTU.
func TestWireGuardOverUserspaceMesh(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	type outerNode struct {
		network  wgtransport.Network
		wg       *device.Device
		key      Key
		endpoint netip.AddrPort
		ip       netip.Addr
	}
	var outer []outerNode
	for _, raw := range []string{"100.96.0.11", "100.96.0.12"} {
		ip := netip.MustParseAddr(raw)
		key, _ := GenerateKey()
		private, _ := decodeKey(key.Private)
		tun, network, err := wgtransport.NewNetstack([]netip.Addr{ip}, 1280)
		if err != nil {
			t.Fatal(err)
		}
		bind := &PacketBind{Listen: func(uint16) (net.PacketConn, error) {
			return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		}}
		wg, err := wgtransport.Start(tun, bind, "private_key="+hex.EncodeToString(private)+"\n", "test Mesh: ")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(wg.Close)
		bind.mu.RLock()
		ep := bind.socket.LocalAddr().(*net.UDPAddr).AddrPort()
		bind.mu.RUnlock()
		outer = append(outer, outerNode{network: network, wg: wg, key: key, endpoint: ep, ip: ip})
	}
	// Configure the responder before the initiator's keepalive sends a packet.
	// Otherwise the first handshake can arrive before its key is installed,
	// forcing the five-second retry timer on this entirely local test.
	for _, i := range []int{1, 0} {
		node := outer[i]
		remote := outer[1-i]
		public, _ := remote.key.Public()
		key, _ := decodeKey(public)
		cfg := fmt.Sprintf("public_key=%s\nendpoint=%s\nallowed_ip=100.96.0.0/12\n", hex.EncodeToString(key), remote.endpoint)
		// Start one initiator: the carrier must be established before testing
		// nested fragmentation, rather than synchronizing two handshake timers.
		if i == 0 {
			cfg += "persistent_keepalive_interval=25\n"
		}
		if err := node.wg.IpcSet(cfg); err != nil {
			t.Fatal(err)
		}
	}
	for _, node := range outer {
		waitHandshake(t, ctx, node.wg)
	}
	var transports []*Transport
	var peers []Peer
	for i, node := range outer {
		key, _ := GenerateKey()
		peer := testPeer(t, fmt.Sprint(i), key, netip.AddrPortFrom(node.ip, Port))
		network := node.network.(wgtransport.PacketNetwork)
		bind := &PacketBind{Listen: func(port uint16) (net.PacketConn, error) {
			return network.ListenPacket(netip.AddrPortFrom(node.ip, port))
		}}
		tr, err := Start(ctx, key, peer.IP, true, bind, "auto")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(tr.Close)
		transports = append(transports, tr)
		peers = append(peers, peer)
	}
	// Install a passive responder before enabling the initiating peer's
	// keepalive. This isolates the nested data path from simultaneous-initiation
	// backoff; ordinary Reconcile/refresh is covered by TestWireGuardLoopback.
	active, passive := 0, 1
	if peers[1].PublicKey < peers[0].PublicKey {
		active, passive = 1, 0
	}
	remoteKey, _ := decodeKey(peers[active].PublicKey)
	cfg := fmt.Sprintf("public_key=%s\nendpoint=%s\nallowed_ip=%s\n", hex.EncodeToString(remoteKey), peers[active].Endpoint, peers[active].AllowedIPs[0])
	if err := transports[passive].wg.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := transports[active].Reconcile(peers); err != nil {
		t.Fatal(err)
	}
	// Start the chosen initiator first. Iterating by node index could enable
	// the passive peer first and reintroduce simultaneous-initiation backoff.
	waitHandshake(t, ctx, transports[active].wg)
	waitHandshake(t, ctx, transports[passive].wg)
	if err := transports[passive].Reconcile(peers); err != nil {
		t.Fatal(err)
	}
	l, err := transports[1].Network.ListenTCP(netip.AddrPortFrom(peers[1].IP, 18082))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	served := make(chan error, 1)
	payload := bytes.Repeat([]byte("nested WireGuard MTU test; "), 4096)
	go func() {
		c, err := l.Accept()
		if err != nil {
			served <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(15 * time.Second))
		_, err = c.Write(payload)
		served <- err
	}()
	c, err := transports[0].Network.DialContext(ctx, "tcp", netip.AddrPortFrom(peers[1].IP, 18082).String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("nested payload corrupted")
	}
}

func waitHandshake(t *testing.T, ctx context.Context, wg wireGuardDevice) {
	// Production peers initiate on traffic, with persistent keepalive disabled.
	// These handshake-only tests explicitly generate traffic using a test keepalive.
	dump, err := wg.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(dump, "\n") {
		if strings.HasPrefix(line, "public_key=") {
			if err := wg.IpcSet(line + "\npersistent_keepalive_interval=1\n"); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Helper()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		dump, err := wg.IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(dump, "last_handshake_time_sec=") && !strings.Contains(dump, "last_handshake_time_sec=0\n") {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("WireGuard handshake timed out")
		case <-tick.C:
		}
	}
}

type countingDevice struct{ writes int }

func (d *countingDevice) IpcSet(string) error   { d.writes++; return nil }
func (*countingDevice) IpcGet() (string, error) { return "", nil }
func (*countingDevice) Close()                  {}

func TestReconcileDiff(t *testing.T) {
	a, b := testRecord(t, "a"), testRecord(t, "b")
	peers, _, err := BuildPeers("account", []Record{a, b}, []cfapi.Registration{registration("a", "100.96.0.1"), registration("b", "100.96.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	device := &countingDevice{}
	tr := &Transport{wg: device, public: a.PublicKey, ip: peers[0].IP}
	if err := tr.Reconcile(peers); err != nil {
		t.Fatal(err)
	}
	if err := tr.Reconcile(peers); err != nil {
		t.Fatal(err)
	}
	if device.writes != 1 {
		t.Fatalf("unchanged refresh rewrote device %d times", device.writes)
	}
	peers[1].Endpoint = netip.MustParseAddrPort("100.96.0.3:51821")
	if err := tr.Reconcile(peers); err != nil {
		t.Fatal(err)
	}
	if device.writes != 2 {
		t.Fatal("endpoint change not applied")
	}
}

func BenchmarkReconcileUnchanged(b *testing.B) {
	key, _ := GenerateKey()
	public, _ := key.Public()
	ip, _ := Address("account", public)
	peer := Peer{PublicKey: public, IP: ip, Endpoint: netip.MustParseAddrPort("100.96.0.2:51821"), AllowedIPs: []netip.Prefix{netip.PrefixFrom(ip, 128)}}
	peers := []Peer{peer}
	tr := &Transport{wg: &countingDevice{}, public: "self", peers: peers}
	b.ReportAllocs()
	for b.Loop() {
		if err := tr.Reconcile(peers); err != nil {
			b.Fatal(err)
		}
	}
}
