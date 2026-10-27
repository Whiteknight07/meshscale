//go:build linux

package secure

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// Explicit opt-in only: run this binary in a disposable container/network
// namespace with CAP_NET_ADMIN and /dev/net/tun, never in the host namespace.
func TestSecureLinuxTUN(t *testing.T) {
	if os.Getenv("MESHSCALE_TEST_SECURE_TUN") != "1" {
		t.Skip("requires an isolated Linux network namespace; see docs/secure.md")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	serverKey, _ := GenerateKey()
	clientKey, _ := GenerateKey()
	serverPeer := testPeer(t, "server", serverKey, netip.AddrPort{})
	clientPeer := testPeer(t, "client", clientKey, netip.AddrPort{})
	bind := &PacketBind{Listen: func(uint16) (net.PacketConn, error) { return net.ListenPacket("udp4", "127.0.0.1:0") }}
	server, err := Start(ctx, serverKey, serverPeer.IP, false, bind, "auto")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	bind.mu.RLock()
	serverPeer.Endpoint = bind.socket.LocalAddr().(*net.UDPAddr).AddrPort()
	bind.mu.RUnlock()
	client, endpoint := loopbackTransport(t, clientKey, clientPeer.IP)
	clientPeer.Endpoint = endpoint
	for _, tr := range []*Transport{server, client} {
		if err := tr.Reconcile([]Peer{serverPeer, clientPeer}); err != nil {
			t.Fatal(err)
		}
	}
	waitHandshake(t, ctx, server.wg)
	waitHandshake(t, ctx, client.wg)
	iface, err := net.InterfaceByName("meshsecure0")
	if err != nil || iface.MTU != server.MTU {
		t.Fatalf("secure TUN missing or invalid: %v", err)
	}
	l, err := server.Network.ListenTCP(netip.AddrPortFrom(serverPeer.IP, 18085))
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
		if source != clientPeer.IP.String() {
			served <- &net.AddrError{Err: "lost secure source identity", Addr: source}
			return
		}
		_, err = c.Write([]byte("secure TUN"))
		served <- err
	}()
	c, err := client.Network.DialContext(ctx, "tcp", netip.AddrPortFrom(serverPeer.IP, 18085).String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len("secure TUN"))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "secure TUN" {
		t.Fatalf("TUN payload=%q error=%v", got, err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	server.Close()
	if _, err := net.InterfaceByName("meshsecure0"); err == nil {
		t.Fatal("TUN interface survived cleanup")
	}
}
