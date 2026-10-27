package secure

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

// Like gVisor, this socket signals closure with EOF rather than net.ErrClosed.
type eofPacketConn struct {
	net.PacketConn
	closed chan struct{}
}

func (c eofPacketConn) ReadFrom([]byte) (int, net.Addr, error) { <-c.closed; return 0, nil, io.EOF }
func (c eofPacketConn) Close() error                           { close(c.closed); return c.PacketConn.Close() }

func TestPacketBindCloseAndReopen(t *testing.T) {
	b := &PacketBind{Listen: func(uint16) (net.PacketConn, error) {
		c, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		return eofPacketConn{c, make(chan struct{})}, nil
	}}
	defer b.Close()
	for range 2 {
		recv, _, err := b.Open(0)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := recv[0]([][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1))
			done <- err
		}()
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed bind returned %v", err)
		}
	}
}

type benchmarkPacketConn struct {
	net.PacketConn
	addr *net.UDPAddr
}

func (c benchmarkPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c benchmarkPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	p[0] = 0
	return 1, c.addr, nil
}
func (c benchmarkPacketConn) LocalAddr() net.Addr { return c.addr }
func (c benchmarkPacketConn) Close() error        { return nil }

func BenchmarkPacketBindSend(b *testing.B) {
	bind := &PacketBind{socket: benchmarkPacketConn{}}
	ep, err := bind.ParseEndpoint("100.96.0.2:51821")
	if err != nil {
		b.Fatal(err)
	}
	packets := [][]byte{make([]byte, 1280)}
	b.ReportAllocs()
	for b.Loop() {
		if err := bind.Send(packets, ep); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkPacketBindReceive(b *testing.B) {
	bind := &PacketBind{Listen: func(uint16) (net.PacketConn, error) {
		return benchmarkPacketConn{addr: &net.UDPAddr{IP: net.IPv4(100, 96, 0, 2), Port: 51821}}, nil
	}}
	_, err := bind.ParseEndpoint("100.96.0.2:51821")
	if err != nil {
		b.Fatal(err)
	}
	receive, _, err := bind.Open(51821)
	if err != nil {
		b.Fatal(err)
	}
	defer bind.Close()
	packets := [][]byte{make([]byte, 1280)}
	sizes := make([]int, 1)
	endpoints := make([]conn.Endpoint, 1)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := receive[0](packets, sizes, endpoints); err != nil {
			b.Fatal(err)
		}
	}
}

type scopedEndpoint struct {
	conn.Endpoint
	local, remote netip.Addr
}

func (e scopedEndpoint) SrcIP() netip.Addr { return e.local }
func (e scopedEndpoint) DstIP() netip.Addr { return e.remote }
func TestFilterMeshCarrier(t *testing.T) {
	local := netip.MustParseAddr("100.96.0.7")
	peer := netip.MustParseAddr("100.96.0.2")
	for _, tc := range []struct {
		name                string
		source, destination netip.Addr
		want                int
	}{
		{"Mesh", peer, local, 1},
		{"GRO omitted pktinfo", peer, netip.Addr{}, 1},
		{"IPv4 socket mapped address", netip.MustParseAddr("::ffff:100.96.0.2"), local, 1},
		{"public source", netip.MustParseAddr("192.0.2.1"), local, 0},
		{"other destination", peer, netip.MustParseAddr("10.0.1.96"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packets := [][]byte{{1}}
			sizes := []int{1}
			endpoints := []conn.Endpoint{scopedEndpoint{local: tc.destination, remote: tc.source}}
			if got := filterMeshPackets(local, packets, sizes, endpoints, 1); got != tc.want {
				t.Fatalf("kept %d", got)
			}
		})
	}
	packets := [][]byte{{1}, {2}, {3}}
	sizes := []int{1, 1, 1}
	valid := scopedEndpoint{local: local, remote: peer}
	endpoints := []conn.Endpoint{nil, valid, valid}
	if n := filterMeshPackets(local, packets, sizes, endpoints, 3); n != 2 || packets[0][0] != 2 || packets[1][0] != 3 {
		t.Fatalf("bad compacted batch: %v", packets)
	}
}
func BenchmarkPacketFilterMeshBatch(b *testing.B) {
	local := netip.MustParseAddr("100.96.0.7")
	ep := scopedEndpoint{local: local, remote: netip.MustParseAddr("100.96.0.2")}
	packets := make([][]byte, 128)
	sizes := make([]int, 128)
	endpoints := make([]conn.Endpoint, 128)
	for i := range packets {
		packets[i] = make([]byte, 1280)
		sizes[i] = 1280
		endpoints[i] = ep
	}
	b.ReportAllocs()
	for b.Loop() {
		if filterMeshPackets(local, packets, sizes, endpoints, 128) != 128 {
			b.Fatal("dropped Mesh batch")
		}
	}
}
