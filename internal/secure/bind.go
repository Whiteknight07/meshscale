package secure

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// PacketBind lets the outer WireGuard datagrams use either OS Mesh sockets or
// the native backend's UDP netstack. There is no third-party relay or key server.
type PacketBind struct {
	Listen    func(uint16) (net.PacketConn, error)
	mu        sync.RWMutex
	socket    net.PacketConn
	closed    chan struct{}
	endpoints sync.Map
}
type endpoint struct {
	addr netip.AddrPort
	udp  *net.UDPAddr
}

func (e *endpoint) ClearSrc()           {}
func (e *endpoint) SrcToString() string { return "" }
func (e *endpoint) DstToString() string { return e.addr.String() }
func (e *endpoint) DstToBytes() []byte  { return e.addr.AppendTo(nil) }
func (e *endpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (e *endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (b *PacketBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	a = netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
	ep := b.cachedEndpoint(a)
	b.endpoints.Store(a, ep)
	return ep, nil
}
func (*PacketBind) BatchSize() int { return 1 }
func (*PacketBind) SetMark(mark uint32) error {
	if mark != 0 {
		return fmt.Errorf("packet bind does not support marks")
	}
	return nil
}
func (b *PacketBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if b.Listen == nil {
		return nil, 0, fmt.Errorf("packet bind requires a listener")
	}
	s, err := b.Listen(port)
	if err != nil {
		return nil, 0, err
	}
	a, err := netip.ParseAddrPort(s.LocalAddr().String())
	if err != nil {
		s.Close()
		return nil, 0, err
	}
	b.socket = s
	b.closed = make(chan struct{})
	closed := b.closed
	receive := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		n, addr, err := s.ReadFrom(packets[0])
		if err != nil {
			// gVisor returns EOF when a UDP socket closes. WireGuard requires
			// net.ErrClosed to stop its receive loop immediately before rebinding.
			select {
			case <-closed:
				return 0, net.ErrClosed
			default:
			}
			return 0, err
		}
		var ip netip.AddrPort
		if udp, ok := addr.(*net.UDPAddr); ok {
			ip = udp.AddrPort()
			ip = netip.AddrPortFrom(ip.Addr().Unmap(), ip.Port())
		} else {
			ip, err = netip.ParseAddrPort(addr.String())
		}
		if err != nil {
			return 0, err
		}
		sizes[0], endpoints[0] = n, b.cachedEndpoint(ip)
		return 1, nil
	}
	return []conn.ReceiveFunc{receive}, a.Port(), nil
}
func (b *PacketBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket == nil {
		return nil
	}
	close(b.closed)
	err := b.socket.Close()
	b.socket = nil
	return err
}
func (b *PacketBind) Send(packets [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.RLock()
	socket := b.socket
	b.mu.RUnlock()
	if socket == nil {
		return net.ErrClosed
	}
	for _, p := range packets {
		if _, err := socket.WriteTo(p, e.udp); err != nil {
			return err
		}
	}
	return nil
}

// Configured endpoints are reused by receive and send. Unknown sources are not
// cached, preventing unauthenticated datagrams from growing the map.
func (b *PacketBind) cachedEndpoint(a netip.AddrPort) *endpoint {
	if ep, ok := b.endpoints.Load(a); ok {
		return ep.(*endpoint)
	}
	return &endpoint{addr: a, udp: net.UDPAddrFromAddrPort(a)}
}
