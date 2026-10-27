// Package wgtransport owns the WireGuard/TUN/netstack setup shared by the
// native Mesh backend and the end-to-end secure overlay.
package wgtransport

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/Whiteknight07/meshscale/internal/wgtransport/netstack"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type Network interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	ListenTCP(netip.AddrPort) (net.Listener, error)
}

// PacketNetwork is the UDP carrier needed when nesting secure WireGuard over a
// native userspace Mesh backend. It avoids exposing a concrete gVisor type.
type PacketNetwork interface {
	ListenPacket(netip.AddrPort) (net.PacketConn, error)
}
type stackNetwork struct{ *netstack.Net }

func (s stackNetwork) ListenTCP(a netip.AddrPort) (net.Listener, error) {
	return s.ListenTCPAddrPort(a)
}
func (s stackNetwork) ListenPacket(a netip.AddrPort) (net.PacketConn, error) {
	return s.ListenUDPAddrPort(a)
}

type OSNetwork struct{}

func (OSNetwork) DialContext(ctx context.Context, n, a string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, n, a)
}
func (OSNetwork) ListenTCP(a netip.AddrPort) (net.Listener, error) {
	return net.Listen("tcp", a.String())
}
func (OSNetwork) ListenPacket(a netip.AddrPort) (net.PacketConn, error) {
	return net.ListenUDP("udp4", net.UDPAddrFromAddrPort(a))
}
func NewNetstack(ips []netip.Addr, mtu int) (tun.Device, Network, error) {
	t, stack, err := netstack.CreateNetTUN(ips, nil, mtu)
	if err != nil {
		return nil, nil, fmt.Errorf("create WireGuard netstack: %w", err)
	}
	return t, stackNetwork{stack}, nil
}

// Start owns t on every path. Callers own any OS route cleanup separately.
func Start(t tun.Device, bind conn.Bind, configuration, label string) (*device.Device, error) {
	wg := device.NewDevice(t, bind, device.NewLogger(device.LogLevelError, label))
	err := wg.IpcSet(configuration)
	if err == nil {
		err = wg.Up()
	}
	if err != nil {
		wg.Close()
		return nil, fmt.Errorf("initialize WireGuard: %w", err)
	}
	return wg, nil
}
