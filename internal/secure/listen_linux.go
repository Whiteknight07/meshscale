//go:build linux

package secure

import (
	"context"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// Binding to the TUN device is essential: source-address checks alone cannot
// prove a packet arrived through WireGuard rather than a spoofed host route.
func listenSecureTCP(a netip.AddrPort) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var inner error
		err := raw.Control(func(fd uintptr) {
			inner = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "meshsecure0")
		})
		if err != nil {
			return err
		}
		return inner
	}}
	return lc.Listen(context.Background(), "tcp6", a.String())
}
