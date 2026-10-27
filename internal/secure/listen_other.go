//go:build !linux

package secure

import (
	"fmt"
	"net"
	"net/netip"
)

func listenSecureTCP(netip.AddrPort) (net.Listener, error) {
	return nil, fmt.Errorf("secure system interface requires Linux")
}
