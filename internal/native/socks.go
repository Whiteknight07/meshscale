package native

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

// SOCKS5 supports CONNECT to numeric Mesh IPs only. It cannot become a general
// internet proxy and never changes OS DNS or routes.
func serveSOCKS(ctx context.Context, listener net.Listener, network Network) error {
	var workers sync.WaitGroup
	defer workers.Wait()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	slots := make(chan struct{}, 128)
	for {
		c, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			workers.Add(1)
			go func() { defer workers.Done(); defer func() { <-slots }(); socksConn(ctx, c, network) }()
		default:
			c.Close()
		}
	}
}
func socksConn(ctx context.Context, c net.Conn, network Network) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	var header [2]byte
	if _, err := io.ReadFull(c, header[:]); err != nil || header[0] != 5 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	noAuth := false
	for _, method := range methods {
		if method == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		c.Write([]byte{5, 255})
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	reply := func(code byte) { c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) }
	if req[0] != 5 || req[1] != 1 || req[2] != 0 {
		reply(7)
		return
	}
	var ip netip.Addr
	switch req[3] {
	case 1:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return
		}
		ip = netip.AddrFrom4(b)
	case 4:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return
		}
		ip = netip.AddrFrom16(b)
	default:
		reply(8)
		return
	}
	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return
	}
	addr := netip.AddrPortFrom(ip, binary.BigEndian.Uint16(port[:]))
	if !meshaddr.IsDevice(ip) || addr.Port() == 0 {
		reply(2)
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	peer, err := network.DialContext(dialCtx, "tcp", addr.String())
	if err != nil {
		reply(5)
		return
	}
	defer peer.Close()
	reply(0)
	c.SetDeadline(time.Time{})
	relay(ctx, c, peer)
}

func socksListener(address string) (net.Listener, error) {
	addr, err := netip.ParseAddrPort(address)
	if err != nil || !addr.Addr().IsLoopback() {
		return nil, fmt.Errorf("SOCKS address must be a numeric loopback IP and port")
	}
	return net.Listen("tcp", addr.String())
}
