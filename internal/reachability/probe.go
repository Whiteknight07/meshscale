// Package reachability checks Mesh addresses without raw sockets or root access.
package reachability

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const ProbeTimeout = 400 * time.Millisecond

// Prober returns nil only after a reply from the target address. Implementations
// must honor context cancellation and deadlines.
type Prober interface {
	Probe(context.Context, netip.Addr) error
}

// Network tries datagram ICMP, then TCP on a small set of service ports.
// Ports may include a configured meshscale SSH port; nil uses common defaults.
type Network struct {
	Ports []uint16
	echo  func(context.Context, netip.Addr) error
}

func (p Network) Probe(ctx context.Context, ip netip.Addr) error {
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	echo := p.echo
	if echo == nil {
		echo = echoReply
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("probe %s: %w", ip, err)
	}
	ports := p.Ports
	if len(ports) == 0 {
		ports = []uint16{22, 2222, 443, 80}
	}
	replies := make(chan error, len(ports)+1)
	go func() { replies <- echo(ctx, ip) }()
	// Give ICMP the full deadline: mobile RTTs can exceed 250ms. Start TCP
	// after an ICMP error or a short head start, so a slow echo still has time
	// to arrive while TCP fallback is in flight.
	timer := time.NewTimer(150 * time.Millisecond)
	defer timer.Stop()
	pendingEcho := 1
	var errs []error
	select {
	case err := <-replies:
		if err == nil {
			return nil
		}
		errs = append(errs, err)
		pendingEcho = 0
	case <-timer.C:
	}
	// DialContext observes cancellation; collect every result before returning.
	for _, port := range ports {
		go func(port uint16) {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
			if err == nil {
				conn.Close()
			}
			replies <- err
		}(port)
	}
	online := false
	for range len(ports) + pendingEcho {
		if err := <-replies; err == nil {
			online = true
			cancel()
		} else {
			errs = append(errs, err)
		}
	}
	if online {
		return nil
	}
	return fmt.Errorf("probe %s: %w", ip, errors.Join(errs...))
}

func echoReply(ctx context.Context, ip netip.Addr) error {
	network, bind, protocol := "udp4", "0.0.0.0", 1
	var request, reply icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	if ip.Is6() {
		network, bind, protocol = "udp6", "::", 58
		request, reply = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	// udp4/udp6 select SOCK_DGRAM ICMP on Linux and macOS, never raw ICMP.
	conn, err := icmp.ListenPacket(network, bind)
	if err != nil {
		return fmt.Errorf("datagram ICMP socket: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, ok := ctx.Deadline()
	if ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("ICMP deadline: %w", err)
		}
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("ICMP nonce: %w", err)
	}
	packet, err := (&icmp.Message{Type: request, Body: &icmp.Echo{ID: 1, Seq: 1, Data: nonce}}).Marshal(nil)
	if err != nil {
		return fmt.Errorf("marshal ICMP echo: %w", err)
	}
	if _, err := conn.WriteTo(packet, &net.UDPAddr{IP: net.IP(ip.AsSlice()), Zone: ip.Zone()}); err != nil {
		return fmt.Errorf("send ICMP echo: %w", err)
	}
	buf := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("receive ICMP echo: %w", err)
		}
		source, ok := peer.(*net.UDPAddr)
		if !ok || !source.IP.Equal(net.IP(ip.AsSlice())) {
			continue
		}
		msg, err := icmp.ParseMessage(protocol, buf[:n])
		if err != nil || msg.Type != reply || msg.Code != 0 {
			continue
		}
		body, ok := msg.Body.(*icmp.Echo)
		// Linux rewrites the echo ID to the ping socket's port. Match the random
		// payload and sequence instead, as well as the target address and reply type.
		if ok && body.Seq == 1 && bytes.Equal(body.Data, nonce) {
			return nil
		}
	}
}
