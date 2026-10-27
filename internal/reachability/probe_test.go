package reachability

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

func TestNetworkFallback(t *testing.T) {
	for _, tc := range []struct {
		name                string
		echoOK, tcpOK, want bool
	}{
		{"echo reply", true, false, true},
		{"ICMP unavailable TCP open", false, true, true},
		{"ICMP unavailable TCP refused", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			port := uint16(listener.Addr().(*net.TCPAddr).Port)
			if !tc.tcpOK {
				listener.Close()
			}
			p := Network{Ports: []uint16{port}, echo: func(context.Context, netip.Addr) error {
				if tc.echoOK {
					return nil
				}
				return errors.New("datagram ICMP denied")
			}}
			err = p.Probe(context.Background(), netip.MustParseAddr("127.0.0.1"))
			if (err == nil) != tc.want {
				t.Fatalf("Probe: %v", err)
			}
		})
	}
}

// Explicitly opt in; ordinary tests never contact a real device. Run this as an
// unprivileged user too to verify datagram ICMP without CAP_NET_RAW.
func TestLiveProbe(t *testing.T) {
	targets := os.Getenv("MESHSCALE_TEST_PROBE_IPS")
	if targets == "" {
		t.Skip("set MESHSCALE_TEST_PROBE_IPS to comma-separated Mesh IPs")
	}
	for _, address := range strings.Split(targets, ",") {
		t.Run(address, func(t *testing.T) {
			ip, err := netip.ParseAddr(address)
			if err != nil || !meshaddr.IsDevice(ip) {
				t.Fatalf("invalid Mesh IP %q", address)
			}
			ctx, cancel := context.WithTimeout(context.Background(), ProbeTimeout)
			start := time.Now()
			icmpErr := echoReply(ctx, ip)
			cancel()
			startNetwork := time.Now()
			probeErr := (Network{}).Probe(context.Background(), ip)
			t.Logf("ICMP reply=%v duration=%s; ICMP/TCP reachable=%v duration=%s; ICMP error=%v; probe error=%v", icmpErr == nil, startNetwork.Sub(start), probeErr == nil, time.Since(startNetwork), icmpErr, probeErr)
		})
	}
}
