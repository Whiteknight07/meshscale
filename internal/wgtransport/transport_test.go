package wgtransport

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

// Application UDP output and TCP timers can run independently of TUN.Write.
// Shutdown must unblock a TUN reader and tolerate stack-originated packets even
// when WireGuard has stopped reading its TUN during device.Close.
func TestNetstackConcurrentOutputAndClose(t *testing.T) {
	for range 100 {
		tun, network, err := NewNetstack([]netip.Addr{netip.MustParseAddr("100.96.0.1")}, 1280)
		if err != nil {
			t.Fatal(err)
		}
		socket, err := network.(PacketNetwork).ListenPacket(netip.MustParseAddrPort("100.96.0.1:1234"))
		if err != nil {
			tun.Close()
			t.Fatal(err)
		}
		started := make(chan struct{})
		var workers sync.WaitGroup
		workers.Go(func() {
			close(started)
			for range 100 {
				if _, err := socket.WriteTo([]byte("shutdown"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("100.96.0.2:1234"))); err != nil {
					return
				}
			}
		})
		<-started
		if err := tun.Close(); err != nil {
			t.Fatal(err)
		}
		socket.Close()
		workers.Wait()
		if _, err := tun.Write([][]byte{{0x60}}, 0); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("late TUN write: %v", err)
		}
		if _, err := tun.Read([][]byte{make([]byte, 1280)}, make([]int, 1), 0); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("late TUN read: %v", err)
		}
		if err := tun.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNetstackCloseUnblocksRead(t *testing.T) {
	tun, _, err := NewNetstack([]netip.Addr{netip.MustParseAddr("100.96.0.1")}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	result := make(chan error, 1)
	go func() { _, err := tun.Read([][]byte{make([]byte, 1280)}, make([]int, 1), 0); result <- err }()
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close left a TUN reader blocked")
	}
}
