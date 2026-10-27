package native

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/localstate"
)

type echoNetwork struct{}

func (echoNetwork) DialContext(context.Context, string, string) (net.Conn, error) {
	a, b := net.Pipe()
	go func() { defer b.Close(); io.Copy(b, b) }()
	return &addressedConn{Conn: a, local: &net.TCPAddr{IP: net.ParseIP("100.96.0.4"), Port: 12345}, remote: &net.TCPAddr{IP: net.ParseIP("100.96.0.2"), Port: 22}}, nil
}
func (echoNetwork) ListenTCP(netip.AddrPort) (net.Listener, error) {
	return nil, fmt.Errorf("not implemented")
}
func TestControlDialMeshOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "native")
	if err := localstate.Dir(dir); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socketPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ctrl := &control{transport: &Transport{Network: echoNetwork{}}, cancel: cancel, listeners: map[uint64]net.Listener{}}
	done := make(chan error, 1)
	go func() { done <- ctrl.serve(ctx, listener) }()
	defer func() {
		cancel()
		ctrl.close()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	client := &Client{Dir: dir}
	dialCtx, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	if c, err := client.DialContext(dialCtx, "tcp", "1.1.1.1:80"); err == nil {
		c.Close()
		t.Fatal("proxy accepted non-Mesh IP")
	}
	c, err := client.DialContext(dialCtx, "tcp", "100.96.0.2:22")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if c.RemoteAddr().String() != "100.96.0.2:22" || c.LocalAddr().String() != "100.96.0.4:12345" {
		t.Fatal("lost original Mesh identity")
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "hello" {
		t.Fatalf("echo=%q err=%v", b, err)
	}
}
func TestSOCKSHandshakeAndRestrictions(t *testing.T) {
	for _, outside := range []bool{false, true} {
		t.Run(fmt.Sprint(outside), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a, b := net.Pipe()
			defer a.Close()
			done := make(chan struct{})
			go func() { socksConn(ctx, b, echoNetwork{}); close(done) }()
			defer func() { cancel(); <-done }()
			a.SetDeadline(time.Now().Add(3 * time.Second))
			a.Write([]byte{5, 1, 0})
			reply := make([]byte, 2)
			if _, err := io.ReadFull(a, reply); err != nil || reply[1] != 0 {
				t.Fatal("SOCKS greeting failed")
			}
			ip := []byte{100, 96, 0, 2}
			if outside {
				ip = []byte{1, 1, 1, 1}
			}
			request := append([]byte{5, 1, 0, 1}, ip...)
			request = append(request, 0, 22)
			a.Write(request)
			reply = make([]byte, 10)
			if _, err := io.ReadFull(a, reply); err != nil {
				t.Fatal(err)
			}
			if outside {
				if reply[1] != 2 {
					t.Fatal("outside Mesh accepted")
				}
				return
			}
			if reply[1] != 0 {
				t.Fatalf("CONNECT failed %v", reply)
			}
			a.Write([]byte("hello"))
			out := make([]byte, 5)
			if _, err := io.ReadFull(a, out); err != nil || string(out) != "hello" {
				t.Fatalf("echo=%q err=%v", out, err)
			}
		})
	}
	if l, err := socksListener("0.0.0.0:1080"); err == nil {
		l.Close()
		t.Fatal("wildcard SOCKS listener accepted")
	}
}

type listenNetwork struct{ created chan net.Listener }

func (l listenNetwork) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}
func (l listenNetwork) ListenTCP(netip.AddrPort) (net.Listener, error) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	l.created <- raw
	return &meshListener{raw}, nil
}

type meshListener struct{ net.Listener }

func (l *meshListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &addressedConn{Conn: c, local: &net.TCPAddr{IP: net.ParseIP("100.96.0.4"), Port: 22}, remote: &net.TCPAddr{IP: net.ParseIP("100.96.0.2"), Port: 1234}}, nil
}
func TestControlListenerLease(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "native")
	if err := localstate.Dir(dir); err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("unix", socketPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	network := listenNetwork{created: make(chan net.Listener, 1)}
	ctrl := &control{transport: &Transport{Network: network}, ips: []netip.Addr{netip.MustParseAddr("100.96.0.4")}, cancel: cancel, listeners: map[uint64]net.Listener{}}
	done := make(chan error, 1)
	go func() { done <- ctrl.serve(ctx, raw) }()
	defer func() {
		cancel()
		ctrl.close()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	client := &Client{Dir: dir}
	if l, err := client.ListenTCP(ctx, netip.MustParseAddrPort("100.96.0.99:22")); err == nil {
		l.Close()
		t.Fatal("listened as another device")
	}
	listener, err := client.ListenTCP(ctx, netip.MustParseAddrPort("100.96.0.4:22"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	systemListener := <-network.created
	received := make(chan net.Conn, 1)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			received <- c
		}
	}()
	caller, err := net.Dial("tcp", systemListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()
	var c net.Conn
	select {
	case c = <-received:
	case <-ctx.Done():
		t.Fatal("netstack accept timed out")
	}
	defer c.Close()
	if c.RemoteAddr().String() != "100.96.0.2:1234" {
		t.Fatal("listener lost Mesh source identity")
	}
	caller.Write([]byte("hello"))
	b := make([]byte, 5)
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "hello" {
		t.Fatal("listener transport failed")
	}
	listener.Close()
	if c, err := listener.Accept(); err == nil {
		c.Close()
		t.Fatal("closed lease still accepts")
	}
}

// An outstanding remote Accept must not prevent the shared network control
// from shutting down. Secure mode uses ServeNetwork and does not own ctrl.close.
func TestServeNetworkCancellationWithListener(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "control")
	if err := localstate.Dir(dir); err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("unix", socketPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	network := listenNetwork{created: make(chan net.Listener, 1)}
	ip := netip.MustParseAddr("fd6d:6573:6873::1234")
	done := make(chan error, 1)
	go func() {
		done <- ServeNetwork(ctx, raw, network, []netip.Addr{ip}, func() bool { return true }, func(addr netip.Addr) bool { return addr == ip })
	}()
	client := &Client{Dir: dir}
	listener, err := client.ListenTCP(ctx, netip.AddrPortFrom(ip, 2222))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if c != nil {
			c.Close()
		}
		accepted <- err
	}()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("network control deadlocked with a leased listener")
	}
	select {
	case err := <-accepted:
		if err == nil {
			t.Fatal("accept succeeded after cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("remote Accept did not stop")
	}
}
