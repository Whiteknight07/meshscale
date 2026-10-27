package native

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Whiteknight07/meshscale/internal/backend"
	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

type request struct {
	Op       string `json:"op"`
	Address  string `json:"address,omitempty"`
	Listener uint64 `json:"listener,omitempty"`
}
type response struct {
	Error    string         `json:"error,omitempty"`
	Status   backend.Status `json:"status"`
	Listener uint64         `json:"listener,omitempty"`
	Local    string         `json:"local,omitempty"`
	Remote   string         `json:"remote,omitempty"`
}

func socketPath(dir string) string      { return filepath.Join(dir, "control.sock") }
func sendLine(w io.Writer, v any) error { return json.NewEncoder(w).Encode(v) }
func readLine(r *bufio.Reader, v any) error {
	b, err := r.ReadSlice('\n')
	if err != nil {
		return err
	}
	if json.Unmarshal(b, v) != nil {
		return fmt.Errorf("invalid native control message")
	}
	return nil
}

type Client struct{ Dir string }

var _ backend.Backend = (*Client)(nil)

func (c *Client) open(ctx context.Context, req request) (net.Conn, response, error) {
	var reply response
	if err := localstate.Dir(c.Dir); err != nil {
		return nil, reply, err
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath(c.Dir))
	if err != nil {
		return nil, reply, fmt.Errorf("native daemon is unavailable; run meshscale up: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	if deadline, ok := ctx.Deadline(); ok {
		raw.SetDeadline(deadline)
	}
	reader := bufio.NewReader(raw)
	if err = sendLine(raw, req); err == nil {
		err = readLine(reader, &reply)
	}
	stop()
	if err == nil && reply.Error != "" {
		err = errors.New(reply.Error)
	}
	if err != nil {
		raw.Close()
		return nil, reply, err
	}
	raw.SetDeadline(time.Time{})
	return &bufferedConn{Conn: raw, reader: reader}, reply, nil
}

func (c *Client) Status(ctx context.Context) (backend.Status, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, reply, err := c.open(ctx, request{Op: "status"})
	if err != nil {
		return backend.Status{State: "disconnected", Reason: "native daemon is not running"}, err
	}
	raw.Close()
	return reply.Status, nil
}
func (c *Client) Registration(context.Context) (backend.Registration, error) {
	s, err := LoadState(c.Dir)
	if err != nil {
		return backend.Registration{}, err
	}
	// The admin API omits the device API's t. prefix.
	id := s.Registration.ID
	if len(id) > 2 {
		id = id[2:]
	}
	return backend.Registration{ID: id, RegistrationID: id, ConnectorID: s.NodeID}, nil
}
func (c *Client) Connect(ctx context.Context) error {
	status, err := c.Status(ctx)
	if err != nil {
		return err
	}
	if !status.Connected {
		return fmt.Errorf("native daemon is still connecting")
	}
	return nil
}
func (c *Client) Disconnect(ctx context.Context) error {
	// An offline daemon has nothing to disconnect; malformed/private state errors
	// remain visible and must never trigger a fallback to another backend.
	if err := localstate.Dir(c.Dir); err != nil {
		return err
	}
	if _, err := os.Lstat(socketPath(c.Dir)); os.IsNotExist(err) {
		return nil
	}
	raw, _, err := c.open(ctx, request{Op: "stop"})
	if err != nil {
		return err
	}
	defer raw.Close()
	// The daemon closes this stream only after WireGuard, routes and listeners
	// are closed and its state lock has been released.
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	_, err = io.Copy(io.Discard, raw)
	return err
}
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("native local control supports TCP only")
	}
	raw, reply, err := c.open(ctx, request{Op: "dial", Address: address})
	if err != nil {
		return nil, err
	}
	return wrapAddresses(raw, reply), nil
}
func (c *Client) ListenTCP(ctx context.Context, address netip.AddrPort) (net.Listener, error) {
	lease, reply, err := c.open(ctx, request{Op: "listen", Address: address.String()})
	if err != nil {
		return nil, err
	}
	lctx, cancel := context.WithCancel(ctx)
	l := &remoteListener{client: c, lease: lease, id: reply.Listener, addr: address, ctx: lctx, cancel: cancel}
	go func() { io.Copy(io.Discard, lease); l.Close() }()
	return l, nil
}

type remoteListener struct {
	client *Client
	lease  net.Conn
	id     uint64
	addr   netip.AddrPort
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func (l *remoteListener) Accept() (net.Conn, error) {
	raw, reply, err := l.client.open(l.ctx, request{Op: "accept", Listener: l.id})
	if err != nil {
		return nil, err
	}
	return wrapAddresses(raw, reply), nil
}
func (l *remoteListener) Close() error   { l.once.Do(func() { l.cancel(); l.lease.Close() }); return nil }
func (l *remoteListener) Addr() net.Addr { return net.TCPAddrFromAddrPort(l.addr) }

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
func (c *bufferedConn) CloseWrite() error          { return closeWrite(c.Conn) }

type addressedConn struct {
	net.Conn
	local, remote net.Addr
}

func (c *addressedConn) LocalAddr() net.Addr  { return c.local }
func (c *addressedConn) RemoteAddr() net.Addr { return c.remote }
func (c *addressedConn) CloseWrite() error    { return closeWrite(c.Conn) }
func wrapAddresses(c net.Conn, reply response) net.Conn {
	local, _ := net.ResolveTCPAddr("tcp", reply.Local)
	remote, _ := net.ResolveTCPAddr("tcp", reply.Remote)
	return &addressedConn{Conn: c, local: local, remote: remote}
}
func closeWrite(c net.Conn) error {
	if half, ok := c.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func relay(ctx context.Context, a, b net.Conn) {
	stop := context.AfterFunc(ctx, func() { a.Close(); b.Close() })
	defer stop()
	defer a.Close()
	defer b.Close()
	done := make(chan struct{})
	go func() { io.Copy(a, b); closeWrite(a); close(done) }()
	io.Copy(b, a)
	closeWrite(b)
	<-done
}

// control serves only a private Unix socket, with a bounded set of sessions.
// Listener leases keep SSH addresses exclusive and preserve actual peer IPs.
type control struct {
	transport *Transport
	ips       []netip.Addr
	cancel    context.CancelFunc
	mu        sync.Mutex
	listeners map[uint64]net.Listener
	next      uint64
	stopping  []net.Conn
	workers   sync.WaitGroup
}

func (s *control) serve(ctx context.Context, listener net.Listener) error {
	slots := make(chan struct{}, 128)
	defer func() {
		s.cancel()
		s.close()
		s.workers.Wait()
	}()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
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
			s.workers.Add(1)
			go func() { defer s.workers.Done(); defer func() { <-slots }(); s.handle(ctx, c) }()
		default:
			c.Close()
		}
	}
}
func (s *control) close() {
	s.mu.Lock()
	for _, l := range s.listeners {
		l.Close()
	}
	s.mu.Unlock()
}
func (s *control) finishStop() {
	for _, c := range s.stopping {
		c.Close()
	}
}
func meshTarget(raw string) (netip.AddrPort, error) {
	addr, err := netip.ParseAddrPort(raw)
	if err != nil || !meshaddr.IsDevice(addr.Addr()) || addr.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("target must be a numeric Mesh IP and port")
	}
	return addr, nil
}
func (s *control) handle(ctx context.Context, raw net.Conn) {
	keep := false
	defer func() {
		if !keep {
			raw.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(raw)
	var req request
	if readLine(reader, &req) != nil {
		return
	}
	raw.SetDeadline(time.Time{})
	fail := func(err error) { _ = sendLine(raw, response{Error: err.Error()}) }
	switch req.Op {
	case "status":
		status := backend.Status{State: "connecting", Reason: "waiting for WireGuard edge handshake"}
		if s.transport.Healthy() {
			status = backend.Status{State: "connected", Connected: true}
		}
		_ = sendLine(raw, response{Status: status})
	case "stop":
		s.mu.Lock()
		s.stopping = append(s.stopping, raw)
		s.mu.Unlock()
		if sendLine(raw, response{}) == nil {
			keep = true
		}
		// Keep the stop stream open across daemon cleanup.
		stop()
		s.cancel()
	case "dial":
		addr, err := meshTarget(req.Address)
		if s.transport.target != nil {
			addr, err = netip.ParseAddrPort(req.Address)
			if err == nil && (!s.transport.target(addr.Addr()) || addr.Port() == 0) {
				err = fmt.Errorf("target is outside the permitted overlay")
			}
		}
		if err != nil {
			fail(err)
			return
		}
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		peer, err := s.transport.Network.DialContext(dialCtx, "tcp", addr.String())
		if err != nil {
			fail(err)
			return
		}
		defer peer.Close()
		if sendLine(raw, response{Local: peer.LocalAddr().String(), Remote: peer.RemoteAddr().String()}) != nil {
			return
		}
		relay(ctx, &bufferedConn{Conn: raw, reader: reader}, peer)
	case "listen":
		addr, err := meshTarget(req.Address)
		if s.transport.target != nil {
			addr, err = netip.ParseAddrPort(req.Address)
			if err == nil && (!s.transport.target(addr.Addr()) || addr.Port() == 0) {
				err = fmt.Errorf("target is outside the permitted overlay")
			}
		}
		if err != nil {
			fail(err)
			return
		}
		local := false
		for _, ip := range s.ips {
			if addr.Addr() == ip {
				local = true
			}
		}
		if !local {
			fail(fmt.Errorf("listener address is not this registration's Mesh IP"))
			return
		}
		listener, err := s.transport.Network.ListenTCP(addr)
		if err != nil {
			fail(err)
			return
		}
		defer listener.Close()
		s.mu.Lock()
		s.next++
		id := s.next
		s.listeners[id] = listener
		s.mu.Unlock()
		defer func() { s.mu.Lock(); delete(s.listeners, id); s.mu.Unlock() }()
		if sendLine(raw, response{Listener: id}) != nil {
			return
		}
		io.Copy(io.Discard, reader)
	case "accept":
		s.mu.Lock()
		listener := s.listeners[req.Listener]
		s.mu.Unlock()
		if listener == nil {
			fail(fmt.Errorf("native listener is closed"))
			return
		}
		peer, err := listener.Accept()
		if err != nil {
			fail(err)
			return
		}
		defer peer.Close()
		if sendLine(raw, response{Local: peer.LocalAddr().String(), Remote: peer.RemoteAddr().String()}) != nil {
			return
		}
		relay(ctx, &bufferedConn{Conn: raw, reader: reader}, peer)
	default:
		fail(fmt.Errorf("unknown native control operation"))
	}
}
