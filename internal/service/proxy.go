package service

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"sync"
)

type Forward struct {
	Port     int `json:"port"`
	MeshPort int `json:"mesh_port"`
}

func (f Forward) Validate() error {
	if f.Port < 1 || f.Port > 65535 || f.MeshPort < 1 || f.MeshPort > 65535 {
		return fmt.Errorf("ports must be between 1 and 65535")
	}
	return nil
}

type ListenFunc func(context.Context, int) ([]net.Listener, error)
type proxy struct {
	forward   Forward
	cancel    context.CancelFunc
	listeners []net.Listener
	workers   sync.WaitGroup
}

// Proxies limits each forward to 128 simultaneous TCP streams.
type Proxies struct {
	mu      sync.Mutex
	active  map[int]*proxy
	desired map[int]Forward
	Listen  ListenFunc
	Save    func([]Forward) error
}

// Load retains pending forwards while the backend connects. Call before Run.
func (p *Proxies) Load(forwards []Forward) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	desired := make(map[int]Forward, len(forwards))
	for _, f := range forwards {
		if err := f.Validate(); err != nil {
			return err
		}
		if _, ok := desired[f.MeshPort]; ok {
			return fmt.Errorf("duplicate saved mesh port")
		}
		desired[f.MeshPort] = f
	}
	p.desired = desired
	return nil
}
func (p *Proxies) desiredLocked() []Forward {
	out := make([]Forward, 0, len(p.desired))
	for _, f := range p.desired {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MeshPort < out[j].MeshPort })
	return out
}
func (p *Proxies) listLocked() []Forward {
	out := make([]Forward, 0, len(p.active))
	for _, entry := range p.active {
		out = append(out, entry.forward)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MeshPort < out[j].MeshPort })
	return out
}
func (p *Proxies) List() []Forward                          { p.mu.Lock(); defer p.mu.Unlock(); return p.listLocked() }
func (p *Proxies) Add(ctx context.Context, f Forward) error { return p.add(ctx, f, true) }

// Restore starts a previously saved forward without rewriting desired state.
func (p *Proxies) Restore(ctx context.Context, f Forward) error { return p.add(ctx, f, false) }
func (p *Proxies) add(ctx context.Context, f Forward, persist bool) error {
	if err := f.Validate(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !persist {
		if desired, ok := p.desired[f.MeshPort]; !ok || desired != f {
			return nil
		}
	}
	if existing := p.active[f.MeshPort]; existing != nil {
		if existing.forward == f {
			return nil
		}
		return fmt.Errorf("mesh port %d is already forwarded; turn it off first", f.MeshPort)
	}
	child, cancel := context.WithCancel(ctx)
	listeners, err := p.Listen(child, f.MeshPort)
	if err != nil {
		cancel()
		return err
	}
	entry := &proxy{forward: f, cancel: cancel, listeners: listeners}
	if len(listeners) == 0 {
		cancel()
		return fmt.Errorf("no Mesh listeners")
	}
	if p.active == nil {
		p.active = make(map[int]*proxy)
	}
	p.active[f.MeshPort] = entry
	if p.desired == nil {
		p.desired = make(map[int]Forward)
	}
	previous, wasDesired := p.desired[f.MeshPort]
	p.desired[f.MeshPort] = f
	if persist && p.Save != nil {
		if err := p.Save(p.desiredLocked()); err != nil {
			delete(p.active, f.MeshPort)
			if wasDesired {
				p.desired[f.MeshPort] = previous
			} else {
				delete(p.desired, f.MeshPort)
			}
			cancel()
			for _, l := range listeners {
				l.Close()
			}
			return err
		}
	}
	slots := make(chan struct{}, 128)
	for _, l := range listeners {
		entry.workers.Go(func() {
			stop := context.AfterFunc(child, func() { l.Close() })
			defer stop()
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				select {
				case slots <- struct{}{}:
					entry.workers.Go(func() { defer func() { <-slots }(); proxyConn(child, conn, f.Port) })
				default:
					conn.Close()
				}
			}
		})
	}
	return nil
}
func stopProxy(entry *proxy) {
	entry.cancel()
	for _, l := range entry.listeners {
		l.Close()
	}
	entry.workers.Wait()
}

// Remove(0) disables every forward. Persistence succeeds before listeners close.
func (p *Proxies) Remove(port int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	previous := make(map[int]Forward, len(p.desired))
	for key, f := range p.desired {
		previous[key] = f
		if port == 0 || key == port {
			delete(p.desired, key)
		}
	}
	var removed []*proxy
	for key, entry := range p.active {
		if port == 0 || key == port {
			removed = append(removed, entry)
			delete(p.active, key)
		}
	}
	if p.Save != nil {
		if err := p.Save(p.desiredLocked()); err != nil {
			p.desired = previous
			for _, entry := range removed {
				p.active[entry.forward.MeshPort] = entry
			}
			return err
		}
	}
	for _, entry := range removed {
		stopProxy(entry)
	}
	return nil
}

// Close preserves the saved configuration for the next daemon start.
func (p *Proxies) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, entry := range p.active {
		stopProxy(entry)
		delete(p.active, key)
	}
}
func halfClose(c net.Conn) {
	if half, ok := c.(interface{ CloseWrite() error }); ok {
		_ = half.CloseWrite()
	}
}
func proxyConn(ctx context.Context, mesh net.Conn, port int) {
	defer mesh.Close()
	local, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return
	}
	defer local.Close()
	stop := context.AfterFunc(ctx, func() { mesh.Close(); local.Close() })
	defer stop()
	done := make(chan struct{})
	go func() { io.Copy(local, mesh); halfClose(local); close(done) }()
	io.Copy(mesh, local)
	halfClose(mesh)
	<-done
}
