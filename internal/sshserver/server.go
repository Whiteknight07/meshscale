package sshserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

type Server struct {
	Signer ssh.Signer
	Auth   *Authorizer
}

// Listen binds every address explicitly and closes all listeners on any error.
// It never falls back to a wildcard or to a non-Mesh interface.
func Listen(ips []netip.Addr, port int) ([]net.Listener, error) {
	if len(ips) == 0 || port < 1 || port > 65535 {
		return nil, fmt.Errorf("a Mesh address and port 1-65535 are required")
	}
	assigned, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	local := map[netip.Addr]bool{}
	for _, address := range assigned {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil {
			local[prefix.Addr().Unmap()] = true
		}
	}
	var listeners []net.Listener
	fail := func(err error) ([]net.Listener, error) {
		for _, l := range listeners {
			l.Close()
		}
		return nil, err
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if !meshaddr.IsDevice(ip) || !local[ip] {
			return fail(fmt.Errorf("refusing to listen on %s: not a locally assigned Mesh device IP", ip))
		}
		network := "tcp6"
		if ip.Is4() {
			network = "tcp4"
		}
		address := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		l, err := net.Listen(network, address)
		if err != nil {
			return fail(fmt.Errorf("listen on Mesh IP %s: %w; if OpenSSH owns this port (including 0.0.0.0 or ::), use --port or configure its ListenAddress to exclude the Mesh IP", address, err))
		}
		listeners = append(listeners, l)
	}
	return listeners, nil
}

// Serve bounds concurrent connections and closes sessions when ctx is canceled.
func (s *Server) Serve(ctx context.Context, listeners []net.Listener) error {
	if s.Signer == nil || s.Auth == nil || len(listeners) == 0 {
		return fmt.Errorf("SSH server needs a host key, authorizer and listeners")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() {
		for _, l := range listeners {
			l.Close()
		}
	})
	defer stop()
	slots := make(chan struct{}, 128)
	failures := make(chan error, len(listeners))
	var workers sync.WaitGroup
	defer workers.Wait()
	for _, l := range listeners {
		workers.Go(func() {
			for {
				conn, err := l.Accept()
				if err != nil {
					failures <- err
					return
				}
				select {
				case slots <- struct{}{}:
					workers.Go(func() { defer func() { <-slots }(); s.handleConn(ctx, conn) })
				default:
					s.Auth.audit("deny", Identity{}, conn.RemoteAddr().String(), "", "connection limit reached")
					conn.Close()
				}
			}
		})
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-failures:
		wasCanceled := ctx.Err() != nil
		cancel()
		if wasCanceled {
			return nil
		}
		return err
	}
}

func (s *Server) handleConn(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	raw.SetDeadline(time.Now().Add(20 * time.Second))
	_, authenticated := raw.(interface{ wireGuardAuthenticated() })
	var target *localUser
	config := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-meshscale",
		NoClientAuth:  true,
		MaxAuthTries:  1,
		AuthLogCallback: func(meta ssh.ConnMetadata, method string, err error) {
			if method != "none" && err != nil {
				ip, _, _ := net.SplitHostPort(meta.RemoteAddr().String())
				s.Auth.audit("deny", Identity{}, ip, meta.User(), "only Mesh-authorized none authentication is supported")
			}
		},
		NoClientAuthCallback: func(meta ssh.ConnMetadata) (*ssh.Permissions, error) {
			var err error
			target, err = s.Auth.authorizeConnection(ctx, meta.RemoteAddr(), meta.User(), authenticated)
			if err != nil {
				var missing *missingPolicyError
				if errors.As(err, &missing) {
					return nil, &ssh.BannerError{Err: err, Message: "meshscale: " + err.Error() + "\r\n"}
				}
				return nil, err
			}
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(s.Signer)
	conn, channels, requests, err := ssh.NewServerConn(raw, config)
	if err != nil {
		return
	}
	defer conn.Close()
	if target == nil {
		return
	} // No session can exist without the callback's approval.
	raw.SetDeadline(time.Time{})
	go func() {
		for request := range requests {
			ok := request.Type == "keepalive@openssh.com"
			if !ok {
				s.Auth.audit("deny", target.identity, target.identity.IP.String(), conn.User(), "unsupported global request: "+request.Type)
			}
			request.Reply(ok, nil)
		}
	}()
	slots := make(chan struct{}, 16)
	for channel := range channels {
		if channel.ChannelType() != "session" {
			channel.Reject(ssh.Prohibited, "meshscale: forwarding and non-session channels are disabled")
			s.Auth.audit("deny", target.identity, target.identity.IP.String(), conn.User(), "forwarding/non-session channel disabled")
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			s.Auth.audit("deny", target.identity, target.identity.IP.String(), conn.User(), "session limit reached")
			channel.Reject(ssh.ResourceShortage, "too many sessions")
			continue
		}
		// Recheck on each channel: a persistent connection cannot bypass a policy
		// edit or a registration revocation once the identity cache expires.
		current, err := s.Auth.authorizeConnection(ctx, conn.RemoteAddr(), conn.User(), authenticated)
		if err != nil {
			message := "meshscale: session authorization denied"
			var missing *missingPolicyError
			if errors.As(err, &missing) {
				message = "meshscale: " + err.Error()
			}
			channel.Reject(ssh.Prohibited, message)
			<-slots
			continue
		}
		if current.UID != target.UID || current.GID != target.GID || current.identity.RegistrationID != target.identity.RegistrationID || current.identity.DeviceID != target.identity.DeviceID || current.identity.PublicKey != target.identity.PublicKey {
			s.Auth.audit("deny", current.identity, current.identity.IP.String(), conn.User(), "login identity changed since handshake")
			channel.Reject(ssh.Prohibited, "meshscale: session authorization denied")
			<-slots
			continue
		}
		ch, reqs, err := channel.Accept()
		if err != nil {
			<-slots
			continue
		}
		go func() { defer func() { <-slots }(); s.session(ctx, conn, current, ch, reqs) }()
	}
}
