package native

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type DaemonOptions struct {
	Userspace       bool
	SOCKS           string
	RefreshInterval time.Duration
	Output          io.Writer
	OnTransport     func(*Transport)
}

// Run owns transport lifetime; the caller holds the state lock until it returns.
// Shutdown closes all sockets and TUN routes before acknowledging down.
func Run(ctx context.Context, dir string, state *State, api *API, opts DaemonOptions, release func()) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The state lock is released before acknowledging stop; down --forget can
	// then acquire it without racing cleanup.
	var ctrl *control
	defer func() {
		release()
		if ctrl != nil {
			ctrl.finishStop()
		}
	}()
	fresh, err := api.Refresh(ctx, state.Account, state.Registration)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	state.Registration = fresh
	if err := state.Save(dir); err != nil {
		return err
	}
	transport, err := Start(ctx, state, opts.Userspace)
	if err != nil {
		return err
	}
	defer transport.Close()
	if opts.OnTransport != nil {
		opts.OnTransport(transport)
	}
	ips, _ := fresh.IPs()
	ctrl = &control{transport: transport, ips: ips, cancel: cancel, listeners: map[uint64]net.Listener{}}
	listener, err := listenControl(socketPath(dir))
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(socketPath(dir))
	var socks net.Listener
	if opts.Userspace {
		socks, err = socksListener(opts.SOCKS)
		if err != nil {
			return err
		}
		defer socks.Close()
	}
	var workers sync.WaitGroup
	defer func() { cancel(); ctrl.close(); workers.Wait() }()
	errorsCh := make(chan error, 3)
	workers.Go(func() { errorsCh <- ctrl.serve(ctx, listener) })
	if socks != nil {
		workers.Go(func() { errorsCh <- serveSOCKS(ctx, socks, transport.Network) })
	}
	interval := opts.RefreshInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	mode := "TUN"
	if opts.Userspace {
		mode = "userspace"
	}
	if opts.Output != nil {
		fmt.Fprintf(opts.Output, "Experimental native %s running; Mesh IPv4=%s IPv6=%s MTU=%d\n", mode, fresh.Config.Interface.Addresses.V4, fresh.Config.Interface.Addresses.V6, MTU)
		if socks != nil {
			fmt.Fprintf(opts.Output, "SOCKS5 CONNECT proxy: %s (numeric Mesh IPs only)\n", socks.Addr())
		}
		fmt.Fprintln(opts.Output, "Foreground daemon: keep this process running; Ctrl-C, SIGTERM or meshscale down disconnects.")
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errorsCh:
			return err
		case <-ticker.C:
			fresh, err := api.Refresh(ctx, state.Account, state.Registration)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				// Never keep an unverified/revoked registration running indefinitely.
				var status *HTTPError
				if errors.As(err, &status) && (status.Status == 401 || status.Status == 403 || status.Status == 404) {
					return fmt.Errorf("native registration revoked or expired: %w", err)
				}
				return fmt.Errorf("native config refresh failed; connection stopped: %w", err)
			}
			if err := transport.Refresh(state, fresh); err != nil {
				return err
			}
			state.Registration = fresh
			if err := state.Save(dir); err != nil {
				return err
			}
			if opts.Output != nil {
				fmt.Fprintln(opts.Output, "Native configuration refreshed.")
			}
		}
	}
}

// listenControl replaces only a stale socket, never a file or symlink that
// was substituted at the control path.
func listenControl(path string) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode().Type() != os.ModeSocket {
			return nil, fmt.Errorf("refusing to replace non-socket %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		os.Remove(path)
		return nil, err
	}
	return listener, nil
}
