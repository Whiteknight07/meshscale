package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/Whiteknight07/meshscale/internal/backend"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/native"
	"github.com/Whiteknight07/meshscale/internal/service"
	"github.com/Whiteknight07/meshscale/internal/sshserver"
)

func init() {
	register(&command{name: "serve", short: "share a localhost TCP service on Mesh; status or off", run: runServe})
}
func meshListen(local backend.Backend, settings *config.BackendSettings, client *cfapi.Client, account string) service.ListenFunc {
	return func(ctx context.Context, port int) ([]net.Listener, error) {
		queryCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		ips, err := localSSHIPs(queryCtx, client, account, local)
		if err != nil {
			return nil, err
		}
		if settings.Backend == "native" && settings.Userspace {
			var listeners []net.Listener
			for _, ip := range ips {
				l, err := local.(*native.Client).ListenTCP(ctx, netip.AddrPortFrom(ip, uint16(port)))
				if err != nil {
					for _, l := range listeners {
						l.Close()
					}
					return nil, err
				}
				listeners = append(listeners, l)
			}
			return listeners, nil
		}
		return sshserver.Listen(ips, port)
	}
}
func noServiceSocket(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED)
}
func runServe(parent context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshscale serve <port> [--mesh-port N] [--tcp] | serve status | serve off")
	}
	dir, err := config.ServiceDir()
	if err != nil {
		return err
	}
	if args[0] == "status" || args[0] == "off" {
		if len(args) != 1 {
			return fmt.Errorf("usage: meshscale serve %s", args[0])
		}
		method := "GET"
		if args[0] == "off" {
			method = "DELETE"
		}
		var forwards []service.Forward
		var out any = &forwards
		if method == "DELETE" {
			out = nil
		}
		err := service.Request(parent, dir, method, "/serve", nil, out)
		if noServiceSocket(err) {
			if method == "DELETE" {
				release, err := localstate.Lock(dir)
				if err != nil {
					return fmt.Errorf("daemon is starting or stopping; retry serve off: %w", err)
				}
				defer release()
				options, err := config.LoadService()
				if err != nil {
					return err
				}
				if len(options.Forwards) > 0 {
					options.Forwards = nil
					if err := options.Save(); err != nil {
						return err
					}
				}
				fmt.Println("Mesh forwarding disabled; daemon is stopped.")
				return nil
			}
			options, err := config.LoadService()
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(struct {
				Running  bool              `json:"running"`
				Forwards []service.Forward `json:"saved_forwards"`
			}{false, options.Forwards})
		}
		if err != nil {
			return err
		}
		if method == "GET" {
			return json.NewEncoder(os.Stdout).Encode(forwards)
		}
		fmt.Println("Mesh forwarding disabled.")
		return nil
	}
	port, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("port must be a number")
	}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	meshPort := fs.Int("mesh-port", port, "port to bind on this device's Mesh IPs")
	fs.Bool("tcp", false, "forward raw TCP (also the default for HTTP)")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected serve arguments")
	}
	forward := service.Forward{Port: port, MeshPort: *meshPort}
	if err := forward.Validate(); err != nil {
		return err
	}
	err = service.Request(parent, dir, "PUT", "/serve", forward, nil)
	if err == nil {
		fmt.Printf("Serving mesh port %d -> 127.0.0.1:%d in the running daemon.\n", *meshPort, port)
		return nil
	}
	if !noServiceSocket(err) {
		return err
	}
	if _, err := os.Stat(service.UnitPath); err == nil {
		return fmt.Errorf("service is installed but unavailable; start meshscale.service before configuring serve")
	}
	local, settings, err := selectedBackend()
	if err != nil {
		return err
	}
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	proxies := &service.Proxies{Listen: meshListen(local, settings, cfapi.New(tokens, version), account)}
	ctrl := &service.Control{Proxies: proxies}
	ctrl.Update(func(s *service.Status) { s.Mode = "serve"; s.Backend = settings.Backend })
	ready := make(chan struct{})
	done := make(chan error, 1)
	var workers sync.WaitGroup
	defer func() { cancel(); proxies.Close(); workers.Wait() }()
	workers.Go(func() { done <- ctrl.Run(ctx, dir, ready) })
	select {
	case <-ready:
	case err := <-done:
		return err
	case <-ctx.Done():
		return nil
	}
	if err := proxies.Add(ctx, forward); err != nil {
		return err
	}
	fmt.Printf("Serving Mesh port %d -> 127.0.0.1:%d in foreground; Ctrl-C stops.\n", *meshPort, port)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-done:
			return err
		case <-ticker.C:
			if len(proxies.List()) == 0 {
				return nil
			}
		}
	}
}
