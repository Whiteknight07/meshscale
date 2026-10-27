package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/native"
)

func init() {
	register(&command{name: "ping", short: "TCP reachability probe to a device (default SSH port 22)", run: runPing})
}
func runPing(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ping", flag.ContinueOnError)
	port := fs.Int("port", 22, "TCP port to probe")
	timeout := fs.Duration("timeout", 5*time.Second, "connection timeout")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 || *port < 1 || *port > 65535 || *timeout <= 0 {
		return fmt.Errorf("usage: meshscale ping [--port 22] [--timeout 5s] <name|name.secure|ip>")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	ip, isSecure, err := resolveSecureTarget(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	var dial interface {
		DialContext(context.Context, string, string) (net.Conn, error)
	} = &net.Dialer{}
	if isSecure {
		dir, err := secureDir()
		if err != nil {
			return err
		}
		dial = &native.Client{Dir: dir}
	} else {
		devices, cached, err := daemonDevices(ctx, false)
		if err != nil {
			return err
		}
		if !cached {
			account, tokens, err := resolveCredentials()
			if err != nil {
				return err
			}
			state, err := config.LoadMeshState()
			if err != nil {
				return err
			}
			devices, err = loadMeshDevices(ctx, cfapi.New(tokens, version), account, nil, time.Now(), state)
			if err != nil {
				return err
			}
		}
		ip, err = resolveSSHTarget(devices, fs.Arg(0))
		if err != nil {
			return err
		}
		local, settings, err := selectedBackend()
		if err != nil {
			return err
		}
		if settings.Backend == "native" && settings.Userspace {
			dial = local.(*native.Client)
		}
	}
	start := time.Now()
	c, err := dial.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), fmt.Sprint(*port)))
	if err != nil {
		return fmt.Errorf("TCP probe %s: %w", ip, err)
	}
	c.Close()
	fmt.Fprintf(os.Stdout, "pong from %s TCP/%d in %s (secure=%t)\n", ip, *port, time.Since(start).Round(time.Microsecond), isSecure)
	return nil
}
