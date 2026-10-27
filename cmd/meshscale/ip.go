package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/native"
	"github.com/Whiteknight07/meshscale/internal/warpcli"
)

func init() {
	register(&command{name: "ip", short: "print this machine's Mesh IP (-4 or -6)", run: runIP})
}

func runIP(ctx context.Context, args []string) error {
	family, err := parseIPFlags(args)
	if err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	local, settings, err := selectedBackend()
	if err != nil {
		return err
	}
	if runtime.GOOS == "darwin" && settings.Backend == "warp" && !warpcli.Installed() {
		return warpcli.EnrollmentFailure("not_installed")
	}
	if settings.Backend == "native" {
		state, err := native.LoadState(local.(*native.Client).Dir)
		if err != nil {
			return err
		}
		ip := state.Registration.Config.Interface.Addresses.V4
		if family == 6 {
			ip = state.Registration.Config.Interface.Addresses.V6
		}
		if ip == "" {
			return fmt.Errorf("no assigned Mesh IPv%d address", family)
		}
		fmt.Fprintln(os.Stdout, ip)
		return nil
	}
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	return writeLocalIP(ctx, os.Stdout, cfapi.New(tokens, version), account, local, family)
}

func parseIPFlags(args []string) (int, error) {
	fs := flag.NewFlagSet("ip", flag.ContinueOnError)
	v4 := fs.Bool("4", false, "print the Mesh IPv4 address (default)")
	v6 := fs.Bool("6", false, "print the Mesh IPv6 address")
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	if fs.NArg() != 0 || (*v4 && *v6) {
		return 0, fmt.Errorf("usage: meshscale ip [-4 | -6]")
	}
	if *v6 {
		return 6, nil
	}
	return 4, nil
}

func writeLocalIP(ctx context.Context, out io.Writer, client *cfapi.Client, account string, local localWARP, family int) error {
	status, err := local.Status(ctx)
	if err != nil {
		return fmt.Errorf("cannot read local WARP status (is Cloudflare One installed and running?): %w", err)
	}
	if !status.Connected {
		if status.Reason != "" {
			return fmt.Errorf("not connected to Cloudflare Mesh: %s (%s)", status.State, status.Reason)
		}
		return fmt.Errorf("not connected to Cloudflare Mesh: %s", status.State)
	}
	info, err := local.Registration(ctx)
	if err != nil {
		return fmt.Errorf("cannot identify this machine's WARP registration: %w", err)
	}
	registrations, err := client.ListRegistrations(ctx, account)
	if err != nil {
		return err
	}
	devices := mergeMeshDevices(registrations, nil, nil, time.Now())
	markThisMachine(devices, info)
	var address string
	matched := false
	for _, d := range devices {
		if !d.ThisMachine {
			continue
		}
		matched = true
		ip := d.IPv4
		if family == 6 {
			ip = d.IPv6
		}
		if address != "" && ip != "" && address != ip {
			return fmt.Errorf("multiple WARP registrations match this machine; warp-cli must expose its active registration ID")
		}
		if ip != "" {
			address = ip
		}
	}
	if !matched {
		return fmt.Errorf("this machine's WARP registration was not found in the selected Cloudflare account")
	}
	if address == "" {
		return fmt.Errorf("this machine has no Mesh IPv%d address; check that Mesh IPs are enabled for the account", family)
	}
	_, err = fmt.Fprintln(out, address)
	return err
}
