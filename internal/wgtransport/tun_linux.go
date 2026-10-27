//go:build linux

package wgtransport

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/Whiteknight07/meshscale/internal/secureroute"
)

// CreateTUN creates an exclusive interface and adds only the supplied routes.
// It never replaces existing interfaces/routes or changes the default route.
func CreateTUN(ctx context.Context, ifname string, ips []netip.Addr, routes []string, mtu int) (tun.Device, func(), error) {
	if os.Geteuid() != 0 {
		return nil, nil, fmt.Errorf("TUN mode requires root; use --userspace")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		return nil, nil, fmt.Errorf("TUN mode needs iproute2: %w", err)
	}
	if _, err := net.InterfaceByName(ifname); err == nil {
		return nil, nil, fmt.Errorf("%s already exists; refusing to modify it", ifname)
	}
	// A fixed exclusive name prevents accidental modification of another tunnel.
	t, err := tun.CreateTUN(ifname, mtu)
	if err != nil {
		return nil, nil, err
	}
	name, err := t.Name()
	if err != nil {
		t.Close()
		return nil, nil, err
	}
	command := secureroute.Command(ctx)
	execute := func(name string, args ...string) error {
		if name == "ip" {
			name = ip
		}
		return command(name, args...)
	}
	run := func(args ...string) error {
		if err := execute("ip", args...); err != nil {
			return fmt.Errorf("configure Mesh TUN: %w", err)
		}
		return nil
	}
	cleanup := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = exec.CommandContext(cleanupCtx, ip, "link", "delete", "dev", name).Run()
	}
	fail := func(err error) (tun.Device, func(), error) { t.Close(); cleanup(); return nil, nil, err }
	// Avoid an unrelated link-local route on this dedicated Mesh interface.
	if err := run("link", "set", "dev", name, "addrgenmode", "none"); err != nil {
		return fail(err)
	}
	for _, address := range ips {
		args := []string{"address", "add", netip.PrefixFrom(address, address.BitLen()).String(), "dev", name, "noprefixroute"}
		if address.Is6() {
			args = append(args, "nodad")
		}
		if err := run(args...); err != nil {
			return fail(err)
		}
	}
	if err := run("link", "set", "dev", name, "mtu", fmt.Sprint(mtu), "up"); err != nil {
		return fail(err)
	}
	for _, prefix := range routes {
		// add, never replace: an existing route is a conflict requiring user action.
		install := run
		if name == "meshsecure0" {
			install = func(args ...string) error {
				return secureroute.Install(execute, args...)
			}
		}
		if err := install("route", "add", prefix, "dev", name); err != nil {
			return fail(err)
		}
	}
	return t, cleanup, nil
}
