package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
)

func init() {
	register(&command{name: "whois", short: "show the device and user that own a Mesh IP or name", run: runWhois})
}

func runWhois(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("whois", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: meshscale whois <mesh-ip-or-name>")
	}
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	state, err := config.LoadMeshState()
	if err != nil {
		return fmt.Errorf("read Mesh node state: %w", err)
	}
	devices, err := loadMeshDevices(ctx, cfapi.New(tokens, version), account, nil, time.Now(), state)
	if err != nil {
		return err
	}
	if err := assignDNSNames(devices); err != nil {
		return err
	}
	device, ip, err := findMeshNameOrIP(devices, fs.Arg(0))
	if err != nil {
		return err
	}
	return writeWhois(os.Stdout, device, ip, time.Now())
}

func findMeshNameOrIP(devices []meshDevice, query string) (meshDevice, string, error) {
	if ip, err := netip.ParseAddr(query); err == nil && ip.Zone() == "" {
		d, err := findMeshIP(devices, ip)
		return d, ip.Unmap().String(), err
	}
	query = strings.ToLower(strings.TrimSuffix(query, "."))
	var matches []meshDevice
	for _, d := range devices {
		short, _, _ := strings.Cut(d.DNSName, ".")
		if d.DNSName != "" && (query == d.DNSName || query == short) {
			matches = append(matches, d)
		}
	}
	if len(matches) != 1 {
		return meshDevice{}, "", fmt.Errorf("expected one device with Mesh name %q; found %d", query, len(matches))
	}
	d := matches[0]
	ip := d.IPv4
	if ip == "" {
		ip = d.IPv6
	}
	return d, ip, nil
}

func findMeshIP(devices []meshDevice, ip netip.Addr) (meshDevice, error) {
	var match meshDevice
	found := false
	for _, d := range devices {
		v4, _ := netip.ParseAddr(d.IPv4)
		v6, _ := netip.ParseAddr(d.IPv6)
		if ip.Unmap() != v4.Unmap() && ip.Unmap() != v6.Unmap() {
			continue
		}
		if found {
			return meshDevice{}, fmt.Errorf("multiple devices own Mesh IP %s in the API response", ip)
		}
		match, found = d, true
	}
	if !found {
		return meshDevice{}, fmt.Errorf("no device found with Mesh IP %s in this account", ip)
	}
	return match, nil
}

func writeWhois(out io.Writer, d meshDevice, ip string, now time.Time) error {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fields := [][2]string{
		{"Mesh IP:", ip}, {"Device:", d.Name}, {"User/owner:", d.User},
		{"OS:", d.OS}, {"Status:", deviceState(d, now)},
	}
	if d.DNSName != "" {
		fields = append(fields, [2]string{"DNS name:", d.DNSName})
	}
	if d.Kind == "node" {
		fields = append(fields, [2]string{"Node ID:", d.ID})
	}
	registrationID := d.ID
	if d.Kind == "node" {
		registrationID = d.RegistrationID
	}
	if registrationID != "" {
		fields = append(fields, [2]string{"Registration:", registrationID})
	}
	if d.DeviceID != "" {
		fields = append(fields, [2]string{"Device ID:", d.DeviceID})
	}
	for _, field := range fields {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", field[0], tableField(field[1])); err != nil {
			return err
		}
	}
	return w.Flush()
}
