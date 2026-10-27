package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/devicesync"
	"github.com/Whiteknight07/meshscale/internal/hostsdns"
	"github.com/Whiteknight07/meshscale/internal/names"
)

func init() {
	devicesync.Default.Register("hosts", syncHosts)
}

func hostsEnabled() bool {
	settings, err := config.LoadDNS()
	return err == nil && settings.Hosts != "off" && !config.Paused()
}

func syncHosts(ctx context.Context, snapshot devicesync.Snapshot) error {
	// The menu app and rootless users must never prompt for privilege or try to
	// write /etc. A root daemon/up owns this fallback.
	if os.Geteuid() != 0 || !snapshot.LocalHosts {
		return nil
	}
	return syncHostsAt(ctx, snapshot, hostsdns.Path, hostsdns.SystemLookup)
}

// Paths and resolver are injected only by temp-file tests, never via the CLI.
func syncHostsAt(ctx context.Context, snapshot devicesync.Snapshot, path string, lookup hostsdns.Lookup) error {
	settings, err := config.LoadDNS()
	if err != nil {
		return err
	}
	if settings.Hosts == "off" || config.Paused() {
		return hostsdns.Update(ctx, path, nil, nil)
	}
	var participants []names.Participant
	for _, d := range snapshot.Devices {
		participants = append(participants, names.Participant{ID: d.ID, Name: d.Name, IPv4: d.IPv4, IPv6: d.IPv6})
	}
	records, err := names.Build(participants, "mesh")
	if err != nil {
		return err
	}
	if settings.Hosts == "auto" {
		// Once auto installed a block, system lookups include it. Retain it until
		// down/off instead of mistaking our fallback for a recovered DNS resolver.
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		without, err := hostsdns.Rewrite(data, nil)
		if err != nil {
			return err
		}
		if bytes.Equal(data, without) {
			checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			needed := hostsdns.NeedsHosts(checkCtx, records, lookup)
			cancel()
			if !needed {
				return nil
			}
		}
	}
	return hostsdns.Update(ctx, path, records, hostsEnabled)
}

func cleanupHosts(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return hostsdns.Update(ctx, hostsdns.Path, nil, nil)
}

func setDNSHosts(ctx context.Context, mode string) error {
	if mode != "auto" && mode != "on" && mode != "off" {
		return fmt.Errorf("dns-hosts must be auto, on or off")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("dns-hosts requires root; use the root daemon's configuration")
	}
	settings := &config.DNSSettings{Hosts: mode}
	if err := settings.Save(); err != nil {
		return err
	}
	if mode == "off" || config.Paused() {
		if err := cleanupHosts(ctx); err != nil {
			return err
		}
	} else {
		account, tokens, err := resolveCredentials()
		if err != nil {
			return fmt.Errorf("DNS preference saved; run meshscale up after sign-in: %w", err)
		}
		snapshot, err := deviceSnapshot(ctx, cfapi.New(tokens, version), account)
		if err != nil {
			return err
		}
		snapshot.LocalHosts = true
		if err := syncHosts(ctx, snapshot); err != nil {
			return err
		}
	}
	fmt.Printf("Hosts DNS: %s.\n", mode)
	return nil
}
