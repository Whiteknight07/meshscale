package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/localstate"
)

// Called only by the existing account inventory refresh, never a daemon tick or
// a fresh API call in meshscale ssh when cached inventory is available.
func assignSSHMode(ctx context.Context, client *cfapi.Client, account string, devices []meshDevice) error {
	for i := range devices {
		devices[i].SSHMode = "unknown"
	}
	targets, err := client.ListInfrastructureTargets(ctx, account)
	if err != nil {
		return nil
	}
	dir, err := config.Dir()
	if err != nil {
		return err
	}
	var state struct {
		Mode string `json:"mode"`
	}
	err = localstate.Read(filepath.Join(dir, "cloudflare-ssh", "state.json"), &state)
	if os.IsNotExist(err) {
		err = nil
	}
	if err != nil {
		return err
	}
	for i := range devices {
		d := &devices[i]
		d.SSHMode = "unknown"
		if d.ThisMachine && state.Mode != "" {
			d.SSHMode = state.Mode
		}
		for _, target := range targets {
			if target.IP.IPv4 != nil && d.IPv4 != "" && target.IP.IPv4.Address == d.IPv4 || target.IP.IPv6 != nil && d.IPv6 != "" && target.IP.IPv6.Address == d.IPv6 {
				d.SSHMode = "cloudflare"
			}
		}
	}
	return nil
}
