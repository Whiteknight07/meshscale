package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/service"
)

// Only a missing or refused socket, or a daemon too old to serve the
// inventory, permits direct API fallback. A responding daemon's cache/refresh
// errors must remain visible, including during startup.
func daemonDevices(ctx context.Context, refresh bool) ([]meshDevice, bool, error) {
	dir, err := config.ServiceDir()
	if err != nil {
		return nil, true, err
	}
	method := "GET"
	timeout := 200 * time.Millisecond
	if refresh {
		method = "POST"
		timeout = 35 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var inventory service.Inventory
	if err := service.Request(ctx, dir, method, "/devices", nil, &inventory); err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return nil, false, nil
		}
		if errors.Is(err, errors.ErrUnsupported) {
			fmt.Fprintln(os.Stderr, "Warning: the running daemon is older than this CLI; restart the meshscale daemon to use its cache")
			return nil, false, nil
		}
		return nil, true, fmt.Errorf("daemon status: %w", err)
	}
	if inventory.Error != "" {
		fmt.Fprintf(os.Stderr, "Warning: cached inventory from %s: %s\n", inventory.UpdatedAt.Format(time.RFC3339), inventory.Error)
	}
	if inventory.Status.Secure.Enabled && !inventory.Status.Secure.Running {
		fmt.Fprintf(os.Stderr, "Warning: secure engine stopped: %s\n", inventory.Status.Secure.Error)
	}
	applyRuntimeStatus(inventory.Devices, inventory.Status)
	return inventory.Devices, true, nil
}

func applyRuntimeStatus(devices []meshDevice, status service.Status) {
	for i := range devices {
		d := &devices[i]
		if d.ThisMachine {
			d.SSHPolicy = ""
			if status.SSH {
				d.SSHPolicy = status.SSHPolicy
			}
			d.SecureTCP = status.Secure.CongestionControl
			d.OffersExit = status.Secure.OffersExit
			d.ExitNode, d.ExitState, d.ExitAllowLAN = status.Secure.ExitNode, status.Secure.ExitState, status.Secure.AllowLAN
			d.Online = status.Connection.Connected
			d.OnlineSource = "local"
			d.ConnectionState = status.Connection.State
		}
		if d.Secure == nil {
			continue
		}
		d.Secure.LastHandshake = nil
		d.Secure.HandshakeAge = nil
		for _, peer := range status.Secure.Peers {
			if peer.PublicKey == d.Secure.PublicKey {
				d.Secure.LastHandshake, d.Secure.HandshakeAge = peer.LastHandshake, peer.HandshakeAge
			}
		}
	}
}
