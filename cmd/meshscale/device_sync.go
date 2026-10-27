package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/devicesync"
)

func deviceSnapshot(ctx context.Context, client *cfapi.Client, account string) (devicesync.Snapshot, error) {
	snapshot := devicesync.Snapshot{Client: client, Account: account}
	state, err := config.LoadMeshState()
	if err != nil {
		return snapshot, err
	}
	before, _ := json.Marshal(state.Accounts)
	memory := &config.MeshState{Accounts: state.Accounts}
	devices, err := loadMeshDevices(ctx, client, account, nil, time.Now(), memory)
	if err != nil {
		return snapshot, err
	}
	after, _ := json.Marshal(memory.Accounts)
	if !bytes.Equal(before, after) {
		state.Accounts = memory.Accounts
		if err := state.Save(); err != nil {
			return snapshot, err
		}
	}
	for _, d := range devices {
		snapshot.Devices = append(snapshot.Devices, devicesync.Device{ID: d.Kind + "/" + d.ID, Name: d.Name, IPv4: d.IPv4, IPv6: d.IPv6, Owner: d.User})
	}
	return snapshot, nil
}
func syncAfterUp(ctx context.Context, client *cfapi.Client, account string) error {
	snapshot, err := deviceSnapshot(ctx, client, account)
	if err != nil {
		return fmt.Errorf("load devices: %w", err)
	}
	snapshot.LocalHosts, snapshot.Quiet = true, true
	return devicesync.Default.Run(ctx, snapshot)
}
