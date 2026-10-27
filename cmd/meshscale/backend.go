package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/backend"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/native"
	"github.com/Whiteknight07/meshscale/internal/secure"
	"github.com/Whiteknight07/meshscale/internal/warpcli"
)

func selectedBackend() (backend.Backend, *config.BackendSettings, error) {
	settings, err := config.LoadBackend()
	if err != nil {
		return nil, nil, err
	}
	if settings.Backend == "native" {
		dir, err := settings.NativeStateDir()
		if err != nil {
			return nil, nil, err
		}
		return &native.Client{Dir: dir}, settings, nil
	}
	return warpcli.New(""), settings, nil
}

// runNativeUp is intentionally separate from account setup/DNS synchronization:
// experimental enrollment must never edit profiles or Gateway settings.
func runNativeUp(ctx context.Context, out io.Writer, settings *config.BackendSettings, name string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("native node enrollment is currently Linux-only; macOS enrollment needs a separate implementation")
	}
	if !settings.Userspace && os.Geteuid() != 0 {
		return fmt.Errorf("native TUN mode requires root; use --userspace")
	}
	dir, err := settings.NativeStateDir()
	if err != nil {
		return err
	}
	if settings.Userspace {
		addr, err := netip.ParseAddrPort(settings.SOCKS)
		if err != nil || !addr.Addr().IsLoopback() {
			return fmt.Errorf("SOCKS address must be a numeric loopback IP and port")
		}
	}
	settings.NativeDir = dir
	if err := settings.Warn(os.Stderr); err != nil {
		return err
	}
	if err := settings.Save(); err != nil {
		return err
	}
	release, err := localstate.Lock(dir)
	if err != nil {
		return err
	}
	// Release before acknowledging down, and exactly once on every return path.
	released := false
	unlock := func() {
		if !released {
			release()
			released = true
		}
	}
	defer unlock()
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	client := cfapi.New(tokens, version)
	state, err := native.LoadState(dir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if state != nil {
		if state.Account != account {
			return fmt.Errorf("native state belongs to another account; refusing to replace it")
		}
		if name != "" && name != state.Name {
			return fmt.Errorf("native node is named %q; run down --forget before changing its name", state.Name)
		}
		name = state.Name
	} else {
		if name == "" {
			name, err = os.Hostname()
			if err != nil {
				return err
			}
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return fmt.Errorf("hostname is empty; use --hostname")
		}
		nodes, err := client.ListMeshNodes(ctx, account)
		if err != nil {
			return err
		}
		for _, n := range nodes {
			if n.Name == name && n.DeletedAt == nil {
				return fmt.Errorf("native credentials missing for existing Mesh node %q; choose a unique --hostname", name)
			}
		}
		node, err := client.CreateMeshNode(ctx, account, cfapi.CreateMeshNodeParams{Name: name})
		if err != nil {
			return err
		}
		state = &native.State{Account: account, NodeID: node.ID, Name: name}
		if err := state.Save(dir); err != nil {
			return err
		}
		fmt.Fprintln(out, "Created Mesh node:", name)
	}
	api := native.NewAPI()
	if state.Registration.ID == "" {
		if state.Pending {
			return fmt.Errorf("native registration was interrupted; use down --forget before retrying to avoid duplicate registrations")
		}
		token, err := client.MeshNodeToken(ctx, account, state.NodeID)
		if err != nil {
			return err
		}
		if err := native.ValidateNodeToken(token, account, state.NodeID); err != nil {
			return err
		}
		private, public, err := native.GenerateKey()
		if err != nil {
			return err
		}
		state.PrivateKey, state.Pending = private, true
		if err := state.Save(dir); err != nil {
			return err
		}
		registration, regErr := api.Register(ctx, account, state.NodeID, name, token, public)
		// Persist even a validation failure if the remote API created a credential,
		// so that explicit cleanup remains possible.
		state.Registration = registration
		if regErr == nil {
			state.Pending = false
		}
		if err := state.Save(dir); err != nil {
			return err
		}
		if regErr != nil {
			return regErr
		}
		fmt.Fprintln(out, "Enrolled this machine using the experimental native backend.")
	} else {
		fmt.Fprintln(out, "Reusing native Mesh registration:", name)
	}
	meshState, err := config.LoadMeshState()
	if err != nil {
		return err
	}
	meshState.Remember(account, state.NodeID, strings.TrimPrefix(state.Registration.ID, "t."))
	if err := meshState.Save(); err != nil {
		return err
	}
	securePath, err := secureDir()
	if err != nil {
		return err
	}
	secureSettings, err := secure.LoadConfig(securePath)
	if err != nil {
		return err
	}
	if err := config.SetPaused(false); err != nil {
		return err
	}
	if secureSettings.Enabled {
		unlock()
		return runDaemon(ctx, nil)
	}
	return native.Run(ctx, dir, state, api, native.DaemonOptions{Userspace: settings.Userspace, SOCKS: settings.SOCKS, Output: out}, unlock)
}

func forgetNative(ctx context.Context, dir string) error {
	release, err := localstate.Lock(dir)
	if err != nil {
		return err
	}
	defer release()
	state, err := native.LoadStateForRemoval(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	if state.Account != account {
		return fmt.Errorf("native state belongs to another account; refusing deletion")
	}
	client := cfapi.New(tokens, version)
	// Verify ownership by ID and exact saved name before deleting a node.
	nodes, err := client.ListMeshNodes(ctx, account)
	if err != nil {
		return err
	}
	found := false
	for _, n := range nodes {
		if n.ID == state.NodeID && n.DeletedAt == nil {
			if n.Name != state.Name {
				return fmt.Errorf("native node name changed; refusing deletion")
			}
			found = true
		}
	}
	if state.Registration.ID != "" {
		err := native.NewAPI().Deregister(ctx, account, state.Registration)
		var status *native.HTTPError
		if err != nil && !(errors.As(err, &status) && (status.Status == 401 || status.Status == 404)) {
			return err
		}
	}
	if found {
		if err := client.DeleteMeshNode(ctx, account, state.NodeID); err != nil {
			return err
		}
	}
	if err := os.Remove(native.StatePath(dir)); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "Forgot native registration and deleted Mesh node:", state.Name)
	return nil
}
