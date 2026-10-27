package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"runtime"

	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/native"
	"github.com/Whiteknight07/meshscale/internal/secure"
	"github.com/Whiteknight07/meshscale/internal/warpcli"
)

func init() {
	register(&command{name: "down", short: "disconnect this machine from Mesh", run: runDown})
}
func runDown(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	forget := fs.Bool("forget", false, "native: deregister and delete this Mesh node and its local credentials")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: meshscale down [--forget]")
	}
	local, settings, err := selectedBackend()
	if err != nil {
		return err
	}
	if *forget && settings.Backend != "native" {
		return fmt.Errorf("--forget currently requires the native backend; official WARP registration was preserved")
	}
	if runtime.GOOS == "darwin" && settings.Backend == "warp" && !warpcli.Installed() {
		return warpcli.EnrollmentFailure("not_installed")
	}
	if dir, err := secureDir(); err == nil {
		settings, err := secure.LoadConfig(dir)
		if err != nil {
			return err
		}
		if settings.AdvertiseExit {
			if err := runSet(ctx, []string{"--advertise-exit-node=false", "--secure=false"}); err != nil {
				return err
			}
		}
	}
	// Record the intent first so the daemon does not reconnect.
	if err := config.SetPaused(true); err != nil {
		return err
	}
	cleanupErr := cleanupHosts(ctx)
	if err := local.Disconnect(ctx); err != nil {
		return errors.Join(err, cleanupErr)
	}
	if cleanupErr != nil {
		return fmt.Errorf("disconnected; remove hosts DNS: %w", cleanupErr)
	}
	if *forget {
		return forgetNative(ctx, local.(*native.Client).Dir)
	}
	return nil
}
