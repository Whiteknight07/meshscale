package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Whiteknight07/meshscale/internal/selfupdate"
)

func init() {
	register(&command{name: "update", short: "install a verified GitHub release or roll back", run: runUpdate})
}

func runUpdate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	target := fs.String("version", "", "release tag (default: latest published release)")
	check := fs.Bool("check", false, "check the available release without replacing anything")
	rollback := fs.Bool("rollback", false, "restore and consume meshscale.prev without network access")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 || *rollback && (*check || *target != "") {
		return fmt.Errorf("usage: meshscale update [--version vX.Y.Z] [--check] | --rollback")
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		return err
	}
	updater := selfupdate.New(binary)
	if *rollback {
		if err := updater.Rollback(); err != nil {
			return err
		}
		fmt.Println("Previous version restored. Restart an existing daemon when ready.")
		return nil
	}
	release, err := updater.Check(ctx, *target)
	if err != nil {
		return err
	}
	fmt.Printf("Installed: %s; available: %s.\n", version, release.Version)
	if *check || release.Version == version {
		return nil
	}
	fmt.Println("Downloading and verifying...")
	if err := updater.Install(ctx, release); err != nil {
		return err
	}
	fmt.Printf("Updated to %s. Previous binary: meshscale.prev. Restart an existing daemon when ready.\n", release.Version)
	return nil
}
