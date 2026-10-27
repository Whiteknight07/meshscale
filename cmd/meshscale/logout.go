package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Whiteknight07/meshscale/internal/auth"
	"github.com/Whiteknight07/meshscale/internal/config"
)

func init() {
	register(&command{name: "logout", short: "revoke and remove the saved Cloudflare login", run: runLogout})
}

func runLogout(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("usage: meshscale logout")
	}
	store, err := auth.DefaultStore()
	if err != nil {
		return err
	}
	err = store.Logout(ctx, auth.NewClient())
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("No saved OAuth login.")
	} else {
		if err != nil {
			return err
		}
		fmt.Println("Signed out of Cloudflare.")
	}
	if env, err := config.LoadEnv(); err == nil && env["CLOUDFLARE_API_TOKEN"] != "" {
		fmt.Println("API token credentials are still configured in the environment or dev.env.")
	}
	return nil
}
