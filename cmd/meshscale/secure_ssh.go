package main

import (
	"context"
	"fmt"
	"time"

	"github.com/Whiteknight07/meshscale/internal/secure"
)

// Reload listeners and downgrade protection when set --secure changes, even
// while the account device fingerprint is unchanged.
func runManagedSSHD(ctx context.Context, args []string) error {
	dir, err := secureDir()
	if err != nil {
		return err
	}
	initial, err := secure.LoadConfig(dir)
	if err != nil {
		return err
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runSSHDWithPolicyWarning(child, args, false) }()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			cancel()
			<-done
			return nil
		case <-ticker.C:
			fresh, err := secure.LoadConfig(dir)
			if err != nil || fresh != initial {
				cancel()
				<-done
				if err != nil {
					return err
				}
				return fmt.Errorf("secure settings changed; restarting SSH listeners")
			}
		}
	}
}
