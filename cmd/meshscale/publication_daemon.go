package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/Whiteknight07/meshscale/internal/auth"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/publication"
)

func publicationDir() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "publication")
	if err := localstate.Dir(dir); err != nil {
		return "", err
	}
	return dir, nil
}
func publicationManager(client *cfapi.Client, account string) (*publication.Manager, error) {
	dir, err := publicationDir()
	if err != nil {
		return nil, err
	}
	manager, err := publication.New(publication.Store{Dir: dir}, account, client, client, &publication.Cloudflared{Output: os.Stderr}, &publication.ACME{Dir: dir})
	if err != nil {
		return nil, err
	}
	manager.Owner = func(ctx context.Context) (string, error) {
		return auth.ResolveOwnerEmail(ctx, client, account)
	}
	return manager, nil
}
func startPublication(ctx context.Context, client *cfapi.Client, account string, logger *log.Logger) (func(), error) {
	manager, err := publicationManager(client, account)
	if err != nil {
		return nil, fmt.Errorf("initialize publication supervisor: %w", err)
	}
	stop, err := manager.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("start publication supervisor: %w", err)
	}
	logger.Printf("publication control socket: %s", publication.Socket(manager.Store.Dir))
	return stop, nil
}

// supervisePublication runs Funnel and certificates inside the connectivity
// daemon. They are optional, so a startup failure (an API outage, a missing
// cloudflared, a busy state directory) is logged and retried with backoff
// instead of taking Mesh connectivity down.
func supervisePublication(ctx context.Context, client *cfapi.Client, account string, logger *log.Logger) {
	superviseOptional(ctx, logger, "publication", 30*time.Second, func() (func(), error) {
		return startPublication(ctx, client, account, logger)
	})
}

// superviseOptional keeps start's service running until ctx ends, retrying
// failed starts with exponential backoff capped at ten minutes.
func superviseOptional(ctx context.Context, logger *log.Logger, name string, delay time.Duration, start func() (stop func(), err error)) {
	for ; ; delay = min(2*delay, 10*time.Minute) {
		stop, err := start()
		if err == nil {
			<-ctx.Done()
			stop()
			return
		}
		logger.Printf("%s unavailable: %v; retrying in %s", name, err, delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// runPublicationDaemon permits upgrading and validating publication services
// while the existing connectivity daemon continues without a network restart.
func runPublicationDaemon(ctx context.Context) error {
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	logger := log.New(os.Stderr, "meshscale publication: ", log.LstdFlags|log.LUTC)
	stop, err := startPublication(ctx, cfapi.New(tokens, version), account, logger)
	if err != nil {
		return err
	}
	defer stop()
	<-ctx.Done()
	return nil
}
