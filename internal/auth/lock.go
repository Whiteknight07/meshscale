package auth

import (
	"context"
	"path/filepath"
	"time"

	"github.com/Whiteknight07/meshscale/internal/localstate"
)

func (s *Store) lock(ctx context.Context) (func(), error) {
	if err := localstate.Dir(filepath.Dir(s.Path)); err != nil {
		return nil, err
	}
	return lockSession(ctx, s.Path+".lock")
}

func waitForLock(ctx context.Context) error {
	timer := time.NewTimer(25 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
