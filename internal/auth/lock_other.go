//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package auth

import (
	"context"
	"errors"
	"os"
)

// Windows and other platforms use an exclusive file. A crashed owner leaves a
// stale lock that must be removed manually after checking no login is running.
func lockSession(ctx context.Context, path string) (func(), error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err == nil {
			return func() {
				file.Close()
				os.Remove(path)
			}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if err := waitForLock(ctx); err != nil {
			return nil, err
		}
	}
}
