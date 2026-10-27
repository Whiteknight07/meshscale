//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package auth

import (
	"context"
	"errors"
	"os"
	"syscall"

	"github.com/Whiteknight07/meshscale/internal/localstate"
)

func lockSession(ctx context.Context, path string) (func(), error) {
	file, err := localstate.OpenFile(path, os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			file.Close()
			return nil, err
		}
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			// Keep the file: unlinking it can give waiters different inodes.
			return func() {
				syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				file.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			file.Close()
			return nil, err
		}
		if err := waitForLock(ctx); err != nil {
			file.Close()
			return nil, err
		}
	}
}
