//go:build linux || darwin

package hostsdns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func lock(ctx context.Context, path string) (func(), error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err == nil {
		st := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0600 {
			err = fmt.Errorf("unsafe hosts lock file")
		}
	}
	if err == nil {
		for {
			err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
			if !errors.Is(err, unix.EWOULDBLOCK) {
				break
			}
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				f.Close()
				return nil, fmt.Errorf("wait for hosts writer: %w", ctx.Err())
			case <-timer.C:
			}
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}

func metadata(f *os.File, info os.FileInfo, original string) error {
	st := info.Sys().(*syscall.Stat_t)
	if err := f.Chown(int(st.Uid), int(st.Gid)); err != nil {
		return err
	}
	if err := f.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	return copyLabel(f, original)
}

// isMountPoint reports a rename refused because the target is a mount point.
func isMountPoint(err error) bool { return errors.Is(err, unix.EBUSY) }
