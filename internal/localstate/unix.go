//go:build linux || darwin

package localstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func currentOwner(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid())
}
func owned(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && (st.Uid == 0 || st.Uid == uint32(os.Geteuid()))
}

func openFile(path string, flag int) (*os.File, error) {
	fd, err := unix.Open(path, flag|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, &os.PathError{Op: "open private state", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// Lock is held across enrollment and daemon lifetime, preventing duplicate
// registrations and concurrent state deletion. It never follows a symlink.
func Lock(dir string) (func(), error) {
	release, busy, err := tryLock(dir)
	if busy {
		return nil, fmt.Errorf("native state is in use; run meshscale down first")
	}
	return release, err
}

// WaitLock guards a brief critical section, such as creating a key, waiting
// up to timeout for another process to finish instead of failing at once.
func WaitLock(dir string, timeout time.Duration) (func(), error) {
	deadline := time.Now().Add(timeout)
	for {
		release, busy, err := tryLock(dir)
		if !busy {
			return release, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%s is still locked by another meshscale process after %s", dir, timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func tryLock(dir string) (release func(), busy bool, err error) {
	if err := Dir(dir); err != nil {
		return nil, false, err
	}
	f, err := OpenFile(filepath.Join(dir, "daemon.lock"), os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, false, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return func() { f.Close() }, false, nil
}
