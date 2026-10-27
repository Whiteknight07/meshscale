//go:build linux || darwin

package sshserver

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Check ancestors from the root down, including when the final directory is
// absent. Missing files must never conceal an unsafe ancestor or a symlink.
func policyDir(path string, create bool) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("SSH policy paths must be absolute")
	}
	path = filepath.Clean(path)
	if parent := filepath.Dir(path); parent != path {
		if err := policyDir(parent, create); err != nil {
			return err
		}
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) && create {
		if err := os.Mkdir(path, 0755); err != nil && !os.IsExist(err) {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || !info.IsDir() || (info.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && info.Mode()&os.ModeSticky != 0)) {
		return fmt.Errorf("%s must be a protected directory owned by root or UID %d, without symlinks", path, os.Geteuid())
	}
	return nil
}

func openPolicyFile(path string) (*os.File, error) {
	if err := policyDir(filepath.Dir(path), false); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("%s must be a regular file owned by root or UID %d, mode 0644 or stricter, without symlinks", path, os.Geteuid())
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open SSH policy", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	after, err := f.Stat()
	if err != nil || !os.SameFile(info, after) {
		f.Close()
		return nil, fmt.Errorf("SSH policy changed while opening %s", path)
	}
	return f, nil
}

func writePolicyFile(path string, data []byte, force bool) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("SSH policy paths must be absolute")
	}
	dir := filepath.Dir(path)
	if err := policyDir(dir, true); err != nil {
		return err
	}
	existing, err := openPolicyFile(path)
	if err == nil {
		existing.Close()
		if !force {
			return fmt.Errorf("SSH policy already exists at %s; use --force to replace it", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".ssh-policy-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Chmod(0644); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if force {
		err = os.Rename(tmp.Name(), path)
	} else {
		err = os.Link(tmp.Name(), path)
	}
	if err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
