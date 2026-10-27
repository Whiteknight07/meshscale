//go:build linux || darwin

package sshserver

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func checkProtectedDir(path string, private bool) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("SSH paths must be absolute")
	}
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return fmt.Errorf("%s must be a root-owned directory without group/other write access or symlinks", current)
		}
		if current == filepath.Clean(path) && private && info.Mode().Perm() != 0700 {
			return fmt.Errorf("%s must have mode 0700", path)
		}
		if current == "/" {
			break
		}
	}
	return nil
}

func openProtected(path string, private bool) (*os.File, error) {
	if err := checkProtectedDir(filepath.Dir(path), false); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || (private && info.Mode().Perm() != 0600) {
		return nil, fmt.Errorf("%s must be a root-owned regular file, mode %s, without symlinks", path, map[bool]string{true: "0600", false: "0644 or stricter"}[private])
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(info, after) {
		f.Close()
		return nil, fmt.Errorf("SSH file changed while opening %s", path)
	}
	return f, nil
}
