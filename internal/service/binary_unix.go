//go:build linux || darwin

package service

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ValidateSystemBinary prevents a privileged service from executing a binary
// that an unprivileged local user can replace, including through its parents.
// The caller resolves legitimate system symlinks before calling this function.
func ValidateSystemBinary(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("system service binary path must be absolute")
	}
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		writable := info.Mode().Perm()&0022 != 0 && (current == filepath.Clean(path) || info.Mode()&os.ModeSticky == 0)
		if !ok || stat.Uid != 0 || writable || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("system service path %s must be root-owned without symlinks or group/other write access; install the binary in /usr/local/bin first", current)
		}
		if current == filepath.Clean(path) {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
				return fmt.Errorf("system service binary must be a regular executable")
			}
		} else if !info.IsDir() {
			return fmt.Errorf("system service binary parent is not a directory")
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}
