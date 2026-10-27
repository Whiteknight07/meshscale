//go:build linux

package hostsdns

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const selinuxLabel = "security.selinux"

// copyLabel gives the replacement file the original's SELinux label
// (net_conf_t for /etc/hosts). A file created in /etc would otherwise get the
// directory default and the rename would silently relabel /etc/hosts. Systems
// without SELinux labels need nothing.
func copyLabel(f *os.File, original string) error {
	size, err := unix.Lgetxattr(original, selinuxLabel, nil)
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read hosts file SELinux label: %w", err)
	}
	label := make([]byte, size)
	n, err := unix.Lgetxattr(original, selinuxLabel, label)
	if err != nil {
		return fmt.Errorf("read hosts file SELinux label: %w", err)
	}
	if err := unix.Fsetxattr(int(f.Fd()), selinuxLabel, label[:n], 0); err != nil {
		return fmt.Errorf("keep hosts file SELinux label: %w", err)
	}
	return nil
}
