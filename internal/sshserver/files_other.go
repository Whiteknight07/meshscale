//go:build !linux && !darwin

package sshserver

import (
	"fmt"
	"os"
)

func checkProtectedDir(string, bool) error { return fmt.Errorf("SSH server requires Linux") }
func openProtected(string, bool) (*os.File, error) {
	return nil, fmt.Errorf("SSH server requires Linux")
}
