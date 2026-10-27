//go:build !linux && !darwin

package sshserver

import (
	"fmt"
	"os"
)

func openPolicyFile(string) (*os.File, error) {
	return nil, fmt.Errorf("SSH policies require Linux or macOS")
}
func writePolicyFile(string, []byte, bool) error {
	return fmt.Errorf("SSH policies require Linux or macOS")
}
