//go:build linux

package config

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestSSHPolicyRootlessPath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("already exercised as the current unprivileged user")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command("/proc/self/fd/3", "-test.run=^TestSSHPolicyDefaultPath$", "-test.v")
	cmd.ExtraFiles = []*os.File{f}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("rootless default-path test: %v\n%s", err, output)
	}
}
