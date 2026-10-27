//go:build linux

package sshserver

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPolicyRootlessFiles(t *testing.T) {
	if os.Geteuid() == 0 {
		// Re-exec this test using an inherited executable FD: Go's build directory
		// is private to root, and should remain so. No host account is modified.
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(executable)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		cmd := exec.Command("/proc/self/fd/3", "-test.run=^TestPolicyRootlessFiles$", "-test.v")
		cmd.ExtraFiles = []*os.File{f}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("rootless test: %v\n%s", err, output)
		}
		return
	}
	for _, tc := range []struct {
		name           string
		symlink, force bool
	}{{"new", false, false}, {"force", false, true}, {"symlink", true, false}, {"force symlink", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "ssh.json")
			if tc.symlink {
				if err := os.Symlink(filepath.Join(dir, "missing"), path); err != nil {
					t.Fatal(err)
				}
			} else if tc.force {
				if err := os.WriteFile(path, []byte(`{"rules":[]}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := InitPolicy(path, "alice@example.com", false, tc.force)
			if tc.symlink {
				if err == nil {
					t.Fatal("accepted rootless symlink")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			st := info.Sys().(*syscall.Stat_t)
			if st.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0644 {
				t.Fatal("wrong rootless policy owner/mode")
			}
			p, err := LoadPolicy(path)
			if err != nil || !p.Allows(Identity{Owner: "alice@example.com"}, "alice", uint32(os.Geteuid())) {
				t.Fatalf("policy=%+v error=%v", p, err)
			}
		})
	}
}
