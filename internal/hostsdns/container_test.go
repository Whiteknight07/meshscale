//go:build linux

package hostsdns

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Opt in only inside a disposable Docker container. A private mount namespace
// places a writable /etc directory over the container's read-only/bind-mounted
// hosts file. Neither the original container hosts nor the host OS is modified.
// Run the compiled test with CAP_SYS_ADMIN (see docs/install.md).
func TestContainerSystemResolver(t *testing.T) {
	if os.Getenv("MESHSCALE_CONTAINER_HOSTS_TEST") != "1" {
		t.Skip("container-only opt-in")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("refusing live hosts test outside Docker")
	}
	if os.Geteuid() != 0 {
		t.Fatal("container test requires root")
	}
	if os.Getenv("MESHSCALE_HOSTS_TEST_CHILD") != "1" {
		cmd := exec.Command("unshare", "--mount", "--propagation", "private", os.Args[0], "-test.run=^TestContainerSystemResolver$", "-test.v")
		cmd.Env = append(os.Environ(), "MESHSCALE_HOSTS_TEST_CHILD=1")
		output, err := cmd.CombinedOutput()
		t.Log(string(output))
		if err != nil {
			t.Fatalf("private container mount namespace: %v (requires CAP_SYS_ADMIN)", err)
		}
		return
	}
	original, err := os.ReadFile(Path)
	if err != nil {
		t.Fatal(err)
	}
	// Copy the resolver inputs into a private replacement for /etc. The real
	// /etc/hosts is a Docker bind mount and cannot be atomically renamed.
	etc := t.TempDir()
	for _, name := range []string{"hosts", "nsswitch.conf", "resolv.conf"} {
		data, err := os.ReadFile(filepath.Join("/etc", name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(etc, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mount(etc, "/etc", "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount("/etc", unix.MNT_DETACH)
	if err := Update(t.Context(), Path, fixtureRecords, nil); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("getent", "hosts", "peer.mesh").CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("100.96.0.2")) {
		t.Fatalf("system lookup: %q %v", output, err)
	}
	if err := Update(t.Context(), Path, nil, nil); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(Path)
	if err != nil || !bytes.Equal(original, restored) {
		t.Fatalf("cleanup changed hosts: %v", err)
	}
}
