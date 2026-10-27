//go:build linux

package hostsdns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/Whiteknight07/meshscale/internal/names"
)

func label(t *testing.T, path string) string {
	buf := make([]byte, 256)
	n, err := unix.Lgetxattr(path, selinuxLabel, buf)
	if err != nil {
		t.Skipf("no SELinux label: %v", err)
	}
	return strings.TrimRight(string(buf[:n]), "\x00")
}

// Replacing the hosts file must keep its SELinux label instead of taking the
// directory default (e.g. etc_t or user_tmp_t instead of net_conf_t).
func TestUpdateKeepsSELinuxLabel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0644); err != nil {
		t.Fatal(err)
	}
	want := "system_u:object_r:net_conf_t:s0"
	if err := unix.Lsetxattr(path, selinuxLabel, []byte(want), 0); err != nil {
		t.Skipf("cannot set SELinux label here: %v", err)
	}
	if got := label(t, path); got != want {
		t.Skipf("label not applied as given (%q)", got)
	}
	records := []names.Record{{Name: "laptop.mesh", IP: "100.96.0.9"}}
	if err := Update(context.Background(), path, records, nil); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); !strings.Contains(string(data), "laptop") {
		t.Fatalf("hosts not updated: %s", data)
	}
	if got := label(t, path); got != want {
		t.Fatalf("SELinux label = %q, want %q", got, want)
	}
}
