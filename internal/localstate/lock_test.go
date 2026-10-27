//go:build linux || darwin

package localstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestWaitLockWaitsForBriefHolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	release, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WaitLock(dir, 50*time.Millisecond); err == nil || !strings.Contains(err.Error(), "still locked") {
		t.Fatalf("held lock: %v", err)
	}
	time.AfterFunc(50*time.Millisecond, release)
	again, err := WaitLock(dir, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	again()
}

func TestLockRejectsUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "public", "fifo", "foreign-owner"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "daemon.lock")
			if kind == "fifo" {
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			} else if kind == "symlink" {
				victim := filepath.Join(dir, "victim")
				if err := os.WriteFile(victim, nil, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, path); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "public" {
					if err := os.Chmod(path, 0644); err != nil {
						t.Fatal(err)
					}
				} else {
					if os.Geteuid() != 0 {
						t.Skip("changing ownership requires root")
					}
					if err := os.Chown(path, 65534, 65534); err != nil {
						t.Fatal(err)
					}
				}
			}
			if release, err := Lock(dir); err == nil {
				release()
				t.Fatal("accepted unsafe lock file")
			}
		})
	}
}
