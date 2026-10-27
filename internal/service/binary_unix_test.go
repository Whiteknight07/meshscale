//go:build linux || darwin

package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSystemServiceRejectsReplaceableExecutables(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership checks")
	}
	for _, kind := range []string{"writable-binary", "foreign-binary", "writable-parent", "foreign-parent", "symlink", "relative"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "meshscale")
			if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := ValidateSystemBinary(path); err != nil {
				t.Fatalf("valid root-owned executable rejected: %v", err)
			}
			switch kind {
			case "writable-binary":
				if err := os.Chmod(path, 0777); err != nil {
					t.Fatal(err)
				}
			case "foreign-binary":
				if err := os.Chown(path, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "writable-parent":
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatal(err)
				}
			case "foreign-parent":
				if err := os.Chown(dir, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				link := path + ".link"
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "relative":
				path = "meshscale"
			}
			if err := ValidateSystemBinary(path); err == nil {
				t.Fatal("accepted replaceable system service executable")
			}
		})
	}
	if err := ValidateSystemBinary("/tmp/meshscale"); err == nil {
		t.Fatal("accepted missing executable")
	}
}
