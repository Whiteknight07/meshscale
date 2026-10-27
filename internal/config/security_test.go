package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirRejectsUnsafeConfiguration(t *testing.T) {
	for _, kind := range []string{"public", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", base)
			path := filepath.Join(base, "meshscale")
			if kind == "public" {
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Symlink(t.TempDir(), path); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Dir(); err == nil {
				t.Fatal("accepted unsafe config directory")
			}
		})
	}
}

func TestLoadEnvRejectsExposedAndLinkedCredentials(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "dev.env")
	if err := os.WriteFile(path, []byte("CLOUDFLARE_API_TOKEN=not-for-output\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnv(); err == nil {
		t.Fatal("accepted exposed credentials")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnv(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".real", path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnv(); err == nil {
		t.Fatal("accepted linked credentials")
	}
}
