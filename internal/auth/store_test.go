package auth

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStorePermissionsAndRoundTrip(t *testing.T) {
	store := &Store{Path: filepath.Join(t.TempDir(), "private", "oauth.json")}
	session := testSession()
	if err := store.Save(session); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.Path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(session); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{store.Path, 0o600}, {filepath.Dir(store.Path), 0o700}} {
		info, err := os.Stat(item.path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != item.mode {
			t.Errorf("permissions = %o, want %o", info.Mode().Perm(), item.mode)
		}
	}
	saved, err := store.Load()
	if err != nil || saved.ClientID != session.ClientID || saved.AccessToken != session.AccessToken || saved.RefreshToken != session.RefreshToken || saved.Account != session.Account || !saved.Expiry.Equal(session.Expiry) {
		t.Fatal("session did not round trip")
	}
	files, err := os.ReadDir(filepath.Dir(store.Path))
	if err != nil || len(files) != 1 {
		t.Fatal("save left temporary files behind")
	}
	if err := store.Delete(); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(); err != nil {
		t.Fatal("delete should be idempotent")
	}
}

func TestInvalidStoreDoesNotLeakContents(t *testing.T) {
	store := &Store{Path: filepath.Join(privateAuthDir(t), "oauth.json")}
	if err := os.WriteFile(store.Path, []byte(`{"access_token":"secret-sentinel"`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := store.Load()
	if err == nil || strings.Contains(err.Error(), "secret-sentinel") {
		t.Fatal("invalid store must fail without leaking token contents")
	}
}

func TestStoreRejectsUnsafeLoginFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions")
	}
	for _, kind := range []string{"public", "symlink", "foreign-owner"} {
		t.Run(kind, func(t *testing.T) {
			store := &Store{Path: filepath.Join(privateAuthDir(t), "oauth.json")}
			if err := store.Save(testSession()); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "public":
				if err := os.Chmod(store.Path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				old := store.Path + ".real"
				if err := os.Rename(store.Path, old); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(old, store.Path); err != nil {
					t.Fatal(err)
				}
			case "foreign-owner":
				if os.Geteuid() != 0 {
					t.Skip("changing ownership requires root")
				}
				if err := os.Chown(store.Path, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.Load(); err == nil {
				t.Fatal("accepted unsafe OAuth login file")
			}
		})
	}
}

func TestStoreRejectsSymlinkDirectory(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	store := &Store{Path: filepath.Join(link, "oauth.json")}
	if err := store.Save(testSession()); err == nil {
		t.Fatal("saved OAuth credentials through a directory symlink")
	}
	if _, err := os.Stat(filepath.Join(real, "oauth.json")); !os.IsNotExist(err) {
		t.Fatal("wrote credentials into symlink target")
	}
}

func privateAuthDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
