package secure

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeyStore(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      os.FileMode
		data      string
		wantError bool
	}{
		{name: "new"},
		{name: "insecure", mode: 0644, data: `{}`, wantError: true},
		{name: "malformed", mode: 0600, data: `{`, wantError: true},
		{name: "invalid key", mode: 0600, data: `{"private_key":"bad"}`, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "secure")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if tc.data != "" {
				if err := os.WriteFile(filepath.Join(dir, "wireguard.json"), []byte(tc.data), tc.mode); err != nil {
					t.Fatal(err)
				}
			}
			key, err := LoadKey(dir)
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v", err)
			}
			if tc.wantError {
				return
			}
			public, err := key.Public()
			if err != nil || public == key.Private {
				t.Fatalf("invalid public key: %v", err)
			}
			again, err := LoadKey(dir)
			if err != nil || again != key {
				t.Fatalf("key not persistent: %v", err)
			}
			info, err := os.Stat(filepath.Join(dir, "wireguard.json"))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("key mode: %v", err)
			}
		})
	}
}
func TestKeySymlinkRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secure")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	key, _ := GenerateKey()
	other := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(other, []byte(`{"private_key":"`+key.Private+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, "wireguard.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(dir); err == nil {
		t.Fatal("accepted symlink")
	}
}
func TestAddress(t *testing.T) {
	key, _ := GenerateKey()
	public, _ := key.Public()
	other, _ := GenerateKey()
	otherPublic, _ := other.Public()
	first, err := Address("account", public)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, account, public string
		equal, invalid        bool
	}{
		{"stable", "account", public, true, false},
		{"different account", "other", public, false, false},
		{"different key", "account", otherPublic, false, false},
		{"missing account", "", public, false, true},
		{"invalid key", "account", "bad", false, true},
		{"low order key", "account", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip, err := Address(tc.account, tc.public)
			if (err != nil) != tc.invalid {
				t.Fatalf("error=%v", err)
			}
			if tc.invalid {
				return
			}
			if !IsIP(ip) || !ip.IsPrivate() || !ip.Is6() || (ip == first) != tc.equal {
				t.Fatalf("unexpected address %s", ip)
			}
		})
	}
}
