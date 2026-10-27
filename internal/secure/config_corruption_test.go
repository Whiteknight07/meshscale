package secure

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNullConfigDoesNotDeselectExit(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("null\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(dir); err == nil {
		t.Fatal("null secure state silently disabled secure mode and deselected exit")
	}
}
