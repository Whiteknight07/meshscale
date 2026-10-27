//go:build linux || darwin

package localstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadRejectsOversizeState(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	// A valid JSON prefix must not hide data beyond the input limit.
	data := `{"ok":true}` + strings.Repeat(" ", readLimit) + "invalid"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var out any
	if err := Read(path, &out); err == nil {
		t.Fatal("accepted oversized state after a valid JSON prefix")
	}
}
