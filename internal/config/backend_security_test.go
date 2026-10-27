package config

import (
	"os"
	"testing"
)

func TestPausedFailsClosedOnUnreadableSettings(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if Paused() {
		t.Fatal("new configuration should permit explicit enrollment")
	}
	path, err := backendPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if !Paused() {
		t.Fatal("invalid saved intent must prevent automatic reconnect")
	}
}
