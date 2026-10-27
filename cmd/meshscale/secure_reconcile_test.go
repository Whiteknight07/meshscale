package main

import (
	"path/filepath"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/secure"
)

func TestSecureReconcileRejectsDeselectedSnapshot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secure")
	stale := secure.Config{Enabled: true, ExitID: "selected"}
	if err := stale.Save(dir); err != nil {
		t.Fatal(err)
	}
	if err := (secure.Config{Enabled: true}).Save(dir); err != nil {
		t.Fatal(err)
	}
	applied := false
	err := reconcileSecureSettings(dir, stale, func() error { applied = true; return nil })
	if err == nil || applied {
		t.Fatalf("stale exit snapshot restored capture after deselection: applied=%t err=%v", applied, err)
	}
}

func TestSecureReconcileHoldsSettingsLockWhileChangingRoutes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secure")
	settings := secure.Config{Enabled: true, ExitID: "selected"}
	if err := settings.Save(dir); err != nil {
		t.Fatal(err)
	}
	err := reconcileSecureSettings(dir, settings, func() error {
		release, err := localstate.Lock(filepath.Join(dir, "config-lock"))
		if err == nil {
			release()
			t.Fatal("CLI could change settings during route mutation")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
