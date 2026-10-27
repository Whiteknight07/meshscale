package config

import (
	"bytes"
	"strings"
	"testing"
)

func TestBackendSelectionAndWarningOnce(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	settings, err := LoadBackend()
	if err != nil || settings.Backend != "warp" {
		t.Fatalf("default=%v err=%v", settings, err)
	}
	if err := settings.Select("native"); err != nil {
		t.Fatal(err)
	}
	settings.Userspace = true
	settings.NativeDir = "/private/native"
	settings.SOCKS = "127.0.0.1:1080"
	var out bytes.Buffer
	if err := settings.Warn(&out); err != nil {
		t.Fatal(err)
	}
	if out.String() != NativeWarning+"\n" {
		t.Fatal("warning text differs")
	}
	settings, err = LoadBackend()
	if err != nil {
		t.Fatal(err)
	}
	if err := settings.Select(""); err != nil || settings.Backend != "native" || !settings.Userspace {
		t.Fatal("did not persist/reuse native")
	}
	if err := settings.Warn(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "WARNING:") != 1 {
		t.Fatal("warning repeated")
	}
	if err := settings.Select("typo"); err == nil || settings.Backend != "native" {
		t.Fatal("unknown backend fell back")
	}
	if err := settings.Select("warp"); err != nil {
		t.Fatal(err)
	}
	if err := settings.Save(); err != nil {
		t.Fatal(err)
	}
	settings, err = LoadBackend()
	if err != nil || settings.Backend != "warp" || !settings.NativeWarningShown {
		t.Fatal("explicit switch lost warning record")
	}
}
