package service

import (
	"context"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestServiceExecutorDoesNotInheritCredentials(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix subprocess fixture")
	}
	names := []string{"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY", "CF_API_TOKEN", "CF_API_KEY"}
	for _, name := range names {
		t.Setenv(name, "not-for-systemctl")
	}
	out, err := Exec(t.Context(), "/usr/bin/env")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if strings.Contains(string(out), name+"=") {
			t.Fatal("service executor inherited credentials")
		}
	}
}

func TestServiceDocuments(t *testing.T) {
	i := Installation{Binary: "/opt/mesh scale/meshscale", Home: "/root", ConfigHome: "/root/config%name"}
	unit, err := i.Unit()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`ExecStart="/opt/mesh scale/meshscale" daemon`, `config%%name`, `UMask=0077`, `LimitCORE=0`, `Restart=on-failure`, `WantedBy=multi-user.target`} {
		if !strings.Contains(unit, want) {
			t.Fatal(unit)
		}
	}
	i.Binary = "/opt/${ATTACKER}/meshscale"
	unit, err = i.Unit()
	if err != nil || !strings.Contains(unit, `ExecStart="/opt/$${ATTACKER}/meshscale" daemon`) {
		t.Fatalf("executable environment expansion: %s %v", unit, err)
	}
	i.Binary = "/opt/mesh<scale>/cli"
	plist, err := i.Plist()
	if err != nil {
		t.Fatal(err)
	}
	var parsed any
	if err := xml.Unmarshal([]byte(plist), &parsed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plist, "mesh&lt;scale&gt;") {
		t.Fatal(plist)
	}
	i.Binary = "/bin/meshscale\nExecStart=/bad"
	if _, err := i.Unit(); err == nil {
		t.Fatal("accepted newline")
	}
}
func TestInstallIdempotentAndUninstall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meshscale.service")
	var calls []string
	runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	installer := Installer{Path: path, Run: runner}
	unit, _ := (Installation{Binary: "/opt/meshscale", Home: "/root", ConfigHome: "/root/.config"}).Unit()
	for range 2 {
		if err := installer.Install(context.Background(), unit); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"systemctl daemon-reload", "systemctl enable --now meshscale.service", "systemctl daemon-reload", "systemctl enable --now meshscale.service"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatal(calls)
	}
	if err := installer.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	n := len(calls)
	if err := installer.Uninstall(context.Background()); err != nil || len(calls) != n {
		t.Fatal(err, calls)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
func TestInstallDoesNotClobberUnownedOrEnableOnFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meshscale.service")
	calls := 0
	runner := func(context.Context, string, ...string) ([]byte, error) {
		calls++
		return nil, errors.New("not systemd")
	}
	installer := Installer{Path: path, Run: runner}
	unit, _ := (Installation{Binary: "/bin/meshscale", Home: "/root", ConfigHome: "/root/.config"}).Unit()
	if err := os.WriteFile(path, []byte("unmanaged"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := installer.Install(context.Background(), unit); err == nil || calls != 0 {
		t.Fatal(err, calls)
	}
	if err := installer.Uninstall(context.Background()); err == nil || calls != 0 {
		t.Fatal(err, calls)
	}
	os.Remove(path)
	if err := installer.Install(context.Background(), unit); err == nil || calls != 1 {
		t.Fatal(err, calls)
	}
}
