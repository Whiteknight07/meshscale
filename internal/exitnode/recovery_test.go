package exitnode

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRecoveryRequiresSuccessfulGuard(t *testing.T) {
	unit := recoveryUnitText("/root/a% config", "/usr/sbin/nft", "/root/a% config/exit-guard.nft")
	for _, wanted := range []string{"DefaultDependencies=no", "Before=network-pre.target", "RequiredBy=network-pre.target", "a%% config"} {
		if !strings.Contains(unit, wanted) {
			t.Fatalf("missing %q in %s", wanted, unit)
		}
	}
	for _, wanted := range []string{"Requires=meshscale-exit-guard.service", "After=meshscale-exit-guard.service"} {
		if !strings.Contains(recoveryDependency, wanted) {
			t.Fatal("network startup can proceed without a successful guard")
		}
	}
}
func TestRecoveryWritesOnlyOwnedFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unit.d", "guard.conf")
	if err := writeOwned(path, recoveryDependency); err != nil {
		t.Fatal(err)
	}
	if err := writeOwned(path, recoveryDependency); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("administrator configuration"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeOwned(path, recoveryDependency); err == nil {
		t.Fatal("overwrote administrator dependency")
	}
	contents, _ := os.ReadFile(path)
	if string(contents) != "administrator configuration" {
		t.Fatal("changed foreign file")
	}
}

func TestRecoveryUnitWrittenBeforeDependencies(t *testing.T) {
	for _, failUnit := range []bool{false, true} {
		t.Run(fmt.Sprint("unit write fails=", failUnit), func(t *testing.T) {
			systemDir := t.TempDir()
			unit := filepath.Join(systemDir, filepath.Base(recoveryUnit))
			if failUnit {
				if err := os.Mkdir(unit, 0700); err != nil {
					t.Fatal(err)
				}
			}
			var commands []string
			run := runnerFunc(func(_ context.Context, _, name string, args ...string) ([]byte, error) {
				commands = append(commands, name+" "+strings.Join(args, " "))
				data, err := os.ReadFile(unit)
				if err != nil || !strings.HasPrefix(string(data), recoveryMarker) {
					t.Fatal("reloaded dependencies without unit", err)
				}
				return nil, nil
			})
			err := installRecoveryUnit(t.Context(), run, systemDir, recoveryUnitText("/state", "/usr/sbin/nft", "/state/exit-guard.nft"))
			if (err != nil) != failUnit {
				t.Fatal(err)
			}
			for _, service := range recoveryServices() {
				path := filepath.Join(systemDir, service+".d", "meshscale-exit-guard.conf")
				data, err := os.ReadFile(path)
				if failUnit {
					if !os.IsNotExist(err) {
						t.Fatal("created dependency before unit write", path, err)
					}
				} else if err != nil || string(data) != recoveryDependency {
					t.Fatal(path, err)
				}
			}
			if failUnit && len(commands) != 0 {
				t.Fatal("systemctl ran after failed unit write", commands)
			}
		})
	}
}

func TestRecoveryRemovesOrphanedOwnedDependencies(t *testing.T) {
	for _, owned := range []bool{true, false} {
		t.Run(fmt.Sprint("owned=", owned), func(t *testing.T) {
			systemDir, stateDir := t.TempDir(), t.TempDir()
			path := filepath.Join(systemDir, "NetworkManager.service.d", "meshscale-exit-guard.conf")
			if err := writeOwned(path, recoveryDependency); err != nil {
				t.Fatal(err)
			}
			if !owned {
				if err := os.WriteFile(path, []byte("administrator configuration"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			var commands []string
			run := runnerFunc(func(_ context.Context, _, name string, args ...string) ([]byte, error) {
				commands = append(commands, name+" "+strings.Join(args, " "))
				return nil, nil
			})
			err := removeRecoveryFrom(t.Context(), run, stateDir, systemDir)
			if (err != nil) == owned {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if owned {
				if !os.IsNotExist(err) || !reflect.DeepEqual(commands, []string{"systemctl daemon-reload"}) {
					t.Fatal("orphan dependency survived", err, commands)
				}
			} else if err != nil || string(data) != "administrator configuration" || len(commands) != 0 {
				t.Fatal("removed unowned dependency", err, commands)
			}
		})
	}
}

func TestRecoveryUnitExistsWhenDependencyWriteFails(t *testing.T) {
	systemDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(systemDir, "NetworkManager.service.d"), []byte("blocked directory"), 0600); err != nil {
		t.Fatal(err)
	}
	run := runnerFunc(func(context.Context, string, string, ...string) ([]byte, error) {
		t.Fatal("systemctl called after failed dependency write")
		return nil, nil
	})
	if err := installRecoveryUnit(t.Context(), run, systemDir, recoveryUnitText("/state", "/usr/sbin/nft", "/state/exit-guard.nft")); err == nil {
		t.Fatal("expected dependency write to fail")
	}
	data, err := os.ReadFile(filepath.Join(systemDir, filepath.Base(recoveryUnit)))
	if err != nil || !strings.HasPrefix(string(data), recoveryMarker) {
		t.Fatal("dependency writes preceded the unit", err)
	}
}
