package exitnode

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const recoveryUnit = "/etc/systemd/system/meshscale-exit-guard.service"
const recoveryMarker = "# Managed by meshscale exit v2\n"

func installRecovery(ctx context.Context, run Runner, dir, body string) error {
	path, err := filepath.Abs(filepath.Join(dir, "exit-guard.nft"))
	if err != nil {
		return err
	}
	script := "add table inet " + GuardTable + "\nflush table inet " + GuardTable + "\ntable inet " + GuardTable + " {\n comment \"" + ownership + "\"\n" + body + "}\n"
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := atomicFile(path, []byte(script), 0600); err != nil {
		return err
	}
	// Containers without an init retain runtime crash protection. Their network
	// namespace must restore this file before enabling networking on recreation.
	if _, err := os.Stat("/run/systemd/system"); os.IsNotExist(err) {
		return nil
	}
	binary, err := exec.LookPath("nft")
	if err != nil {
		return err
	}
	contents := recoveryUnitText(dir, binary, path)
	return installRecoveryUnit(ctx, run, filepath.Dir(recoveryUnit), contents)
}

func installRecoveryUnit(ctx context.Context, run Runner, systemDir, contents string) error {
	// Dependencies must never refer to a unit that has not been written yet.
	if err := writeOwned(filepath.Join(systemDir, filepath.Base(recoveryUnit)), contents); err != nil {
		return err
	}
	for _, service := range recoveryServices() {
		dependency := filepath.Join(systemDir, service+".d", "meshscale-exit-guard.conf")
		if err := writeOwned(dependency, recoveryDependency); err != nil {
			return err
		}
	}
	if _, err := run.Run(ctx, "", "systemctl", "daemon-reload"); err != nil {
		return err
	}
	_, err := run.Run(ctx, "", "systemctl", "enable", "meshscale-exit-guard.service")
	return err
}
func removeRecovery(ctx context.Context, run Runner, dir string) error {
	return removeRecoveryFrom(ctx, run, dir, filepath.Dir(recoveryUnit))
}

func removeRecoveryFrom(ctx context.Context, run Runner, dir, systemDir string) error {
	unit := filepath.Join(systemDir, filepath.Base(recoveryUnit))
	old, err := os.ReadFile(unit)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	exists := err == nil
	if exists && !strings.HasPrefix(string(old), recoveryMarker) {
		return fmt.Errorf("refusing to remove unowned exit recovery unit")
	}
	changed := false
	for _, service := range recoveryServices() {
		path := filepath.Join(systemDir, service+".d", "meshscale-exit-guard.conf")
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !strings.HasPrefix(string(data), recoveryMarker) {
			return fmt.Errorf("refusing to remove unowned recovery dependency %s", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		changed = true
	}
	if exists {
		if _, err := run.Run(ctx, "", "systemctl", "disable", "meshscale-exit-guard.service"); err != nil {
			return err
		}
		if err := os.Remove(unit); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		if _, err := run.Run(ctx, "", "systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	if err := os.Remove(filepath.Join(dir, "exit-guard.nft")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func recoveryUnitText(dir, binary, path string) string {
	return recoveryMarker + fmt.Sprintf(`[Unit]
Description=Restore meshscale selected-exit leak guard
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target NetworkManager.service systemd-networkd.service warp-svc.service tailscaled.service meshscale.service
Wants=network-pre.target
RequiresMountsFor=%s

[Service]
Type=oneshot
ExecStart=%s -f %s
RemainAfterExit=yes

[Install]
RequiredBy=network-pre.target
`, strconv.Quote(strings.ReplaceAll(dir, "%", "%%")), strconv.Quote(binary), strconv.Quote(strings.ReplaceAll(path, "%", "%%")))
}

const recoveryDependency = recoveryMarker + "[Unit]\nRequires=meshscale-exit-guard.service\nAfter=meshscale-exit-guard.service\n"

func recoveryServices() []string {
	return []string{"NetworkManager.service", "systemd-networkd.service", "warp-svc.service", "tailscaled.service", "meshscale.service"}
}
func writeOwned(path, contents string) error {
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && !strings.HasPrefix(string(old), recoveryMarker) {
		return fmt.Errorf("refusing to replace unowned exit recovery file %s", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return atomicFile(path, []byte(contents), 0644)
}
func atomicFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".meshscale-exit-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
