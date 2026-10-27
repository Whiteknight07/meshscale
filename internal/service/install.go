package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/localstate"
)

const UnitPath = "/etc/systemd/system/meshscale.service"
const unitMarker = "# Managed by meshscale service\n"

type Installation struct {
	Binary     string
	ConfigHome string
	Home       string
}

func systemdQuote(s string) (string, error) {
	if s == "" || strings.ContainsAny(s, "\x00\r\n") {
		return "", fmt.Errorf("service paths must be nonempty and single-line")
	}
	// systemd expands percent specifiers even within quoted arguments.
	return strconv.Quote(strings.ReplaceAll(s, "%", "%%")), nil
}
func (i Installation) Unit() (string, error) {
	if !filepath.IsAbs(i.Binary) || !filepath.IsAbs(i.ConfigHome) || !filepath.IsAbs(i.Home) {
		return "", fmt.Errorf("service paths must be absolute")
	}
	// ExecStart performs environment expansion separately from percent
	// specifiers. A literal dollar must remain part of the executable path.
	binary, err := systemdQuote(strings.ReplaceAll(i.Binary, "$", "$$"))
	if err != nil {
		return "", err
	}
	home, err := systemdQuote("HOME=" + i.Home)
	if err != nil {
		return "", err
	}
	config, err := systemdQuote("XDG_CONFIG_HOME=" + i.ConfigHome)
	if err != nil {
		return "", err
	}
	// Options such as SSH live in the service config, not on the command line,
	// so ssh-mode can change them without rewriting the unit.
	return unitMarker + fmt.Sprintf(`[Unit]
Description=meshscale Mesh daemon
Wants=network-online.target
After=network-online.target warp-svc.service

[Service]
Type=simple
ExecStart=%s daemon
Environment=%s
Environment=%s
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
UMask=0077
LimitCORE=0

[Install]
WantedBy=multi-user.target
`, binary, home, config), nil
}
func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
func (i Installation) Plist() (string, error) {
	if _, err := i.Unit(); err != nil {
		return "", err
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.meshscale.daemon</string>
<key>ProgramArguments</key><array><string>%s</string><string>daemon</string></array>
<key>EnvironmentVariables</key><dict><key>HOME</key><string>%s</string><key>XDG_CONFIG_HOME</key><string>%s</string></dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>Umask</key><integer>63</integer>
</dict></plist>
`, xmlText(i.Binary), xmlText(i.Home), xmlText(i.ConfigHome)), nil
}

type Runner func(context.Context, string, ...string) ([]byte, error)

func Exec(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = localstate.ChildEnvironment()
	return cmd.CombinedOutput()
}

type Installer struct {
	Path string
	Run  Runner
}

func (i Installer) command(ctx context.Context, args ...string) ([]byte, error) {
	out, err := i.Run(ctx, "systemctl", args...)
	if err != nil {
		return out, fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return out, nil
}
func (i Installer) Install(ctx context.Context, unit string) error {
	if !strings.HasPrefix(unit, unitMarker) {
		return fmt.Errorf("invalid generated unit")
	}
	old, err := os.Lstat(i.Path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if !old.Mode().IsRegular() {
			return fmt.Errorf("refusing to replace non-regular unit")
		}
		contents, err := os.ReadFile(i.Path)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(string(contents), unitMarker) {
			return fmt.Errorf("refusing to replace unmanaged unit")
		}
	}
	err = nil
	existing, _ := os.ReadFile(i.Path)
	changed := !bytes.Equal(existing, []byte(unit))
	if changed {
		f, err := os.CreateTemp(filepath.Dir(i.Path), ".meshscale-unit-*")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		if err = f.Chmod(0644); err == nil {
			_, err = f.WriteString(unit)
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err := os.Rename(f.Name(), i.Path); err != nil {
			return err
		}
	}
	if _, err := i.command(ctx, "daemon-reload"); err != nil {
		return err
	}
	if _, err := i.command(ctx, "enable", "--now", "meshscale.service"); err != nil {
		return err
	}
	if changed && old != nil {
		_, err = i.command(ctx, "restart", "meshscale.service")
	}
	return err
}
func (i Installer) Uninstall(ctx context.Context) error {
	info, err := os.Lstat(i.Path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to remove non-regular unit")
	}
	contents, err := os.ReadFile(i.Path)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(contents), unitMarker) {
		return fmt.Errorf("refusing to remove unmanaged unit")
	}
	if _, err := i.command(ctx, "disable", "--now", "meshscale.service"); err != nil {
		return err
	}
	if err := os.Remove(i.Path); err != nil {
		return err
	}
	_, err = i.command(ctx, "daemon-reload")
	return err
}
