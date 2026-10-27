package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Whiteknight07/meshscale/internal/localstate"
)

const NativeWarning = "WARNING: The native backend is experimental. It is not a Cloudflare-documented forwarding mechanism under Cloudflare Zero Trust terms §6. It uses an undocumented device API that may change or break without notice. Use it only if you accept these risks."

type BackendSettings struct {
	Backend            string `json:"backend"`
	Userspace          bool   `json:"userspace,omitempty"`
	NativeDir          string `json:"native_state_dir,omitempty"`
	SOCKS              string `json:"socks,omitempty"`
	NativeWarningShown bool   `json:"native_warning_shown,omitempty"`
	// Paused records a deliberate `meshscale down`; the daemon does not
	// reconnect until `meshscale up` clears it.
	Paused bool `json:"paused,omitempty"`
}

func backendPath() (string, error) { dir, err := Dir(); return filepath.Join(dir, "backend.json"), err }
func LoadBackend() (*BackendSettings, error) {
	path, err := backendPath()
	if err != nil {
		return nil, err
	}
	s := &BackendSettings{Backend: "warp"}
	if err := localstate.Read(path, s); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if s.Backend != "warp" && s.Backend != "native" {
		return nil, fmt.Errorf("unknown saved backend %q; refusing to select another backend", s.Backend)
	}
	if s.NativeDir != "" && !filepath.IsAbs(s.NativeDir) {
		return nil, fmt.Errorf("saved native state directory must be absolute")
	}
	return s, nil
}
func (s *BackendSettings) Save() error {
	path, err := backendPath()
	if err != nil {
		return err
	}
	return localstate.Write(path, s)
}

// SetPaused saves whether the user deliberately disconnected.
func SetPaused(paused bool) error {
	s, err := LoadBackend()
	if err != nil || s.Paused == paused {
		return err
	}
	s.Paused = paused
	return s.Save()
}

// Paused reports a deliberate disconnect. Unreadable settings fail closed:
// reconnecting without knowing the user's saved intent can change routing.
func Paused() bool {
	s, err := LoadBackend()
	return err != nil || s.Paused
}

func (s *BackendSettings) Warn(out io.Writer) error {
	if s.NativeWarningShown {
		return nil
	}
	if _, err := fmt.Fprintln(out, NativeWarning); err != nil {
		return err
	}
	s.NativeWarningShown = true
	return s.Save()
}

// Select requires an explicit backend flag to change the saved choice.
func (s *BackendSettings) Select(explicit string) error {
	if explicit == "" {
		return nil
	}
	if explicit != "warp" && explicit != "native" {
		return fmt.Errorf("backend must be warp or native")
	}
	s.Backend = explicit
	return nil
}
func (s *BackendSettings) NativeStateDir() (string, error) {
	if s.NativeDir != "" {
		if !filepath.IsAbs(s.NativeDir) {
			return "", fmt.Errorf("native state directory must be absolute")
		}
		return s.NativeDir, nil
	}
	if os.Geteuid() == 0 {
		return "/var/lib/meshscale/native", nil
	}
	dir, err := Dir()
	return filepath.Join(dir, "native"), err
}
