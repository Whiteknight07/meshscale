// Package config holds meshscale's on-disk locations and simple env loading.
package config

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/localstate"
)

// Dir is meshscale's private config directory (~/.config/meshscale), created
// with 0700 permissions on demand.
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(base, "meshscale")
	if err := localstate.Dir(d); err != nil {
		return "", err
	}
	return d, nil
}

var sealed map[string]string

// SealCredentialEnvironment moves Cloudflare credentials out of the process
// environment so no child process (ip, nft, warp-cli, sshd, shells) can
// inherit them. LoadEnv still returns the captured values. main calls this
// once, before starting any goroutine.
func SealCredentialEnvironment() {
	sealed = map[string]string{}
	for _, k := range []string{"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"} {
		if v := os.Getenv(k); v != "" {
			sealed[k] = v
		}
	}
	for _, k := range localstate.CredentialEnvironmentKeys {
		os.Unsetenv(k)
	}
}

// SealedCredentialEnvironment returns the captured API token as KEY=VALUE
// entries, for starting meshscale itself (which seals them again at once).
// Never pass it to any other program.
func SealedCredentialEnvironment() []string {
	if v := sealed["CLOUDFLARE_API_TOKEN"]; v != "" {
		return []string{"CLOUDFLARE_API_TOKEN=" + v}
	}
	return nil
}

// LoadEnv returns KEY=VALUE pairs from <Dir>/dev.env, overridden by the
// process environment for the same keys.
func LoadEnv() (map[string]string, error) {
	out := map[string]string{}
	d, err := Dir()
	if err != nil {
		return nil, err
	}
	f, err := localstate.OpenFile(filepath.Join(d, "dev.env"), os.O_RDONLY)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if f != nil {
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if k, v, ok := strings.Cut(line, "="); ok {
				out[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		if err := s.Err(); err != nil {
			return nil, err
		}
	}
	for _, k := range []string{"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"} {
		v := os.Getenv(k)
		if v == "" {
			v = sealed[k]
		}
		if v != "" {
			out[k] = v
		}
	}
	return out, nil
}
