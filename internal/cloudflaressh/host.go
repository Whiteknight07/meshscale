package cloudflaressh

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Process records only a stopped meshscale sshd's invocation, never its tokens.
type Process struct {
	Binary string   `json:"binary"`
	Args   []string `json:"args"`
}
type HostState struct {
	CreatedRunSSHD bool              `json:"created_run_sshd,omitempty"`
	Prepared       bool              `json:"prepared"`
	Own            []Process         `json:"own,omitempty"`
	ServiceSSH     bool              `json:"service_ssh"`
	OpenSSHPID     int               `json:"openssh_pid,omitempty"`
	DropIn         string            `json:"drop_in,omitempty"`
	TrustFiles     map[string]string `json:"trust_files,omitempty"`
}
type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type OwnServer interface {
	Stop(context.Context, *State) error
	Restore(context.Context, *State, bool) error
}
type OpenSSHService interface {
	Reload(context.Context, *State) error
	Restore(context.Context, *State) error
}

// FileHost writes only a trust directory and one reserved drop-in. Existing
// files at either path without matching saved state are never adopted.
type FileHost struct {
	RuntimeDir string
	SSHDir     string
	Run        CommandRunner
	Own        OwnServer
	Service    OpenSSHService
	Store      Store
}

func (h FileHost) dropIn() string {
	return filepath.Join(h.SSHDir, "sshd_config.d", "50-meshscale-cloudflare.conf")
}
func (h FileHost) privateDir() string { return filepath.Join(h.SSHDir, "meshscale-cloudflare") }
func (h FileHost) Enable(ctx context.Context, s *State, key string) (err error) {
	first := s.Host == nil
	if first {
		s.Host = &HostState{}
		if _, e := os.Lstat(h.dropIn()); !os.IsNotExist(e) {
			return fmt.Errorf("refusing existing untracked SSH drop-in: %s", h.dropIn())
		}
		if _, e := os.Lstat(h.privateDir()); !os.IsNotExist(e) {
			return fmt.Errorf("refusing existing untracked SSH trust directory: %s", h.privateDir())
		}
	}
	previous := s.Host.DropIn
	if previous != "" {
		data, e := os.ReadFile(h.dropIn())
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		if e == nil && string(data) != previous {
			return fmt.Errorf("managed SSH drop-in changed; refusing to overwrite it")
		}
	}
	if err = h.Store.Save(*s); err != nil {
		return err
	}
	// Refuse symlinks and writable parent directories before writing trust data.
	if err = os.MkdirAll(h.privateDir(), 0755); err != nil {
		return err
	}
	if err = checkDropInDir(h.privateDir()); err != nil {
		return err
	}
	if err = checkDropInDir(filepath.Dir(h.dropIn())); err != nil {
		return err
	}
	files := map[string]string{"ca.pub": strings.TrimSpace(key) + "\n"}
	for _, u := range s.Users {
		files[u] = "# Access owner: " + s.Owner + "\n" + u + "\n" + s.Owner + "\n"
	}
	for name := range files {
		path := filepath.Join(h.privateDir(), name)
		if data, e := os.ReadFile(path); e == nil {
			if old, tracked := s.Host.TrustFiles[name]; !tracked || string(data) != old {
				return fmt.Errorf("refusing untracked or changed SSH trust file %s", path)
			}
		} else if !os.IsNotExist(e) {
			return e
		}
	}
	// Persist intended contents before writing, so a partial write can be retried
	// or removed without adopting administrator files.
	s.Host.TrustFiles = files
	if err = h.Store.Save(*s); err != nil {
		return err
	}
	for name, contents := range files {
		if err = writeOwned(filepath.Join(h.privateDir(), name), []byte(contents)); err != nil {
			return err
		}
	}
	conf := renderDropIn(s.IP, h.privateDir())
	if previous == "" {
		if _, e := os.Lstat(h.dropIn()); !os.IsNotExist(e) {
			return fmt.Errorf("refusing existing untracked SSH drop-in: %s", h.dropIn())
		}
	}
	s.Host.DropIn = conf
	if err = h.Store.Save(*s); err != nil {
		return err
	}
	if err = writeOwned(h.dropIn(), []byte(conf)); err != nil {
		return err
	}
	rollback := func() error {
		s.Host.DropIn = previous
		var restore error
		if previous != "" {
			restore = writeOwned(h.dropIn(), []byte(previous))
		} else {
			restore = os.Remove(h.dropIn())
		}
		return JoinRollback(restore, h.Store.Save(*s))
	}
	if err = h.prepareRuntime(s); err != nil {
		return JoinRollback(err, rollback())
	}
	if _, err = h.Run.Run(ctx, "/usr/sbin/sshd", "-t"); err != nil {
		return JoinRollback(fmt.Errorf("sshd -t: %w", err), rollback())
	}
	// Verify that Include/first-value precedence did not bypass the managed rules.
	for _, u := range append(append([]string(nil), s.Users...), "meshscale-unmapped") {
		out, e := h.Run.Run(ctx, "/usr/sbin/sshd", "-T", "-C", "user="+u+",host=meshscale,addr="+s.IP+",laddr="+s.IP+",lport=22")
		if e != nil {
			return JoinRollback(fmt.Errorf("effective sshd configuration: %w", e), rollback())
		}
		for _, line := range []string{"trustedusercakeys " + filepath.Join(h.privateDir(), "ca.pub"), "authorizedprincipalsfile " + filepath.Join(h.privateDir(), "%u"), "authorizedkeysfile none", "authorizedkeyscommand none", "authenticationmethods publickey", "passwordauthentication no", "kbdinteractiveauthentication no", "hostbasedauthentication no", "pubkeyacceptedalgorithms ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com"} {
			if !strings.Contains("\n"+string(out), "\n"+line+"\n") {
				return JoinRollback(fmt.Errorf("sshd does not apply %q; check Include order and conflicting directives", line), rollback())
			}
		}
	}
	s.Host.Prepared = true
	s.Host.DropIn = conf
	if err = h.Store.Save(*s); err != nil {
		return JoinRollback(err, rollback())
	}
	if err = h.Own.Stop(ctx, s); err != nil {
		return JoinRollback(err, JoinRollback(rollback(), h.Own.Restore(ctx, s, s.Mode != "off")))
	}
	if err = h.Service.Reload(ctx, s); err != nil {
		restore := rollback()
		restore = JoinRollback(restore, h.Service.Restore(ctx, s))
		restore = JoinRollback(restore, h.Own.Restore(ctx, s, s.Mode != "off"))
		return JoinRollback(err, restore)
	}
	return h.Store.Save(*s)
}
func (h FileHost) Disable(ctx context.Context, s *State, mode string) error {
	if s.Host == nil {
		s.Mode = mode
		if err := h.Store.Save(*s); err != nil {
			return err
		}
		return h.Own.Restore(ctx, s, mode == "own")
	}
	if info, err := os.Lstat(h.dropIn()); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("managed SSH drop-in is not a regular file")
		}
		data, err := os.ReadFile(h.dropIn())
		if err != nil {
			return err
		}
		if string(data) != s.Host.DropIn {
			return fmt.Errorf("managed SSH drop-in changed; refusing to remove it")
		}
		if err = os.Remove(h.dropIn()); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := h.prepareRuntime(s); err != nil {
		return err
	}
	if _, err := h.Run.Run(ctx, "/usr/sbin/sshd", "-t"); err != nil {
		return fmt.Errorf("validate restored OpenSSH: %w", err)
	}
	if err := h.Service.Restore(ctx, s); err != nil {
		return err
	}
	if s.Host.CreatedRunSSHD && h.RuntimeDir != "" {
		if err := os.Remove(h.RuntimeDir); err != nil && !os.IsNotExist(err) {
			return err
		}
		s.Host.CreatedRunSSHD = false
	}
	s.Mode = mode
	if err := h.Store.Save(*s); err != nil {
		return err
	}
	if err := h.Own.Restore(ctx, s, mode == "own"); err != nil {
		return err
	}
	if err := h.removeTrust(s.Host.TrustFiles); err != nil {
		return err
	}
	s.Host = nil
	return nil
}

func (h FileHost) removeTrust(files map[string]string) error {
	if _, err := os.Lstat(h.privateDir()); os.IsNotExist(err) {
		return nil
	}
	if err := checkDropInDir(h.privateDir()); err != nil {
		return err
	}
	// Check every tracked file before removing any of them.
	for name, contents := range files {
		if filepath.Base(name) != name || name == "." || name == ".." {
			return fmt.Errorf("invalid tracked SSH trust filename %q", name)
		}
		path := filepath.Join(h.privateDir(), name)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("managed SSH trust file is not regular: %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if string(data) != contents {
			return fmt.Errorf("managed SSH trust file changed; refusing to remove %s", path)
		}
	}
	for name := range files {
		if err := os.Remove(filepath.Join(h.privateDir(), name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	// A nonempty directory contains files we did not create. Leave it and its
	// contents intact, retaining state so the administrator can resolve it.
	if err := os.Remove(h.privateDir()); err != nil {
		return fmt.Errorf("remove owned SSH trust directory (preserving untracked files): %w", err)
	}
	return nil
}
func renderDropIn(ip, dir string) string {
	return "# Managed by meshscale ssh-mode; do not edit.\nMatch LocalAddress " + ip + " LocalPort 22\n    PubkeyAuthentication yes\n    TrustedUserCAKeys " + filepath.Join(dir, "ca.pub") + "\n    AuthorizedPrincipalsFile " + filepath.Join(dir, "%u") + "\n    AuthorizedKeysFile none\n    AuthorizedKeysCommand none\n    AuthenticationMethods publickey\n    PubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    HostbasedAuthentication no\n    PermitRootLogin prohibit-password\n    DisableForwarding yes\nMatch all\n"
}
func writeOwned(path string, data []byte) error {
	if i, e := os.Lstat(path); e == nil && !i.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular file %s", path)
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".meshscale-ssh-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0644); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err == nil {
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

func (h FileHost) prepareRuntime(s *State) error {
	if h.RuntimeDir == "" {
		return nil
	}
	if _, err := os.Lstat(h.RuntimeDir); os.IsNotExist(err) {
		if err = os.Mkdir(h.RuntimeDir, 0755); err != nil {
			return err
		}
		s.Host.CreatedRunSSHD = true
		if err = h.Store.Save(*s); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return checkDropInDir(h.RuntimeDir)
}
