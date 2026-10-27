//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cloudflaressh"
	"github.com/Whiteknight07/meshscale/internal/config"
)

type sshSystem struct{ store sshModeStore }

func (s sshSystem) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %v: %s: %w", name, args, strings.TrimSpace(string(out)), err)
	}
	return out, nil
}
func newCloudflareSSHHost(store sshModeStore) cloudflaressh.Host {
	s := sshSystem{store}
	return cloudflaressh.FileHost{SSHDir: "/etc/ssh", RuntimeDir: "/run/sshd", Run: s, Own: s, Service: openSSHSystem{s}, Store: store}
}
func (s sshSystem) Stop(ctx context.Context, state *cloudflaressh.State) error {
	if state.Host == nil {
		state.Host = &cloudflaressh.HostState{}
	}
	options, err := config.LoadService()
	if err != nil {
		return err
	}
	if options.SSH && options.SSHPort == 22 {
		state.Host.ServiceSSH = true
		if err = s.store.Save(*state); err != nil {
			return err
		}
		options.SSH = false
		if err = options.Save(); err != nil {
			return err
		}
		if _, err = s.Run(ctx, "systemctl", "is-active", "--quiet", "meshscale.service"); err == nil {
			if _, err = s.Run(ctx, "systemctl", "restart", "meshscale.service"); err != nil {
				return err
			}
		}
	}
	processes, err := ownSSHProcesses()
	if err != nil {
		return err
	}
	for pid, process := range processes {
		found := false
		for _, old := range state.Host.Own {
			if old.Binary == process.Binary && strings.Join(old.Args, "\x00") == strings.Join(process.Args, "\x00") {
				found = true
			}
		}
		if !found {
			state.Host.Own = append(state.Host.Own, process)
		}
		if err = s.store.Save(*state); err != nil {
			return err
		}
		if err = syscall.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("stop meshscale sshd PID %d: %w", pid, err)
		}
		for attempt := 0; attempt < 50; attempt++ {
			if syscall.Kill(pid, 0) != nil || !processListening22(pid) {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		if processListening22(pid) {
			return fmt.Errorf("meshscale sshd PID %d did not release port 22", pid)
		}
	}
	return nil
}
func (s sshSystem) Restore(ctx context.Context, state *cloudflaressh.State, own bool) error {
	options, err := config.LoadService()
	if err != nil {
		return err
	}
	if state.Host != nil && state.Host.ServiceSSH || !own && options.SSHPort == 22 {
		options.SSH = own
		if err = options.Save(); err != nil {
			return err
		}
		if _, active := s.Run(ctx, "systemctl", "is-active", "--quiet", "meshscale.service"); active == nil {
			_, err = s.Run(ctx, "systemctl", "restart", "meshscale.service")
			if err != nil {
				return err
			}
		}
	}
	if !own {
		processes, err := ownSSHProcesses()
		if err != nil {
			return err
		}
		for pid := range processes {
			if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
				return err
			}
		}
		return nil
	}
	existing, err := ownSSHProcesses()
	if err != nil {
		return err
	}
	if len(existing) > 0 || options.SSH && options.SSHPort == 22 {
		return nil
	}
	var restore []cloudflaressh.Process
	if state.Host != nil {
		restore = state.Host.Own
	}
	if len(restore) == 0 {
		binary, err := os.Executable()
		if err != nil {
			return err
		}
		restore = []cloudflaressh.Process{{Binary: binary, Args: []string{"sshd"}}}
	}
	for _, p := range restore {
		if err := startSSHProcess(p.Binary, p.Args...); err != nil {
			return err
		}
	}
	return nil
}
func (s sshSystem) Reload(ctx context.Context, state *cloudflaressh.State) error {
	for _, unit := range []string{"ssh.service", "sshd.service"} {
		if _, err := s.Run(ctx, "systemctl", "is-active", "--quiet", unit); err == nil {
			_, err = s.Run(ctx, "systemctl", "reload", unit)
			return err
		}
	}
	if state.Host.OpenSSHPID > 0 && managedOpenSSH(state.Host.OpenSSHPID) {
		return syscall.Kill(state.Host.OpenSSHPID, syscall.SIGHUP)
	}
	// No running system service: launch only on the selected Mesh IP. No public
	// listener, host networking, firewall, or unrelated sshd is changed.
	addr, err := netip.ParseAddr(state.IP)
	if err != nil {
		return err
	}
	listen := netip.AddrPortFrom(addr, 22).String()
	path, err := sshModePath()
	if err != nil {
		return err
	}
	pidfile := filepath.Join(filepath.Dir(path), "openssh.pid")
	cmd := exec.Command("/usr/sbin/sshd", "-D", "-e", "-o", "ListenAddress="+listen, "-o", "PidFile="+pidfile)
	log, err := os.OpenFile(filepath.Join(filepath.Dir(path), "openssh.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("start Mesh-only OpenSSH: %w", err)
	}
	state.Host.OpenSSHPID = cmd.Process.Pid
	if err = s.store.Save(*state); err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	_ = cmd.Process.Release()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(250 * time.Millisecond):
	}
	if !processListening22(state.Host.OpenSSHPID) {
		return fmt.Errorf("OpenSSH did not listen on port 22; inspect %s", filepath.Join(filepath.Dir(path), "openssh.log"))
	}
	return nil
}

// OpenSSHService uses a separate wrapper because OwnServer also has Restore.
type openSSHSystem struct{ sshSystem }

func (s openSSHSystem) Restore(ctx context.Context, state *cloudflaressh.State) error {
	if state.Host != nil && state.Host.OpenSSHPID > 0 {
		pid := state.Host.OpenSSHPID
		if managedOpenSSH(pid) {
			if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
				return err
			}
			for i := 0; i < 50 && processListening22(pid); i++ {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(100 * time.Millisecond):
				}
			}
			if processListening22(pid) {
				return fmt.Errorf("owned OpenSSH did not stop")
			}
		}
		state.Host.OpenSSHPID = 0
		return s.store.Save(*state)
	}
	for _, unit := range []string{"ssh.service", "sshd.service"} {
		if _, err := s.Run(ctx, "systemctl", "is-active", "--quiet", unit); err == nil {
			_, err = s.Run(ctx, "systemctl", "reload", unit)
			return err
		}
	}
	return nil
}
func managedOpenSSH(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return err == nil && strings.Contains(string(data), "sshd") && strings.Contains(string(data), "cloudflare-ssh/openssh.pid")
}

// sshProcessEnvironment hands the sealed API token only to meshscale itself
// (for environment-only credentials); any other program gets none.
func sshProcessEnvironment(binary string, credentials []string) []string {
	env := config.ChildEnvironment()
	self, err := os.Executable()
	if err != nil {
		return env
	}
	a, errA := os.Stat(self)
	b, errB := os.Stat(binary)
	if errA == nil && errB == nil && os.SameFile(a, b) {
		env = append(env, credentials...)
	}
	return env
}

func startSSHProcess(binary string, args ...string) error {
	cmd := exec.Command(binary, args...)
	cmd.Env = sshProcessEnvironment(binary, config.SealedCredentialEnvironment())
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	path, err := sshModePath()
	if err != nil {
		return err
	}
	log, err := os.OpenFile(filepath.Join(filepath.Dir(path), "own.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("restore meshscale sshd: %w", err)
	}
	return cmd.Process.Release()
}
func ownSSHProcesses() (map[int]cloudflaressh.Process, error) {
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	result := map[int]cloudflaressh.Process{}
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", d.Name(), "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
		if len(args) < 2 || !strings.Contains(filepath.Base(args[0]), "meshscale") || args[1] != "sshd" || !ownPort22(args[2:]) {
			continue
		}
		binary, err := os.Readlink(filepath.Join("/proc", d.Name(), "exe"))
		if err != nil {
			return nil, fmt.Errorf("inspect own SSH process %d (container may require privileged exec): %w", pid, err)
		}
		if strings.HasSuffix(binary, " (deleted)") {
			return nil, fmt.Errorf("cannot safely restore deleted meshscale binary PID %d", pid)
		}
		if !processListening22(pid) {
			continue
		}
		result[pid] = cloudflaressh.Process{Binary: binary, Args: args[1:]}
	}
	return result, nil
}
func processListening22(pid int) bool {
	sockets := map[string]bool{}
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) > 9 && strings.HasSuffix(f[1], ":0016") && f[3] == "0A" {
				sockets["socket:["+f[9]+"]"] = true
			}
		}
	}
	fds, _ := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	for _, fd := range fds {
		link, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
		if sockets[link] {
			return true
		}
	}
	return false
}

func ownPort22(args []string) bool {
	port := "22"
	for i := 0; i < len(args); i++ {
		if args[i] == "--port" || args[i] == "-port" {
			if i+1 >= len(args) {
				return false
			}
			i++
			port = args[i]
		} else if value, ok := strings.CutPrefix(args[i], "--port="); ok {
			port = value
		} else if value, ok := strings.CutPrefix(args[i], "-port="); ok {
			port = value
		}
	}
	return port == "22"
}
