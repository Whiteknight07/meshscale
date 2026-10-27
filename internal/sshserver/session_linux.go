//go:build linux

package sshserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

type windowRequest struct{ Width, Height, PixelWidth, PixelHeight uint32 }
type ptyRequest struct {
	Term                                   string
	Width, Height, PixelWidth, PixelHeight uint32
	Modes                                  string
}

type runningSession struct {
	cmd      *exec.Cmd
	terminal *os.File
	done     <-chan int
	// terminalMu orders window resizes with the PTY close on exit, so a resize
	// never reaches a closed (and possibly reused) descriptor.
	terminalMu     sync.Mutex
	terminalClosed bool
}

func (r *runningSession) resize(width, height uint32) bool {
	r.terminalMu.Lock()
	defer r.terminalMu.Unlock()
	return r.terminal != nil && !r.terminalClosed && pty.Setsize(r.terminal, terminalSize(width, height)) == nil
}

func (r *runningSession) closeTerminal() {
	r.terminalMu.Lock()
	defer r.terminalMu.Unlock()
	if !r.terminalClosed {
		r.terminalClosed = true
		r.terminal.Close()
	}
}

func safeEnv(key, value string) bool {
	if len(key) > 64 || len(value) > 1024 || strings.ContainsRune(value, 0) {
		return false
	}
	switch key {
	case "LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE", "LC_MESSAGES", "LC_MONETARY", "LC_NUMERIC", "LC_TIME":
		return true
	}
	return false
}

func terminalSize(width, height uint32) *pty.Winsize {
	if width == 0 {
		width = 80
	}
	if height == 0 {
		height = 24
	}
	if width > 65535 {
		width = 65535
	}
	if height > 65535 {
		height = 65535
	}
	return &pty.Winsize{Cols: uint16(width), Rows: uint16(height)}
}

func (s *Server) session(ctx context.Context, conn *ssh.ServerConn, target *localUser, ch ssh.Channel, requests <-chan *ssh.Request) {
	// Keep draining after the session ends: undrained requests (for example a
	// stream of window changes) would block the connection's shared mux.
	defer func() { go ssh.DiscardRequests(requests) }()
	defer ch.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var terminal *ptyRequest
	env := map[string]string{}
	var process *runningSession
	var done <-chan int
	for {
		select {
		case <-ctx.Done():
			return
		case code := <-done:
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
			return
		case request, open := <-requests:
			if !open {
				return
			}
			ok := false
			switch request.Type {
			case "env":
				var v struct{ Key, Value string }
				if process == nil && ssh.Unmarshal(request.Payload, &v) == nil && len(env) < 32 && safeEnv(v.Key, v.Value) {
					env[v.Key] = v.Value
					ok = true
				}
			case "pty-req":
				var p ptyRequest
				if process == nil && terminal == nil && ssh.Unmarshal(request.Payload, &p) == nil && len(p.Term) <= 128 && !strings.ContainsAny(p.Term, "\x00\r\n") {
					terminal = &p
					ok = true
				}
			case "window-change":
				var w windowRequest
				if terminal != nil && ssh.Unmarshal(request.Payload, &w) == nil {
					terminal.Width, terminal.Height = w.Width, w.Height
					ok = process == nil || process.resize(w.Width, w.Height)
				}
			case "shell", "exec", "subsystem":
				if process != nil {
					break
				}
				command, subsystem := "", ""
				valid := request.Type == "shell" && len(request.Payload) == 0
				if request.Type != "shell" {
					var value struct{ Value string }
					valid = ssh.Unmarshal(request.Payload, &value) == nil && !strings.ContainsRune(value.Value, 0)
					if request.Type == "exec" {
						command = value.Value
					} else {
						subsystem = value.Value
						valid = valid && subsystem == "sftp" && terminal == nil
					}
				}
				if !valid {
					break
				}
				var err error
				process, err = startSession(ctx, conn, target, ch, terminal, env, command, subsystem, request.Type == "shell")
				if err != nil {
					s.Auth.audit("deny", target.identity, target.identity.IP.String(), target.Name, "start session failed: "+err.Error())
					request.Reply(false, nil)
					return
				}
				done, ok = process.done, true
			default:
				// Includes auth-agent-req@openssh.com, X11 and forwarding requests.
				s.Auth.audit("deny", target.identity, target.identity.IP.String(), target.Name, "unsupported session request: "+request.Type)
			}
			request.Reply(ok, nil)
		}
	}
}

func sftpServer() (string, error) {
	for _, path := range []string{"/usr/lib/openssh/sftp-server", "/usr/lib/ssh/sftp-server", "/usr/libexec/openssh/sftp-server", "/usr/libexec/sftp-server"} {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("sftp-server is missing; install openssh-sftp-server")
}

func startSession(ctx context.Context, conn *ssh.ServerConn, target *localUser, ch ssh.Channel, terminal *ptyRequest, env map[string]string, command, subsystem string, shell bool) (*runningSession, error) {
	var cmd *exec.Cmd
	if subsystem == "sftp" {
		path, err := sftpServer()
		if err != nil {
			return nil, err
		}
		cmd = exec.CommandContext(ctx, path)
	} else {
		cmd = exec.CommandContext(ctx, target.Shell)
		if shell {
			cmd.Args = []string{"-" + filepath.Base(target.Shell)}
		} else {
			cmd.Args = append(cmd.Args, "-c", command)
		}
	}
	cmd.Dir = target.Home
	cmd.Env = []string{
		"HOME=" + target.Home, "SHELL=" + target.Shell, "USER=" + target.Name, "LOGNAME=" + target.Name,
		"PATH=/usr/local/bin:/usr/bin:/bin",
	}
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	remoteIP, remotePort, _ := net.SplitHostPort(conn.RemoteAddr().String())
	localIP, localPort, _ := net.SplitHostPort(conn.LocalAddr().String())
	cmd.Env = append(cmd.Env, "SSH_CLIENT="+remoteIP+" "+remotePort+" "+localPort, "SSH_CONNECTION="+remoteIP+" "+remotePort+" "+localIP+" "+localPort)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if os.Geteuid() == 0 {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: target.UID, Gid: target.GID, Groups: target.Groups}
	} else if target.UID != uint32(os.Geteuid()) || target.GID != uint32(os.Getegid()) {
		return nil, fmt.Errorf("rootless SSH sessions must use the server's UID and GID")
	}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 2 * time.Second
	result := &runningSession{cmd: cmd}
	var outputDone chan struct{}
	if terminal != nil {
		master, tty, err := pty.Open()
		if err != nil {
			return nil, err
		}
		defer tty.Close()
		fail := func(err error) (*runningSession, error) { master.Close(); return nil, err }
		if os.Geteuid() == 0 {
			if err := tty.Chown(int(target.UID), int(target.GID)); err != nil {
				return fail(err)
			}
		}
		if err := tty.Chmod(0600); err != nil {
			return fail(err)
		}
		if err := pty.Setsize(master, terminalSize(terminal.Width, terminal.Height)); err != nil {
			return fail(err)
		}
		cmd.Env = append(cmd.Env, "TERM="+terminal.Term, "SSH_TTY="+tty.Name())
		cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
		cmd.SysProcAttr.Setctty = true
		if err := cmd.Start(); err != nil {
			return fail(err)
		}
		result.terminal = master
		outputDone = make(chan struct{})
		go func() { defer close(outputDone); io.Copy(ch, master) }()
		go func() { io.Copy(master, ch) }()
	} else {
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, err
		}
		cmd.Stdout, cmd.Stderr = ch, ch.Stderr()
		if err := cmd.Start(); err != nil {
			stdin.Close()
			return nil, err
		}
		go func() { defer stdin.Close(); io.Copy(stdin, ch) }()
	}
	done := make(chan int, 1)
	result.done = done
	go func() {
		err := cmd.Wait()
		if result.terminal != nil {
			select {
			case <-outputDone:
			case <-time.After(2 * time.Second):
			}
			result.closeTerminal()
		}
		code := 0
		if err != nil {
			code = 1
			if cmd.ProcessState != nil {
				code = cmd.ProcessState.ExitCode()
				if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
					code = 128 + int(status.Signal())
				}
			}
			if code < 1 {
				code = 1
			}
		}
		done <- code
	}()
	return result, nil
}
