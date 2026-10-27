//go:build linux

package sshserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

type meshConn struct{ net.Conn }

func (c meshConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("100.96.0.3"), Port: 1234}
}
func (c meshConn) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP("100.96.0.2"), Port: 22} }

// Socket pairs exercise the complete protocol without starting a host listener.
func handshake(t *testing.T, a *Authorizer, username string) (*ssh.Client, error) {
	return handshakeBanner(t, a, username, nil)
}

func handshakeBanner(t *testing.T, a *Authorizer, username string, banner func(string) error) (*ssh.Client, error) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conns := make([]net.Conn, 2)
	for i, fd := range fds {
		file := os.NewFile(uintptr(fd), "ssh-test")
		conns[i], err = net.FileConn(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Signer: signer, Auth: a}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverDone := make(chan struct{})
	go func() { defer close(serverDone); server.handleConn(ctx, meshConn{conns[0]}) }()
	t.Cleanup(func() {
		conns[0].Close()
		conns[1].Close()
		select {
		case <-serverDone:
		case <-time.After(3 * time.Second):
			t.Error("server failed to stop")
		}
	})
	conns[1].SetDeadline(time.Now().Add(5 * time.Second))
	conn, chans, reqs, err := ssh.NewClientConn(conns[1], "mesh-test", &ssh.ClientConfig{User: username, BannerCallback: banner, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey())})
	if err != nil {
		return nil, err
	}
	conns[1].SetDeadline(time.Time{})
	client := ssh.NewClient(conn, chans, reqs)
	t.Cleanup(func() { client.Close() })
	return client, nil
}

func TestNoneHandshake(t *testing.T) {
	for _, tc := range []struct {
		name, user  string
		fail, allow bool
	}{
		{"Mesh identity allowed", "alice", false, true},
		{"root default denied", "root", false, false},
		{"identity unavailable denied", "alice", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Discard here: handshake handlers run concurrently with the client.
			a := testAuthorizer(new(bytes.Buffer))
			a.Audit = log.New(io.Discard, "", 0)
			if tc.fail {
				a.Identities.(*fakeIdentitySource).err = net.ErrClosed
			}
			client, err := handshake(t, a, tc.user)
			if (err == nil) != tc.allow {
				t.Fatalf("handshake err=%v allow=%v", err, tc.allow)
			}
			if client == nil {
				return
			}
			if _, err := client.Dial("tcp", "127.0.0.1:80"); err == nil {
				t.Fatal("allowed direct TCP forwarding")
			}
			if _, err := client.Listen("tcp", "127.0.0.1:0"); err == nil {
				t.Fatal("allowed remote TCP forwarding")
			}
			session, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			ok, err := session.SendRequest("auth-agent-req@openssh.com", true, nil)
			if err != nil || ok {
				t.Fatalf("agent forwarding accepted: %v %v", ok, err)
			}
			if err := session.Setenv("LD_PRELOAD", "/tmp/evil.so"); err == nil {
				t.Fatal("accepted loader environment")
			}
		})
	}
}

func TestSessionExecAndPTY(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("session credentials require root")
	}
	a := testAuthorizer(new(bytes.Buffer))
	a.Audit = log.New(io.Discard, "", 0)
	a.loadPolicy = func() (Policy, error) {
		return Policy{Rules: []Rule{{From: []string{"*"}, Users: []string{"root"}}}}, nil
	}
	home := t.TempDir()
	a.lookupUser = func(name string) (*localUser, error) {
		return &localUser{Name: name, UID: 0, GID: 0, Home: home, Shell: "/bin/sh"}, nil
	}
	t.Setenv("CLOUDFLARE_API_TOKEN", "must-not-inherit")
	client, err := handshake(t, a, "root")
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	output, err := session.CombinedOutput(`printf '%s:%s:%s' "$USER" "$HOME" "${CLOUDFLARE_API_TOKEN-unset}"; exit 7`)
	exit, ok := err.(*ssh.ExitError)
	if !ok || exit.ExitStatus() != 7 || string(output) != "root:"+home+":unset" {
		t.Fatalf("exec output=%q err=%v", output, err)
	}
	session, err = client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if output, err := session.Output(""); err != nil || len(output) != 0 {
		t.Fatalf("empty exec: output=%q err=%v", output, err)
	}
	session, err = client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err = session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	// The shell pauses for input so the resize is guaranteed to precede stty.
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var outputBuffer bytes.Buffer
	session.Stdout = &outputBuffer
	if err = session.Start("read answer; stty size; tty; echo ok"); err != nil {
		t.Fatal(err)
	}
	if err = session.WindowChange(42, 101); err != nil {
		t.Fatal(err)
	}
	io.WriteString(stdin, "go\n")
	if err = session.Wait(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(outputBuffer.String(), "42 101") || !strings.Contains(outputBuffer.String(), "/dev/pts/") || !strings.Contains(outputBuffer.String(), "ok") {
		t.Fatalf("PTY output=%q", outputBuffer.String())
	}
}

func TestHostKeyPersistence(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned file checks")
	}
	dir := filepath.Join(t.TempDir(), "state")
	first, err := HostKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := HostKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.PublicKey().Marshal(), second.PublicKey().Marshal()) {
		t.Fatal("host key changed")
	}
	path := filepath.Join(dir, "ssh_host_ed25519_key")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("key permissions %v %v", info, err)
	}
	os.Chmod(path, 0644)
	if _, err = HostKey(dir); err == nil {
		t.Fatal("accepted exposed key")
	}
	os.Chmod(path, 0600)
	os.WriteFile(path, []byte("invalid"), 0600)
	if _, err = HostKey(dir); err == nil {
		t.Fatal("silently replaced broken key")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "invalid" {
		t.Fatal("replaced existing key")
	}
}

func TestSafeEnv(t *testing.T) {
	if !safeEnv("LANG", "en_US.UTF-8") || safeEnv("HOME", "/root") || safeEnv("LD_PRELOAD", "evil") || safeEnv("LANG", "bad\x00value") {
		t.Fatal("unsafe environment allowlist")
	}
	if meshaddr.IsDevice(netip.MustParseAddr("2606:4700:cf1:2000::1")) {
		t.Fatal("proxy IP is not a Mesh device identity")
	}
}

func TestSessionRechecksPolicy(t *testing.T) {
	var revoked atomic.Bool
	a := testAuthorizer(new(bytes.Buffer))
	a.Audit = log.New(io.Discard, "", 0)
	a.loadPolicy = func() (Policy, error) {
		if revoked.Load() {
			return Policy{Rules: []Rule{}}, nil
		}
		return Policy{Rules: []Rule{{From: []string{"*"}, Users: []string{"autogroup:nonroot"}}}}, nil
	}
	client, err := handshake(t, a, "alice")
	if err != nil {
		t.Fatal(err)
	}
	revoked.Store(true)
	if _, err := client.NewSession(); err == nil {
		t.Fatal("persistent connection bypassed changed policy")
	}
}

// Window changes racing with session exit must never touch a closed PTY.
func TestSessionResizeRacesExit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("session credentials require root")
	}
	a := testAuthorizer(new(bytes.Buffer))
	a.Audit = log.New(io.Discard, "", 0)
	a.loadPolicy = func() (Policy, error) {
		return Policy{Rules: []Rule{{From: []string{"*"}, Users: []string{"root"}}}}, nil
	}
	home := t.TempDir()
	a.lookupUser = func(name string) (*localUser, error) {
		return &localUser{Name: name, UID: 0, GID: 0, Home: home, Shell: "/bin/sh"}, nil
	}
	client, err := handshake(t, a, "root")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if err = session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
			t.Fatal(err)
		}
		if err = session.Start("exit 0"); err != nil {
			t.Fatal(err)
		}
		stop := make(chan struct{})
		resized := make(chan struct{})
		go func() {
			defer close(resized)
			for h := 10; ; h++ {
				select {
				case <-stop:
					return
				default:
				}
				if session.WindowChange(h%200+1, 80) != nil {
					return
				}
			}
		}()
		session.Wait()
		close(stop)
		<-resized
		session.Close()
	}
}

func TestMissingPolicyHandshakeBanner(t *testing.T) {
	for _, name := range []string{"alice", "root", "alias", "missing"} {
		t.Run(name, func(t *testing.T) {
			a := testAuthorizer(new(bytes.Buffer))
			a.Audit = log.New(io.Discard, "", 0)
			a.loadPolicy = nil
			a.PolicyPath = filepath.Join(t.TempDir(), "ssh.json")
			var banner string
			_, err := handshakeBanner(t, a, name, func(message string) error { banner += message; return nil })
			if err == nil || !strings.Contains(banner, "SSH: no policy (denying all)") || !strings.Contains(banner, "meshscale ssh policy init") {
				t.Fatalf("banner=%q error=%v", banner, err)
			}
			t.Log(strings.TrimSpace(banner))
		})
	}
}
