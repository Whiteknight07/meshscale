package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/localstate"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

// nativeSSH uses the daemon's netstack directly and pins hosts just as the
// OpenSSH path does: accept a new host once, reject a changed key.
func nativeSSH(ctx context.Context, local interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}, ip netip.Addr, port int, username string, command []string) error {
	address := net.JoinHostPort(ip.String(), fmt.Sprint(port))
	dir, err := config.Dir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "known_hosts")
	callback := nativeHostKeyCallback(path, os.Stderr)
	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	raw, err := local.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return err
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	raw.SetDeadline(time.Now().Add(20 * time.Second))
	conn, channels, requests, err := ssh.NewClientConn(raw, address, &ssh.ClientConfig{User: username, HostKeyCallback: callback, Timeout: 20 * time.Second})
	if err != nil {
		return err
	}
	raw.SetDeadline(time.Time{})
	client := ssh.NewClient(conn, channels, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdin, session.Stdout, session.Stderr = os.Stdin, os.Stdout, os.Stderr
	if len(command) > 0 {
		return session.Run(strings.Join(command, " "))
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		width, height, err := term.GetSize(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}
		if err := session.RequestPty(os.Getenv("TERM"), height, width, ssh.TerminalModes{}); err != nil {
			return err
		}
		state, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}
		defer term.Restore(int(os.Stdin.Fd()), state)
	}
	if err := session.Shell(); err != nil {
		return err
	}
	return session.Wait()
}

func nativeHostKeyCallback(path string, out io.Writer) ssh.HostKeyCallback {
	return func(host string, remote net.Addr, key ssh.PublicKey) error {
		release, err := localstate.WaitLock(filepath.Join(filepath.Dir(path), "known-hosts-lock"), 5*time.Second)
		if err != nil {
			return err
		}
		defer release()
		f, err := localstate.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY)
		if err != nil {
			return err
		}
		defer f.Close()
		check, err := knownhosts.New(path)
		if err != nil {
			return err
		}
		err = check(host, remote, key)
		if err == nil {
			return nil
		}
		keyErr, ok := err.(*knownhosts.KeyError)
		if !ok || len(keyErr.Want) != 0 {
			return err
		}
		if _, err := fmt.Fprintln(f, knownhosts.Line([]string{knownhosts.Normalize(host)}, key)); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		fmt.Fprintf(out, "Added Mesh SSH host %s (%s) to %s\n", host, ssh.FingerprintSHA256(key), path)
		return nil
	}
}
