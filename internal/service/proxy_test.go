package service

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTCPProxyAndShutdown(t *testing.T) {
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "localhost-only\n") })}
	go server.Serve(origin)
	defer server.Close()
	var listener net.Listener
	proxies := &Proxies{Listen: func(context.Context, int) ([]net.Listener, error) {
		var err error
		listener, err = net.Listen("tcp4", "127.0.0.1:0")
		return []net.Listener{listener}, err
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer proxies.Close()
	f := Forward{Port: origin.Addr().(*net.TCPAddr).Port, MeshPort: 9000}
	if err := proxies.Add(ctx, f); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: mesh\r\nConnection: close\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "localhost-only\n" {
		t.Fatal(string(body), err)
	}
	if err := proxies.Remove(0); err != nil {
		t.Fatal(err)
	}
	if len(proxies.List()) != 0 {
		t.Fatal(proxies.List())
	}
}
func TestPrivateControlSocket(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	// Unix sockets have a short path limit; use an owned private temp directory.
	if len(Socket(dir)) > 100 {
		var err error
		dir, err = os.MkdirTemp("", "ms-control-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
	}
	proxies := &Proxies{Listen: func(context.Context, int) ([]net.Listener, error) { return nil, fmt.Errorf("not connected") }}
	ctrl := &Control{Proxies: proxies}
	ctrl.Update(func(s *Status) { s.Mode = "daemon" })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- ctrl.Run(ctx, dir, ready) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("no socket")
	}
	for path, mode := range map[string]os.FileMode{dir: 0700, Socket(dir): 0600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal(path, info, err)
		}
	}
	var status Status
	if err := Request(ctx, dir, "GET", "/status", nil, &status); err != nil || status.Mode != "daemon" {
		t.Fatal(status, err)
	}
	if err := Request(ctx, dir, "PUT", "/serve", Forward{Port: 0, MeshPort: 1}, nil); err == nil || !strings.Contains(err.Error(), "ports") {
		t.Fatal(err)
	}
	another := &Control{Proxies: proxies}
	if err := another.Run(ctx, dir, nil); err == nil {
		t.Fatal("duplicate daemon")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(Socket(dir)); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestPendingForwardsSurviveUpdatesAndOff(t *testing.T) {
	binds := 0
	proxies := &Proxies{Listen: func(context.Context, int) ([]net.Listener, error) { binds++; return nil, fmt.Errorf("offline") }}
	f := Forward{Port: 9000, MeshPort: 9000}
	if err := proxies.Load([]Forward{f}); err != nil {
		t.Fatal(err)
	}
	if err := proxies.Restore(context.Background(), f); err == nil {
		t.Fatal("expected backend not ready")
	}
	var saved []Forward
	proxies.Save = func(forwards []Forward) error { saved = forwards; return nil }
	if err := proxies.Remove(0); err != nil {
		t.Fatal(err)
	}
	if len(saved) != 0 {
		t.Fatal(saved)
	}
	// A retry that was queued before off must not resurrect the forward.
	if err := proxies.Restore(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if binds != 1 {
		t.Fatal("off forward resurrected", binds)
	}
}

func TestProxyHalfClose(t *testing.T) {
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := origin.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		request, err := io.ReadAll(conn)
		if err == nil {
			_, err = conn.Write(append([]byte("echo:"), request...))
		}
		done <- err
	}()
	var listener net.Listener
	proxies := &Proxies{Listen: func(context.Context, int) ([]net.Listener, error) {
		var err error
		listener, err = net.Listen("tcp4", "127.0.0.1:0")
		return []net.Listener{listener}, err
	}}
	defer proxies.Close()
	f := Forward{Port: origin.Addr().(*net.TCPAddr).Port, MeshPort: 8080}
	if err := proxies.Add(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	client := raw.(*net.TCPConn)
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(client)
	if err != nil || string(reply) != "echo:request" {
		t.Fatal(string(reply), err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
