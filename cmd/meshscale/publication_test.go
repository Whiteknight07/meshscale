package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Whiteknight07/meshscale/internal/publication"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPublicationCommandInput(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(context.Context, []string) error
		args []string
	}{
		{name: "funnel missing port", run: runFunnel},
		{name: "funnel invalid port", run: runFunnel, args: []string{"invalid"}},
		{name: "funnel zero port", run: runFunnel, args: []string{"0"}},
		{name: "funnel high port", run: runFunnel, args: []string{"65536"}},
		{name: "funnel status extra", run: runFunnel, args: []string{"status", "extra"}},
		{name: "funnel off extra", run: runFunnel, args: []string{"off", "extra"}},
		{name: "cert extra", run: runCert, args: []string{"ashburn", "extra"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			if err := test.run(context.Background(), test.args); err == nil {
				t.Fatal("invalid publication command accepted")
			}
		})
	}
}
func TestPublicationsOnlySkipsBackendAndServiceSettings(t *testing.T) {
	dir, err := os.MkdirTemp("", "pub-cli-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "test-account")
	t.Setenv("CLOUDFLARE_API_TOKEN", "test-token")
	configDir := filepath.Join(dir, "meshscale")
	if err := os.Mkdir(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	// A full daemon must reject these settings. The publication supervisor must
	// neither read nor repair them, and its idle startup needs no account API.
	invalid := []byte("intentionally invalid backend settings")
	if err := os.WriteFile(filepath.Join(configDir, "backend.json"), invalid, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runDaemon(ctx, []string{"--publications-only"}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(configDir, "backend.json"))
	if err != nil || string(after) != string(invalid) {
		t.Fatal("publication daemon changed backend settings", err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "publication", "publication.sock")); !os.IsNotExist(err) {
		t.Fatal("publication socket survived shutdown")
	}
}

func TestOptionalServiceRetriesWithoutFailingTheDaemon(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	attempts, stopped := 0, make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		superviseOptional(ctx, log.New(io.Discard, "", 0), "test", time.Millisecond, func() (func(), error) {
			if attempts++; attempts < 3 {
				return nil, errors.New("api outage")
			}
			return func() { close(stopped) }, nil
		})
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	select {
	case <-stopped:
	default:
		t.Fatal("started service was not stopped")
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestPublicationDefaultNameUsesMeshDNSSanitizer(t *testing.T) {
	for raw, want := range map[string]string{"Stuti's MacBook Pro": "stuti-s-macbook-pro", "💻": "device", "UPPER_and space": "upper-and-space"} {
		got, err := publicationName(raw)
		if err != nil || got != want {
			t.Fatalf("%q: name=%q error=%v, want %q", raw, got, err, want)
		}
	}
}

func TestCertRemoveInput(t *testing.T) {
	for _, args := range [][]string{{"rm"}, {"rm", "one", "two"}, {"rm", "../escape"}} {
		if err := runCert(t.Context(), args); err == nil {
			t.Fatalf("accepted invalid removal %v", args)
		}
	}
}

func TestCertRemoveUsesDaemonWithoutMeshIdentity(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir, err := publicationDir()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", publication.Socket(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request publication.CertRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if r.Method != "DELETE" || r.URL.Path != "/cert" || request.Name != "ashburn" {
			t.Error("incorrect removal request", r.Method, r.URL.Path, request.Name)
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	defer server.Close()
	go server.Serve(listener)
	if err := runCert(t.Context(), []string{"rm", "ashburn"}); err != nil {
		t.Fatal(err)
	}
}
