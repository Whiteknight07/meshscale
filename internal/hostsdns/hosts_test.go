package hostsdns

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/names"
)

var fixtureRecords = []names.Record{{Name: "peer.mesh", IP: "100.96.0.2"}, {Name: "v6.mesh", IP: "2606:4700:cf1::2"}}

func TestRewritePreservesExternalBytes(t *testing.T) {
	for _, original := range []string{"", "\r", "127.0.0.1 localhost\r", "127.0.0.1 localhost\n", "127.0.0.1 localhost", "# comment\r\n127.0.0.1\tlocalhost\r\n", "# crlf\r\n127.0.0.1 localhost"} {
		t.Run(original, func(t *testing.T) {
			first, err := Rewrite([]byte(original), fixtureRecords)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(first, []byte(original)) {
				t.Fatalf("external bytes changed: %q", first)
			}
			again, err := Rewrite(first, fixtureRecords)
			if err != nil || !bytes.Equal(first, again) {
				t.Fatalf("not idempotent: %q / %q, %v", first, again, err)
			}
			removed, err := Rewrite(first, nil)
			if err != nil || string(removed) != original {
				t.Fatalf("cleanup changed external bytes: %q, %v", removed, err)
			}
			updated, err := Rewrite(first, []names.Record{{Name: "new.mesh", IP: "100.96.0.3"}})
			if err != nil || bytes.Contains(updated, []byte("peer.mesh")) || !bytes.Contains(updated, []byte("new.mesh")) {
				t.Fatalf("stale entry: %q, %v", updated, err)
			}
			removed, err = Rewrite(updated, nil)
			if err != nil || string(removed) != original {
				t.Fatalf("updated cleanup: %q %v", removed, err)
			}
		})
	}
	data := []byte("# before\r\n" + begin + "\r\n100.96.0.2\tpeer.mesh\r\n" + end + "\r\n# after\r\n")
	removed, err := Rewrite(data, nil)
	if err != nil || string(removed) != "# before\r\n# after\r\n" {
		t.Fatalf("middle block cleanup: %q %v", removed, err)
	}
}

func TestRejectMalformedBlocksAndRecords(t *testing.T) {
	for _, data := range []string{begin + "\n", end + "\n", begin + "\n" + begin + "\n" + end + "\n", begin + "\n" + end + "\n" + end + "\n", joined + "\n" + end + "\n"} {
		if _, err := Rewrite([]byte(data), nil); err == nil {
			t.Fatalf("accepted %q", data)
		}
	}
	for _, r := range []names.Record{{Name: "peer.mesh\nINJECT", IP: "100.96.0.1"}, {Name: "peer.example", IP: "100.96.0.1"}, {Name: "peer.mesh", IP: "0.0.0.0"}, {Name: "peer.mesh", IP: "fe80::1%eth0"}} {
		if _, err := Rewrite(nil, []names.Record{r}); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
}

func TestUpdateTempFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	original := []byte("127.0.0.1 localhost\r\n# keep me")
	if err := os.WriteFile(path, original, 0644); err != nil {
		t.Fatal(err)
	}
	if err := Update(t.Context(), path, fixtureRecords, nil); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if err := Update(t.Context(), path, fixtureRecords, nil); err != nil {
		t.Fatal(err)
	}
	same, _ := os.Stat(path)
	if !os.SameFile(info, same) {
		t.Fatal("unchanged inventory rewrote hosts")
	}
	if err := Update(t.Context(), path, fixtureRecords, func() bool { return false }); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !bytes.Equal(data, original) {
		t.Fatalf("cleanup: %q", data)
	}
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatal(err)
	}
	if err := Update(t.Context(), path, fixtureRecords, nil); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("read-only file: %v", err)
	}
	data, _ = os.ReadFile(path)
	if !bytes.Equal(data, original) {
		t.Fatal("read-only failure changed file")
	}
}

func TestConcurrentEditorRetried(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("# original\n"), 0644); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := update(t.Context(), path, fixtureRecords, nil, func() {
		calls++
		if calls == 1 {
			if err := os.WriteFile(path, []byte("# editor won\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}
	})
	if err != nil || calls != 2 {
		t.Fatalf("retry: calls %d: %v", calls, err)
	}
	data, _ := os.ReadFile(path)
	if !bytes.HasPrefix(data, []byte("# editor won\n")) {
		t.Fatalf("lost editor's bytes: %q", data)
	}
	err = update(t.Context(), path, nil, nil, func() {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteString("# busy editor\n"); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "concurrently") {
		t.Fatalf("persistent editor: %v", err)
	}
}

func TestAutoSystemResolverDecision(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer []netip.Addr
		err    error
		want   bool
	}{
		{"works", []netip.Addr{netip.MustParseAddr("100.96.0.2")}, nil, false},
		{"stale", []netip.Addr{netip.MustParseAddr("100.96.0.9")}, nil, true},
		{"missing", nil, &net.DNSError{IsNotFound: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(_ context.Context, name string) ([]netip.Addr, error) {
				if name != "peer.mesh" {
					t.Fatal(name)
				}
				return tc.answer, tc.err
			}
			if got := NeedsHosts(t.Context(), fixtureRecords[:1], lookup); got != tc.want {
				t.Fatalf("needed %t", got)
			}
		})
	}
}

func TestDownWaitsForInflightWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	original := []byte("# original\n")
	if err := os.WriteFile(path, original, 0644); err != nil {
		t.Fatal(err)
	}
	writing, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- update(context.Background(), path, fixtureRecords, nil, func() { close(writing); <-release })
	}()
	<-writing
	removed := make(chan error, 1)
	go func() { removed <- Update(context.Background(), path, nil, nil) }()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatalf("down left stale records: %q %v", data, err)
	}
}
