package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func releaseArchive(t *testing.T, entry string, duplicate bool) []byte {
	t.Helper()
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	tw := tar.NewWriter(gz)
	count := 1
	if duplicate {
		count = 2
	}
	for i := 0; i < count; i++ {
		binary := "new binary"
		if err := tw.WriteHeader(&tar.Header{Name: entry, Mode: 0755, Size: int64(len(binary)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(binary)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func TestReleaseServerLifecycle(t *testing.T) {
	root := t.TempDir()
	bindir := filepath.Join(root, "bin")
	if err := os.Mkdir(bindir, 0755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(bindir, "meshscale")
	if err := os.WriteFile(binary, []byte("old binary"), 0755); err != nil {
		t.Fatal(err)
	}
	receiptDir := filepath.Join(root, "share", "meshscale")
	if err := os.MkdirAll(receiptDir, 0700); err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(receiptDir, "install-receipt")
	if err := os.WriteFile(receipt, []byte(fmt.Sprintf("bin/meshscale\t%x\n", sha256.Sum256([]byte("old binary")))), 0600); err != nil {
		t.Fatal(err)
	}
	archive := releaseArchive(t, "meshscale", false)
	metadataRequests, archiveRequests := 0, 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/" + Repository + "/releases/latest", "/repos/" + Repository + "/releases/tags/v1.2.3":
			metadataRequests++
			json.NewEncoder(w).Encode(Release{Version: "v1.2.3", Assets: []Asset{{Name: "SHA256SUMS", URL: server.URL + "/SHA256SUMS"}, {Name: "meshscale_linux_amd64.tar.gz", URL: server.URL + "/archive"}}})
		case "/SHA256SUMS":
			fmt.Fprintf(w, "%x  meshscale_linux_amd64.tar.gz\n", sha256.Sum256(archive))
		case "/archive":
			archiveRequests++
			w.Write(archive)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	u := New(binary)
	u.API, u.HTTP, u.OS, u.Arch = server.URL, server.Client(), "linux", "amd64"
	release, err := u.Check(t.Context(), "")
	if err != nil || release.Version != "v1.2.3" {
		t.Fatalf("check: %+v %v", release, err)
	}
	if archiveRequests != 0 {
		t.Fatal("check downloaded archive")
	}
	if _, err := os.Stat(binary + ".prev"); !os.IsNotExist(err) {
		t.Fatal("check changed filesystem")
	}
	if _, err := u.Check(t.Context(), "v1.2.3"); err != nil {
		t.Fatal(err)
	}
	if err := u.Install(t.Context(), release); err != nil {
		t.Fatal(err)
	}
	checkFile(t, binary, "new binary")
	checkFile(t, binary+".prev", "old binary")
	info, _ := os.Stat(binary)
	if info.Mode().Perm() != 0755 {
		t.Fatal("installed binary is not executable")
	}
	manifest, err := os.ReadFile(receipt)
	if err != nil || !strings.Contains(string(manifest), fmt.Sprintf("bin/meshscale\t%x", sha256.Sum256([]byte("new binary")))) || !strings.Contains(string(manifest), "bin/meshscale.prev\t") {
		t.Fatalf("receipt: %q %v", manifest, err)
	}
	// Rollback has no network path, even with an unusable release server.
	server.Close()
	if err := u.Rollback(); err != nil {
		t.Fatal(err)
	}
	checkFile(t, binary, "old binary")
	if _, err := os.Stat(binary + ".prev"); !os.IsNotExist(err) {
		t.Fatal("rollback did not consume previous binary")
	}
	if err := u.Rollback(); err == nil {
		t.Fatal("rollback without backup succeeded")
	}
	if metadataRequests != 2 || archiveRequests != 1 {
		t.Fatalf("requests metadata=%d archive=%d", metadataRequests, archiveRequests)
	}
}

func checkFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("%s = %q, %v", path, got, err)
	}
}

func TestFailedVerificationNeverReplacesBinaries(t *testing.T) {
	for _, kind := range []string{"bad checksum", "duplicate checksum", "missing checksum", "malformed checksum", "archive 404", "missing binary", "duplicate binary", "path traversal", "truncated gzip"} {
		t.Run(kind, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "meshscale")
			if err := os.WriteFile(binary, []byte("original"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(binary+".prev", []byte("prior"), 0755); err != nil {
				t.Fatal(err)
			}
			entry := "meshscale"
			if kind == "missing binary" {
				entry = "README.txt"
			}
			if kind == "path traversal" {
				entry = "../meshscale"
			}
			archive := releaseArchive(t, entry, kind == "duplicate binary")
			if kind == "truncated gzip" {
				archive = archive[:len(archive)-8]
			}
			manifest := fmt.Sprintf("%x  meshscale_linux_amd64.tar.gz\n", sha256.Sum256(archive))
			switch kind {
			case "bad checksum":
				manifest = fmt.Sprintf("%064d  meshscale_linux_amd64.tar.gz\n", 0)
			case "duplicate checksum":
				manifest += manifest
			case "missing checksum":
				manifest = fmt.Sprintf("%064d  another.tar.gz\n", 0)
			case "malformed checksum":
				manifest = "garbage meshscale_linux_amd64.tar.gz\n"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/sums" {
					fmt.Fprint(w, manifest)
					return
				}
				if kind == "archive 404" {
					http.NotFound(w, r)
					return
				}
				w.Write(archive)
			}))
			defer server.Close()
			u := New(binary)
			u.API, u.HTTP, u.OS, u.Arch = server.URL, server.Client(), "linux", "amd64"
			release := Release{Version: "v1.2.3", Assets: []Asset{{Name: "SHA256SUMS", URL: server.URL + "/sums"}, {Name: "meshscale_linux_amd64.tar.gz", URL: server.URL + "/archive"}}}
			if err := u.Install(t.Context(), release); err == nil {
				t.Fatal("invalid release installed")
			}
			checkFile(t, binary, "original")
			checkFile(t, binary+".prev", "prior")
			matches, _ := filepath.Glob(filepath.Join(filepath.Dir(binary), ".meshscale-*-*"))
			if len(matches) != 0 {
				t.Fatalf("left temporary files: %v", matches)
			}
		})
	}
}

func TestMetadataAndUnsafeDestination(t *testing.T) {
	for _, version := range []string{"../latest", "v1", "v1.2.3?x", "1.2.3"} {
		u := New("unused")
		if _, err := u.Check(t.Context(), version); err == nil {
			t.Fatalf("accepted tag %q", version)
		}
	}
	for _, release := range []Release{{Version: "not-a-tag"}, {Version: "v1.2.3", Draft: true}, {Version: "v9.0.0"}} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(release) }))
		u := New("unused")
		u.API, u.HTTP = server.URL, server.Client()
		if _, err := u.Check(t.Context(), "v1.2.3"); err == nil {
			t.Fatalf("accepted metadata %+v", release)
		}
		server.Close()
	}
	binary := filepath.Join(t.TempDir(), "meshscale")
	target := filepath.Join(filepath.Dir(binary), "target")
	if err := os.WriteFile(target, []byte("safe"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, binary); err != nil {
		t.Fatal(err)
	}
	u := New(binary)
	if err := u.Rollback(); err == nil {
		t.Fatal("accepted binary symlink")
	}
	checkFile(t, target, "safe")
	if _, err := assetURL(Release{Assets: []Asset{{Name: "x", URL: "a"}, {Name: "x", URL: "b"}}}, "x"); err == nil {
		t.Fatal("accepted duplicate asset")
	}
	if _, err := assetURL(Release{}, "unsupported.tar.gz"); err == nil {
		t.Fatal("accepted absent platform asset")
	}
}
