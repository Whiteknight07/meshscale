// Package selfupdate installs the CLI archives produced by release.yml.
package selfupdate

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Whiteknight07/meshscale/internal/localstate"
)

// Repository is the only repository location used by the updater.
const Repository = "Whiteknight07/meshscale"

const maxArchive = 128 << 20

var releaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

type Updater struct {
	// API is injectable for offline release-server tests. Production uses GitHub.
	API      string
	HTTP     *http.Client
	Binary   string
	OS, Arch string
}

type Release struct {
	Version string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
	Draft   bool    `json:"draft"`
}
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

func New(binary string) *Updater {
	return &Updater{API: "https://api.github.com", HTTP: &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) >= 10 {
			return fmt.Errorf("refusing unsafe release redirect")
		}
		return nil
	}}, Binary: binary, OS: runtime.GOOS, Arch: runtime.GOARCH}
}

func (u *Updater) get(ctx context.Context, rawURL string, out io.Writer, limit int64) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "https" && !(strings.HasPrefix(u.API, "http://") && parsed.Scheme == "http")) {
		return fmt.Errorf("invalid release asset URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "meshscale-updater")
	resp, err := u.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("download release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("release download returned HTTP %d", resp.StatusCode)
	}
	if resp.Request.URL.Scheme != "https" && !strings.HasPrefix(u.API, "http://") {
		return fmt.Errorf("release download redirected away from HTTPS")
	}
	n, err := io.Copy(out, io.LimitReader(resp.Body, limit+1))
	if err == nil && n > limit {
		return fmt.Errorf("release asset exceeds size limit")
	}
	return err
}

func (u *Updater) Check(ctx context.Context, version string) (Release, error) {
	var release Release
	endpoint := "/latest"
	if version != "" {
		if !releaseTag.MatchString(version) {
			return release, fmt.Errorf("version must be a release tag such as v1.2.3")
		}
		endpoint = "/tags/" + url.PathEscape(version)
	}
	var data strings.Builder
	if err := u.get(ctx, strings.TrimRight(u.API, "/")+"/repos/"+Repository+"/releases"+endpoint, &data, 1<<20); err != nil {
		return release, err
	}
	if err := json.Unmarshal([]byte(data.String()), &release); err != nil {
		return release, fmt.Errorf("invalid release metadata")
	}
	if release.Draft || !releaseTag.MatchString(release.Version) || version != "" && release.Version != version {
		return release, fmt.Errorf("unexpected release version")
	}
	return release, nil
}

func assetURL(r Release, name string) (string, error) {
	found := ""
	for _, a := range r.Assets {
		if a.Name == name {
			if found != "" || a.URL == "" {
				return "", fmt.Errorf("duplicate or empty release asset %s", name)
			}
			found = a.URL
		}
	}
	if found == "" {
		return "", fmt.Errorf("release has no %s asset", name)
	}
	return found, nil
}

func checksum(manifest, name string) (string, error) {
	scanner := bufio.NewScanner(strings.NewReader(manifest))
	found := ""
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			return "", fmt.Errorf("invalid SHA256SUMS line")
		}
		if strings.TrimPrefix(fields[1], "*") != name {
			continue
		}
		digest, err := hex.DecodeString(fields[0])
		if err != nil || len(digest) != sha256.Size || found != "" {
			return "", fmt.Errorf("invalid or duplicate checksum for %s", name)
		}
		found = strings.ToLower(fields[0])
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("missing checksum for %s", name)
	}
	return found, nil
}

func (u *Updater) Install(ctx context.Context, release Release) error {
	name := "meshscale_" + u.OS + "_" + u.Arch + ".tar.gz"
	archiveURL, err := assetURL(release, name)
	if err != nil {
		return err
	}
	sumsURL, err := assetURL(release, "SHA256SUMS")
	if err != nil {
		return err
	}
	var manifest strings.Builder
	if err := u.get(ctx, sumsURL, &manifest, 1<<20); err != nil {
		return err
	}
	want, err := checksum(manifest.String(), name)
	if err != nil {
		return err
	}
	// All temporary files live beside the binary so the final rename is atomic.
	unlock, err := u.lock()
	if err != nil {
		return err
	}
	defer unlock()
	archive, err := os.CreateTemp(filepath.Dir(u.Binary), ".meshscale-download-*")
	if err != nil {
		return err
	}
	defer os.Remove(archive.Name())
	defer archive.Close()
	hash := sha256.New()
	if err := u.get(ctx, archiveURL, io.MultiWriter(archive, hash), maxArchive); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != want {
		return fmt.Errorf("SHA256 mismatch for %s; installed binary unchanged", name)
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return err
	}
	candidate, err := os.CreateTemp(filepath.Dir(u.Binary), ".meshscale-new-*")
	if err != nil {
		return err
	}
	defer os.Remove(candidate.Name())
	defer candidate.Close()
	if err := extract(archive, candidate); err != nil {
		return err
	}
	if err := candidate.Chmod(0755); err != nil {
		return err
	}
	if err := candidate.Sync(); err != nil {
		return err
	}
	if err := candidate.Close(); err != nil {
		return err
	}
	if err := copyAtomic(u.Binary, u.Binary+".prev"); err != nil {
		return err
	}
	if err := os.Rename(candidate.Name(), u.Binary); err != nil {
		return err
	}
	return u.receipt()
}

func extract(in io.Reader, out io.Writer) error {
	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	found := false
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		total += h.Size
		if h.Size < 0 || total > 512<<20 {
			return fmt.Errorf("release archive exceeds extraction limit")
		}
		if h.Name != "meshscale" {
			continue
		}
		if found || h.Typeflag != tar.TypeReg || h.Size == 0 || h.Size > maxArchive {
			return fmt.Errorf("invalid meshscale archive entry")
		}
		found = true
		if _, err := io.CopyN(out, tr, h.Size); err != nil {
			return err
		}
	}
	// Consume the gzip trailer as well, to detect truncated/corrupt archives.
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("release archive contains no meshscale binary")
	}
	return nil
}

func regular(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file, not a symlink", path)
	}
	return nil
}

func (u *Updater) lock() (func(), error) {
	// The private lock directory also validates every installation ancestor.
	unlock, err := localstate.Lock(filepath.Join(filepath.Dir(u.Binary), ".meshscale-update"))
	if err != nil {
		return nil, err
	}
	if err := regular(u.Binary); err != nil {
		unlock()
		return nil, err
	}
	if err := regular(u.Binary + ".prev"); err != nil && !os.IsNotExist(err) {
		unlock()
		return nil, err
	}

	receipt := filepath.Join(filepath.Dir(filepath.Dir(u.Binary)), "share", "meshscale", "install-receipt")
	if _, err := os.Lstat(receipt); err == nil {
		f, err := localstate.OpenFile(receipt, os.O_RDONLY)
		if err != nil {
			unlock()
			return nil, err
		}
		f.Close()
	} else if !os.IsNotExist(err) {
		unlock()
		return nil, err
	}
	return unlock, nil
}

func copyAtomic(source, dest string) error {
	if err := regular(source); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.CreateTemp(filepath.Dir(dest), ".meshscale-copy-*")
	if err != nil {
		return err
	}
	defer os.Remove(out.Name())
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(out.Name(), dest)
}

func (u *Updater) Rollback() error {
	unlock, err := u.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := regular(u.Binary + ".prev"); err != nil {
		return fmt.Errorf("no usable previous binary: %w", err)
	}
	if err := os.Rename(u.Binary+".prev", u.Binary); err != nil {
		return err
	}
	return u.receipt()
}

// Keep the guided installer's ownership receipt usable after a CLI update.
// Source installs have no receipt and retain that distinction.
func (u *Updater) receipt() error {
	prefix := filepath.Dir(filepath.Dir(u.Binary))
	path := filepath.Join(prefix, "share", "meshscale", "install-receipt")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err := regular(path); err != nil {
		return err
	}
	var data strings.Builder
	for _, name := range []string{"meshscale", "meshscale.prev"} {
		f, err := os.Open(filepath.Join(filepath.Dir(u.Binary), name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, err = io.Copy(hash, f)
		f.Close()
		if err != nil {
			return err
		}
		fmt.Fprintf(&data, "bin/%s\t%x\n", name, hash.Sum(nil))
	}
	if err := localstate.Dir(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".receipt-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := io.WriteString(f, data.String()); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("binary replaced, but installer receipt needs repair: %w", err)
	}
	return nil
}
