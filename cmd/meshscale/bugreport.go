package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/warpcli"
)

const bugreportInputLimit = 1 << 20
const bugreportREADME = "Local diagnostic archive. Nothing was uploaded. Only allowlisted diagnostic fields, parsed versions, timestamps and log levels are exported. Arbitrary messages, command output, identifiers and credential files are withheld. Inputs are bounded to 1 MiB each; journal is limited to 500 lines. Review before sharing. A handshake is not verified egress.\n"

// A child cannot make a bundle arbitrarily large. Continue consuming its output
// after the limit so it cannot block on a full stdout pipe.
type bugreportBuffer struct {
	bytes.Buffer
	truncated bool
}

func (b *bugreportBuffer) Write(p []byte) (int, error) {
	n := len(p)
	keep := min(n, bugreportInputLimit-b.Len())
	if keep < n {
		b.truncated = true
	}
	_, _ = b.Buffer.Write(p[:keep])
	return n, nil
}

func runBugreport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("bugreport", flag.ContinueOnError)
	out := fs.String("out", "", "explicit destination for a local tar.gz (never uploaded)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: meshscale bugreport [--out PATH]")
	}
	explicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "out" {
			explicit = true
		}
	})
	if explicit && strings.TrimSpace(*out) == "" {
		return errors.New("--out requires a file path")
	}
	if !explicit {
		*out = "meshscale-bugreport-" + time.Now().UTC().Format("20060102T150405.000000000Z") + ".tar.gz"
		if err := confirmBugreport(os.Stdin, os.Stderr, *out); err != nil {
			return err
		}
	}
	// Reserve privately without overwriting files or following existing symlinks.
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create local archive: %w", err)
	}
	complete := false
	defer func() {
		f.Close()
		if !complete {
			os.Remove(*out)
		}
	}()
	files, secrets := collectBugreport(ctx)
	if err := writeBugreport(f, files, secrets); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	complete = true
	_, err = fmt.Fprintf(os.Stdout, "Wrote local redacted bugreport: %s (never uploaded)\n", *out)
	return err
}
func confirmBugreport(in io.Reader, out io.Writer, path string) error {
	if _, err := fmt.Fprintf(out, "Write a local redacted diagnostic archive to %s? [y/N] ", path); err != nil {
		return err
	}
	line, _ := bufio.NewReader(io.LimitReader(in, 4096)).ReadString('\n')
	if answer := strings.ToLower(strings.TrimSpace(line)); answer != "y" && answer != "yes" {
		return errors.New("bugreport canceled; use --out PATH to explicitly choose an archive")
	}
	return nil
}

type bugreportSource struct {
	name string
	read func(context.Context) ([]byte, error)
}

func collectBugreport(ctx context.Context) (map[string][]byte, []string) {
	dir, _ := doctorConfigDir()
	sources := []bugreportSource{
		{"doctor.json", func(ctx context.Context) ([]byte, error) { return json.MarshalIndent(collectDoctor(ctx), "", "  ") }},
		{"versions.txt", func(ctx context.Context) ([]byte, error) {
			out, err := doctorCommand(ctx, warpcli.DefaultPath(), "--version")
			header := fmt.Sprintf("meshscale %s\nGo %s\nOS %s/%s\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			if err != nil {
				return []byte(header + "official client version unavailable\n"), nil
			}
			return append([]byte(header), out...), nil
		}},
		{"service-config.json", func(context.Context) ([]byte, error) {
			return readBugreportFile(filepath.Join(dir, "service", "config.json"))
		}},
		{"secure-config.json", func(context.Context) ([]byte, error) {
			return readBugreportFile(filepath.Join(dir, "secure", "config.json"))
		}},
		{"journal.txt", func(ctx context.Context) ([]byte, error) {
			return doctorCommand(ctx, "journalctl", "--unit=meshscale.service", "--lines=500", "--no-pager", "--output=short-iso", "--quiet")
		}},
	}
	if runtime.GOOS == "linux" {
		sources = append(sources, bugreportSource{"ip-rule.txt", func(ctx context.Context) ([]byte, error) {
			v4, err4 := doctorCommand(ctx, "ip", "-4", "rule", "show")
			v6, err6 := doctorCommand(ctx, "ip", "-6", "rule", "show")
			return append(append(v4, []byte("\nIPv6:\n")...), v6...), errors.Join(err4, err6)
		}}, bugreportSource{"mesh-routes.json", bugreportMeshRoutes})
	}
	files := collectBugreportSources(ctx, sources)
	files["README.txt"] = []byte(bugreportREADME)
	return files, bugreportKnownSecrets(dir)
}
func collectBugreportSources(ctx context.Context, sources []bugreportSource) map[string][]byte {
	files := make(map[string][]byte, len(sources))
	var mu sync.Mutex
	var workers sync.WaitGroup
	for _, source := range sources {
		workers.Go(func() {
			readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			// The same deadline covers non-context-aware filesystem readers.
			done := make(chan doctorValue[[]byte], 1)
			go func() { data, err := source.read(readCtx); done <- doctorValue[[]byte]{data, err} }()
			var data []byte
			select {
			case result := <-done:
				data = result.value
				if result.err != nil {
					data = []byte("unavailable: source missing, permission denied, or read failed (raw error withheld)\n")
				}
			case <-readCtx.Done():
				data = []byte("unavailable: collection deadline exceeded\n")
			}
			mu.Lock()
			if strings.HasSuffix(source.name, ".json") && !json.Valid(data) {
				data, _ = json.Marshal(map[string]string{"unavailable": strings.TrimSpace(string(data))})
			}
			files[source.name] = data
			mu.Unlock()
		})
	}
	workers.Wait()
	return files
}
func readBugreportFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input is not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, bugreportInputLimit+1))
	if len(data) > bugreportInputLimit {
		return nil, errors.New("input exceeds diagnostic size limit")
	}
	return data, err
}
func bugreportKnownSecrets(dir string) []string {
	var secrets []string
	// Never archive these files; read secret values solely to scrub unlabelled logs.
	paths := []string{filepath.Join(dir, "oauth.json"), filepath.Join(dir, "secure", "wireguard.json"), filepath.Join(dir, "service", "config.json"), filepath.Join(dir, "secure", "config.json"), filepath.Join(dir, "native", "registration.json"), "/var/lib/meshscale/native/registration.json"}
	var settings config.BackendSettings
	if doctorReadJSON(filepath.Join(dir, "backend.json"), &settings) == nil && settings.NativeDir != "" {
		nativeDir := settings.NativeDir
		if filepath.IsAbs(nativeDir) {
			paths = append(paths, filepath.Join(nativeDir, "registration.json"))
		}
	}
	for _, path := range paths {
		if data, err := readBugreportFile(path); err == nil {
			secrets = append(secrets, bugreportJSONSecrets(data)...)
		}
	}
	if data, err := readBugreportFile(filepath.Join(dir, "dev.env")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if ok && bugreportSecretField.MatchString(key) {
				secrets = append(secrets, strings.Trim(strings.TrimSpace(value), "\"'"))
			}
		}
	}
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		if bugreportSecretField.MatchString(key) && value != "" {
			secrets = append(secrets, value)
		}
	}
	return secrets
}
func writeBugreport(out io.Writer, files map[string][]byte, secrets []string) error {
	// Discover labelled secrets in ALL inputs before exporting ANY input; journals
	// can repeat a config secret without its field name.
	for _, data := range files {
		secrets = append(secrets, bugreportJSONSecrets(data)...)
	}
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if filepath.Base(name) != name || name == "." || name == ".." {
			tw.Close()
			gz.Close()
			return errors.New("invalid diagnostic member name")
		}
		data := redactBugreport(files[name], secrets)
		if name == "README.txt" {
			data = []byte(bugreportREADME)
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			tw.Close()
			gz.Close()
			return err
		}
		if _, err := tw.Write(data); err != nil {
			tw.Close()
			gz.Close()
			return err
		}
	}
	return errors.Join(tw.Close(), gz.Close())
}
