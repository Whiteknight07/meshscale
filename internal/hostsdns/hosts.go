// Package hostsdns maintains only a delimited .mesh block in a hosts file.
package hostsdns

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Whiteknight07/meshscale/internal/names"
)

const Path = "/etc/hosts"
const begin = "# BEGIN meshscale hosts v1"
const joined = begin + " (no preceding newline)"
const end = "# END meshscale hosts v1"

// Rewrite retains all bytes outside our block, including its former missing
// final newline. Malformed or duplicate markers are refused rather than guessed.
func Rewrite(data []byte, records []names.Record) ([]byte, error) {
	start, finish := -1, -1
	separatorSize := 0
	offset := 0
	for _, line := range bytes.SplitAfter(data, []byte("\n")) {
		text := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		switch text {
		case begin, joined:
			if start >= 0 {
				return nil, fmt.Errorf("duplicate meshscale hosts marker")
			}
			start = offset
			if text == joined {
				separatorSize = 1
				if bytes.HasSuffix(line, []byte("\r\n")) {
					separatorSize = 2
				}
			}
		case end:
			if start < 0 || finish >= 0 {
				return nil, fmt.Errorf("unmatched meshscale hosts marker")
			}
			finish = offset + len(line)
		}
		offset += len(line)
	}
	if start >= 0 && finish < 0 {
		return nil, fmt.Errorf("unfinished meshscale hosts block")
	}
	original := append([]byte(nil), data...)
	if start >= 0 {
		if separatorSize > 0 {
			separator := []byte("\n")
			if separatorSize == 2 {
				separator = []byte("\r\n")
			}
			if start < separatorSize || !bytes.Equal(data[start-separatorSize:start], separator) {
				return nil, fmt.Errorf("missing meshscale hosts separator")
			}
			start -= separatorSize
		}
		original = append(append([]byte(nil), data[:start]...), data[finish:]...)
	}
	sorted := append([]names.Record(nil), records...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Name == sorted[j].Name {
			return sorted[i].IP < sorted[j].IP
		}
		return sorted[i].Name < sorted[j].Name
	})
	var entries strings.Builder
	newline := "\n"
	if bytes.Contains(original, []byte("\r\n")) {
		newline = "\r\n"
	}
	for _, r := range sorted {
		if r.IP == "" {
			continue
		}
		// Never allow names or addresses to inject hosts syntax.
		addr, err := netip.ParseAddr(r.IP)
		validName := strings.HasSuffix(r.Name, ".mesh") && len(r.Name) <= 253
		for _, label := range strings.Split(r.Name, ".") {
			if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				validName = false
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					validName = false
				}
			}
		}
		if err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() || !validName {
			return nil, fmt.Errorf("invalid .mesh hosts record")
		}
		entries.WriteString(addr.String() + "\t" + r.Name + newline)
	}
	if entries.Len() == 0 {
		return original, nil
	}
	marker := begin
	prefix := original
	// Put the block back at its original location, preserving external edits on
	// both sides. New blocks append at EOF.
	suffix := []byte(nil)
	if start >= 0 {
		prefix, suffix = data[:start], data[finish:]
	}
	if len(prefix) > 0 && prefix[len(prefix)-1] != '\n' {
		prefix = append(append([]byte(nil), prefix...), []byte(newline)...)
		marker = joined
	}
	out := append([]byte(nil), prefix...)
	out = append(out, []byte(marker+newline+entries.String()+end+newline)...)
	return append(out, suffix...), nil
}

type Lookup func(context.Context, string) ([]netip.Addr, error)

// NeedsHosts tests actual known records through the system resolver. Check every
// name: resolving one peer is not proof that the inventory is current. Existing
// hosts entries deliberately keep auto mode enabled until down/off removes them.
func NeedsHosts(ctx context.Context, records []names.Record, lookup Lookup) bool {
	for _, record := range records {
		if record.IP == "" {
			continue
		}
		want, err := netip.ParseAddr(record.IP)
		if err != nil {
			return true
		}
		got, err := lookup(ctx, record.Name)
		found := false
		for _, ip := range got {
			if ip.Unmap() == want.Unmap() {
				found = true
			}
		}
		if err != nil || !found {
			return true
		}
	}
	return false
}

func SystemLookup(ctx context.Context, name string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", name+".")
}

// Update serializes meshscale writers and retries edits observed before rename.
// enabled is checked under the lock, so an in-flight inventory hook cannot undo
// down/off. A bind-mounted file (Docker) is rewritten in place; a read-only
// file fails.
func Update(ctx context.Context, path string, records []names.Record, enabled func() bool) error {
	return update(ctx, path, records, enabled, nil)
}

func update(ctx context.Context, path string, records []names.Record, enabled func() bool, beforeCommit func()) error {
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return err
	}
	path = filepath.Join(parent, filepath.Base(path))
	lockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	unlock, err := lock(lockCtx, path+".meshscale-lock")
	if err != nil {
		return err
	}
	defer unlock()
	if enabled != nil && !enabled() {
		records = nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("hosts file must be a regular file, not a symlink")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		next, err := Rewrite(data, records)
		if err != nil {
			return err
		}
		if bytes.Equal(data, next) {
			return nil
		}
		if info.Mode().Perm()&0222 == 0 {
			return fmt.Errorf("hosts file is read-only")
		}
		tmp, err := os.CreateTemp(parent, ".meshscale-hosts-*")
		if err != nil {
			return err
		}
		err = func() error {
			defer os.Remove(tmp.Name())
			defer tmp.Close()
			if err := metadata(tmp, info, path); err != nil {
				return err
			}
			if _, err := tmp.Write(next); err != nil {
				return err
			}
			if err := tmp.Sync(); err != nil {
				return err
			}
			if err := tmp.Close(); err != nil {
				return err
			}
			if beforeCommit != nil {
				beforeCommit()
			}
			latestInfo, err := os.Lstat(path)
			if err != nil {
				return err
			}
			latest, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if !os.SameFile(info, latestInfo) || !bytes.Equal(data, latest) || info.Mode() != latestInfo.Mode() || !info.ModTime().Equal(latestInfo.ModTime()) {
				return errConcurrentEdit
			}
			err = rename(tmp.Name(), path)
			if isMountPoint(err) {
				// Docker and similar runtimes bind-mount /etc/hosts, so it can't be
				// replaced. Rewrite it in place under our lock instead.
				return rewriteInPlace(path, next)
			}
			if err != nil {
				return fmt.Errorf("replace hosts file: %w", err)
			}
			return nil
		}()
		if err != errConcurrentEdit {
			return err
		}
	}
	return fmt.Errorf("hosts file changed concurrently; retry after the editor finishes")
}

var errConcurrentEdit = fmt.Errorf("concurrent hosts edit")

var rename = os.Rename

// rewriteInPlace writes over the start of the file before truncating, so an
// interrupted write never leaves an empty hosts file.
func rewriteInPlace(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("rewrite bind-mounted hosts file: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteAt(data, 0); err != nil {
		return fmt.Errorf("rewrite bind-mounted hosts file: %w", err)
	}
	if err := f.Truncate(int64(len(data))); err != nil {
		return fmt.Errorf("rewrite bind-mounted hosts file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("rewrite bind-mounted hosts file: %w", err)
	}
	return f.Close()
}
