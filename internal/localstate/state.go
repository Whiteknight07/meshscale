// Package localstate stores credentials in an owner-only directory.
package localstate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func Dir(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("state directory must be absolute")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !info.IsDir() || !owned(info) || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("%s must be an owned directory without symlinks or group/other write access", p)
		}
		if p == filepath.Clean(path) && (!currentOwner(info) || info.Mode().Perm() != 0700) {
			return fmt.Errorf("%s must be owned by this user with mode 0700", p)
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return nil
}

// OpenFile opens private state without following a final symlink or blocking
// on a FIFO. Validate the opened descriptor, not a separate path lookup.
func OpenFile(path string, flag int) (*os.File, error) {
	if err := Dir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	f, err := openFile(path, flag)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || !currentOwner(info) || info.Mode().Perm() != 0600 {
		f.Close()
		return nil, fmt.Errorf("%s must be an owned regular file with mode 0600", path)
	}
	return f, nil
}

// readLimit bounds a state file; mesh-state.json grows by one link per
// remembered connector, about 80 bytes each.
const readLimit = 16 << 20

func Read(path string, out any) error {
	f, err := OpenFile(path, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, readLimit+1))
	if err != nil {
		return err
	}
	if len(data) > readLimit {
		return fmt.Errorf("state exceeds %d MiB", readLimit>>20)
	}
	// Unmarshalling null into a struct succeeds without changing it. State
	// loaders prefill defaults, so accepting it would erase saved user intent.
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) || json.Unmarshal(data, out) != nil {
		return fmt.Errorf("invalid state JSON (contents withheld)")
	}
	return nil
}

func Write(path string, value any) error {
	if err := Dir(filepath.Dir(path)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(data, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
