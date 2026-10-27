package sshserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Whiteknight07/meshscale/internal/localstate"
	"golang.org/x/crypto/ssh"
)

// HostKey never replaces an existing key, including an unreadable or invalid one.
func HostKey(dir string) (ssh.Signer, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("SSH state directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := checkProtectedDir(dir, true); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "ssh_host_ed25519_key")
	f, err := openProtected(path, true)
	if os.IsNotExist(err) {
		_, key, genErr := ed25519.GenerateKey(rand.Reader)
		if genErr != nil {
			return nil, genErr
		}
		block, genErr := ssh.MarshalPrivateKey(key, "meshscale host key")
		if genErr != nil {
			return nil, genErr
		}
		tmp, genErr := os.CreateTemp(dir, ".host-key-*")
		if genErr != nil {
			return nil, genErr
		}
		defer os.Remove(tmp.Name())
		if genErr = pem.Encode(tmp, block); genErr == nil {
			genErr = tmp.Sync()
		}
		closeErr := tmp.Close()
		if genErr != nil {
			return nil, genErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		// Link publishes the complete key atomically without overwriting a rival.
		if err = os.Link(tmp.Name(), path); err != nil && !os.IsExist(err) {
			return nil, err
		}
		f, err = openProtected(path, true)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 16384))
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("read SSH host key: %w", err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("SSH host key must be ed25519")
	}
	return signer, nil
}

// UserHostKey supports rootless netstack sshd; this key belongs to the daemon
// user, and does not replace the system server's root-owned identity.
func UserHostKey(dir string) (ssh.Signer, error) {
	if err := localstate.Dir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "ssh-host-key.json")
	release, err := localstate.Lock(dir)
	if err != nil {
		return nil, err
	}
	defer release()
	var encoded []byte
	err = localstate.Read(path, &encoded)
	if os.IsNotExist(err) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		block, err := ssh.MarshalPrivateKey(key, "meshscale userspace host key")
		if err != nil {
			return nil, err
		}
		encoded = pem.EncodeToMemory(block)
		if err := localstate.Write(path, encoded); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(encoded)
}
