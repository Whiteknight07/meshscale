// Package secure adds device-to-device WireGuard encryption over Cloudflare Mesh.
package secure

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/Whiteknight07/meshscale/internal/localstate"
)

const OverlayRange = "fd6d:6573:6873::/48"
const Port = 51821

func IsIP(ip netip.Addr) bool {
	return ip.Zone() == "" && netip.MustParsePrefix(OverlayRange).Contains(ip)
}

type Key struct {
	Private string `json:"private_key"`
}

func decodeKey(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != s {
		return nil, fmt.Errorf("invalid WireGuard key")
	}
	return b, nil
}
func (k Key) Public() (string, error) {
	b, err := decodeKey(k.Private)
	if err != nil {
		return "", err
	}
	key, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}
func GenerateKey() (Key, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, fmt.Errorf("generate secure key: %w", err)
	}
	b := k.Bytes()
	// Store WireGuard's canonical clamped scalar.
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
	return Key{Private: base64.StdEncoding.EncodeToString(b)}, nil
}
func LoadKey(dir string) (Key, error) {
	unlock, err := localstate.WaitLock(filepath.Join(dir, "key-lock"), 5*time.Second)
	if err != nil {
		return Key{}, err
	}
	defer unlock()
	path := filepath.Join(dir, "wireguard.json")
	var key Key
	err = localstate.Read(path, &key)
	if os.IsNotExist(err) {
		key, err = GenerateKey()
		if err == nil {
			err = localstate.Write(path, key)
		}
	}
	if err != nil {
		return Key{}, err
	}
	if _, err := key.Public(); err != nil {
		return Key{}, err
	}
	return key, nil
}

// Address is stable across Mesh re-addressing and daemon restarts. Account and
// public key bind the address; no peer may advertise an arbitrary overlay IP.
func Address(account, public string) (netip.Addr, error) {
	b, err := decodeKey(public)
	if err != nil || account == "" {
		return netip.Addr{}, fmt.Errorf("account and valid public key required")
	}
	// Reject low-order/zero public keys, using the standard X25519 implementation.
	probe := make([]byte, 32)
	probe[0] = 1
	priv, _ := ecdh.X25519().NewPrivateKey(probe)
	pub, _ := ecdh.X25519().NewPublicKey(b)
	if _, err := priv.ECDH(pub); err != nil {
		return netip.Addr{}, fmt.Errorf("invalid X25519 public key: %w", err)
	}
	h := sha256.Sum256(append([]byte("meshscale-secure-v1\x00"+account+"\x00"), b...))
	ip := netip.MustParsePrefix(OverlayRange).Addr().As16()
	copy(ip[6:], h[:10])
	return netip.AddrFrom16(ip), nil
}
