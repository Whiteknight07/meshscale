package native

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"path/filepath"

	"github.com/Whiteknight07/meshscale/internal/localstate"
)

type State struct {
	Account      string       `json:"account"`
	NodeID       string       `json:"node_id"`
	Name         string       `json:"name"`
	PrivateKey   string       `json:"private_key,omitempty"`
	Pending      bool         `json:"registration_pending,omitempty"`
	Registration Registration `json:"registration"`
}

func StatePath(dir string) string { return filepath.Join(dir, "registration.json") }
func LoadState(dir string) (*State, error) {
	s, err := LoadStateForRemoval(dir)
	if err != nil {
		return nil, err
	}
	if s.Registration.ID != "" {
		if err := s.Registration.Validate(); err != nil {
			return nil, err
		}
		raw, err := keyBytes(s.PrivateKey)
		if err != nil {
			return nil, err
		}
		key, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid native private key")
		}
		if s.Registration.Token == "" || base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) != s.Registration.Key {
			return nil, fmt.Errorf("native state key/credential mismatch")
		}
	}
	return s, nil
}
func (s *State) Save(dir string) error { return localstate.Write(StatePath(dir), s) }

// LoadStateForRemoval retains cleanup access after a rejected or interrupted
// enrollment. Removal verifies account and node ownership against the admin API.
func LoadStateForRemoval(dir string) (*State, error) {
	var s State
	if err := localstate.Read(StatePath(dir), &s); err != nil {
		return nil, err
	}
	if s.Account == "" || s.NodeID == "" || s.Name == "" {
		return nil, fmt.Errorf("incomplete native state; refusing to re-enroll")
	}
	return &s, nil
}
