package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/Whiteknight07/meshscale/internal/localstate"
)

// MeshState remembers verified registration-to-node links: Cloudflare removes
// them from /connections while offline. No credentials or tokens are stored.
type MeshState struct {
	Accounts map[string]map[string]string `json:"accounts"`
	path     string
}

func LoadMeshState() (*MeshState, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	state := &MeshState{path: filepath.Join(dir, "mesh-state.json")}
	err = localstate.Read(state.path, state)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	return state, nil
}

func (s *MeshState) Remember(account, node, registration string) {
	if s == nil || registration == "" || node == "" {
		return
	}
	if s.Accounts == nil {
		s.Accounts = map[string]map[string]string{}
	}
	if s.Accounts[account] == nil {
		s.Accounts[account] = map[string]string{}
	}
	s.Accounts[account][registration] = node
}

func (s *MeshState) Node(account, registration string) string {
	if s == nil {
		return ""
	}
	return s.Accounts[account][registration]
}

func (s *MeshState) Registrations(account, node string) []string {
	if s == nil {
		return nil
	}
	var ids []string
	for id, n := range s.Accounts[account] {
		if n == node {
			ids = append(ids, id)
		}
	}
	return ids
}

func (s *MeshState) Save() error {
	if s == nil || s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".mesh-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), s.path)
}
