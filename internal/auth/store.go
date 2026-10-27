// Package auth implements Cloudflare's public-client OAuth login.
package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/localstate"
)

// Session is a saved login. Tokens must never be printed or logged.
type Session struct {
	ClientID     string    `json:"client_id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	Expiry       time.Time `json:"expiry"`
	Scope        string    `json:"scope,omitempty"`
	Account      Account   `json:"account"`
	Email        string    `json:"email,omitempty"`
}

type Store struct {
	Path string
}

func DefaultStore() (*Store, error) {
	dir, err := config.Dir()
	if err != nil {
		return nil, err
	}
	return &Store{Path: filepath.Join(dir, "oauth.json")}, nil
}

func (s *Store) Load() (*Session, error) {
	var session Session
	if err := localstate.Read(s.Path, &session); err != nil {
		return nil, err
	}
	if session.AccessToken == "" || session.ClientID == "" || session.Account.ID == "" {
		return nil, errors.New("incomplete OAuth login: run `meshscale login` again")
	}
	return &session, nil
}

// Save replaces the file atomically so an interrupted write keeps the old login.
func (s *Store) Save(session *Session) error {
	return localstate.Write(s.Path, session)
}

// SaveLogin publishes a new interactive login after any in-flight refresh or
// logout completes. Refresh callers already holding the lock use Save directly.
func (s *Store) SaveLogin(ctx context.Context, session *Session) error {
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return s.Save(session)
}

func (s *Store) Delete() error {
	if err := localstate.Dir(filepath.Dir(s.Path)); err != nil {
		return err
	}
	err := os.Remove(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Logout serializes revocation/deletion with refresh-token rotation, so a
// concurrent command cannot save a fresh login after logout has completed.
func (s *Store) Logout(ctx context.Context, client *Client) error {
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	session, err := s.Load()
	if err != nil {
		return err
	}
	if err := client.Revoke(ctx, session); err != nil {
		return err
	}
	return s.Delete()
}
