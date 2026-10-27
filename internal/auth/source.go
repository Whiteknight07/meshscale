package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

var _ cfapi.TokenSource = (*TokenSource)(nil)

type TokenSource struct {
	mu        sync.Mutex
	client    *Client
	store     *Store
	session   Session
	persisted Session
	dirty     bool
}

func NewTokenSource(client *Client, store *Store, session *Session) *TokenSource {
	c := *client
	// Refresh and revoke must use the client that issued the saved tokens.
	c.ClientID = session.ClientID
	return &TokenSource{client: &c, store: store, session: *session, persisted: *session}
}

func (s *TokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Until(s.session.Expiry) > time.Minute && !s.dirty {
		return s.session.AccessToken, nil
	}
	if s.store == nil {
		return "", errors.New("OAuth refresh requires a session store")
	}
	unlock, err := s.store.lock(ctx)
	if err != nil {
		return "", fmt.Errorf("lock OAuth login: %w", err)
	}
	defer unlock()

	// Another process may have rotated the refresh token while we waited.
	saved, err := s.store.Load()
	if err != nil {
		if !s.dirty || !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("reload OAuth login: %w", err)
		}
	} else {
		if saved.ClientID != s.session.ClientID || saved.Account.ID != s.session.Account.ID {
			return "", errors.New("OAuth login changed; rerun the command")
		}
		if !s.dirty || saved.AccessToken != s.persisted.AccessToken || saved.RefreshToken != s.persisted.RefreshToken {
			s.session, s.persisted, s.dirty = *saved, *saved, false
		}
	}
	if time.Until(s.session.Expiry) <= time.Minute {
		if s.session.RefreshToken == "" {
			return "", errors.New("OAuth login expired: run `meshscale login` again")
		}
		token, err := s.client.tokenRequest(ctx, url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {s.session.RefreshToken},
		})
		if err != nil {
			return "", err
		}
		s.session.AccessToken = token.AccessToken
		s.session.TokenType = token.TokenType
		s.session.Expiry = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
		if token.RefreshToken != "" {
			s.session.RefreshToken = token.RefreshToken
		}
		if token.Scope != "" {
			s.session.Scope = token.Scope
		}
		s.dirty = true
	}
	if s.dirty {
		if err := s.store.Save(&s.session); err != nil {
			return "", fmt.Errorf("persist refreshed OAuth login: %w", err)
		}
		s.persisted = s.session
		s.dirty = false
	}
	return s.session.AccessToken, nil
}
