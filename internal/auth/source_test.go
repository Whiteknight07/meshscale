package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testSession() *Session {
	return &Session{ClientID: "saved-client", AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "Bearer", Expiry: time.Now().Add(30 * time.Second), Account: Account{ID: "account", Name: "My account"}, Email: "me@example.com", Scope: "offline_access"}
}

func TestRefreshAheadOfExpiryPersistsRotation(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		name := "kept-refresh"
		if rotate {
			name = "rotated-refresh"
		}
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				r.ParseForm()
				if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "old-refresh" || r.Form.Get("client_id") != "saved-client" || r.Form.Has("client_secret") {
					t.Error("incorrect refresh request")
				}
				token := tokenResponse{AccessToken: "new-access", TokenType: "Bearer", ExpiresIn: 3600}
				if rotate {
					token.RefreshToken = "new-refresh"
				}
				json.NewEncoder(w).Encode(token)
			}))
			defer server.Close()
			store := &Store{Path: filepath.Join(privateAuthDir(t), "oauth.json")}
			session := testSession()
			if err := store.Save(session); err != nil {
				t.Fatal(err)
			}
			client := NewClient()
			client.ClientID, client.TokenURL = "different-env-client", server.URL
			source := NewTokenSource(client, store, session)
			var wg sync.WaitGroup
			for range 12 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					token, err := source.Token(context.Background())
					if err != nil || token != "new-access" {
						t.Errorf("refresh failed: %v", err)
					}
				}()
			}
			wg.Wait()
			if requests.Load() != 1 {
				t.Fatalf("refresh requests = %d, want 1", requests.Load())
			}
			saved, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			wantRefresh := "old-refresh"
			if rotate {
				wantRefresh = "new-refresh"
			}
			if saved.AccessToken != "new-access" || saved.RefreshToken != wantRefresh || saved.Account != session.Account || saved.Email != session.Email || saved.Scope != session.Scope || time.Until(saved.Expiry) < 59*time.Minute {
				t.Fatal("refreshed login was not persisted correctly")
			}
		})
	}
}

func TestUnexpiredTokenDoesNotRefresh(t *testing.T) {
	session := testSession()
	session.Expiry = time.Now().Add(time.Hour)
	client := NewClient()
	client.TokenURL = "http://invalid.invalid"
	source := NewTokenSource(client, nil, session)
	token, err := source.Token(context.Background())
	if err != nil || token != session.AccessToken {
		t.Fatalf("unexpired token: %v", err)
	}
}

func TestRefreshFailurePreservesSavedLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "sensitive-response", http.StatusBadRequest)
	}))
	defer server.Close()
	store := &Store{Path: filepath.Join(privateAuthDir(t), "oauth.json")}
	session := testSession()
	store.Save(session)
	client := NewClient()
	client.TokenURL = server.URL
	if _, err := NewTokenSource(client, store, session).Token(context.Background()); err == nil {
		t.Fatal("expected refresh failure")
	}
	saved, err := store.Load()
	if err != nil || saved.RefreshToken != session.RefreshToken || saved.AccessToken != session.AccessToken {
		t.Fatal("failed refresh changed saved tokens")
	}
}

func TestRotatedTokenRetainedAfterPersistenceFailure(t *testing.T) {
	store := &Store{Path: filepath.Join(privateAuthDir(t), "oauth.json")}
	if err := store.Save(testSession()); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		// Make the save fail after the locked reload and successful exchange.
		if err := os.Remove(store.Path); err != nil {
			t.Error(err)
		}
		if err := os.Mkdir(store.Path, 0o700); err != nil {
			t.Error(err)
		}
		json.NewEncoder(w).Encode(tokenResponse{AccessToken: "new-access", RefreshToken: "new-refresh", TokenType: "Bearer", ExpiresIn: 3600})
	}))
	defer server.Close()
	client := NewClient()
	client.TokenURL = server.URL
	source := NewTokenSource(client, store, testSession())
	if _, err := source.Token(context.Background()); err == nil {
		t.Fatal("expected persistence failure")
	}
	if err := os.Remove(store.Path); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Load()
	if err != nil || saved.RefreshToken != "new-refresh" || requests.Load() != 1 {
		t.Fatal("rotated token was lost or refresh retried unnecessarily")
	}
}

func TestIndependentTokenSourcesRefreshOnce(t *testing.T) {
	var requests atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			close(entered)
		}
		<-release
		json.NewEncoder(w).Encode(tokenResponse{AccessToken: "new-access", RefreshToken: "new-refresh", TokenType: "Bearer", ExpiresIn: 3600})
	}))
	defer server.Close()
	store := &Store{Path: filepath.Join(privateAuthDir(t), "oauth.json")}
	session := testSession()
	if err := store.Save(session); err != nil {
		t.Fatal(err)
	}
	client := NewClient()
	client.TokenURL = server.URL
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 2)
	for range 2 {
		// Separate sources and store handles simulate independent CLI processes.
		source := NewTokenSource(client, &Store{Path: store.Path}, session)
		go func() {
			token, err := source.Token(ctx)
			if err == nil && token != "new-access" {
				err = fmt.Errorf("token = %q", token)
			}
			done <- err
		}()
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("refresh did not start")
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("refresh requests = %d, want 1", requests.Load())
	}
	saved, err := store.Load()
	if err != nil || saved.RefreshToken != "new-refresh" {
		t.Fatalf("rotated session was not saved: %v", err)
	}
}

func TestRefreshLockCancellation(t *testing.T) {
	store := &Store{Path: filepath.Join(privateAuthDir(t), "oauth.json")}
	if err := store.Save(testSession()); err != nil {
		t.Fatal(err)
	}
	unlock, err := store.lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = NewTokenSource(NewClient(), store, testSession()).Token(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock cancellation: %v", err)
	}
}
