package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

func TestOAuthNeverFollowsCredentialRedirects(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var leaked atomic.Int32
			capture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				leaked.Add(1)
				fmt.Fprint(w, `{"access_token":"stolen","token_type":"Bearer","expires_in":3600,"email":"attacker@example.com"}`)
			}))
			defer capture.Close()
			redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, capture.URL, status)
			}))
			defer redirect.Close()
			client := NewClient()
			client.TokenURL, client.RevokeURL, client.UserInfoURL = redirect.URL, redirect.URL, redirect.URL
			if _, err := client.tokenRequest(t.Context(), url.Values{"refresh_token": {"secret-refresh"}}); err == nil {
				t.Fatal("accepted redirected token response")
			}
			if err := client.Revoke(t.Context(), testSession()); err == nil {
				t.Fatal("accepted redirected revocation")
			}
			if _, err := client.userInfo(t.Context(), cfapi.StaticToken("secret-access")); err == nil {
				t.Fatal("accepted redirected identity")
			}
			if leaked.Load() != 0 {
				t.Fatal("followed an OAuth redirect")
			}
		})
	}
}

func TestOAuthTransportErrorsWithholdResponseURLs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An invalid escape makes net/http include Location in its error.
		w.Header().Set("Location", "https://attacker.invalid/secret-sentinel%zz")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := NewClient()
	client.TokenURL = server.URL
	_, err := client.tokenRequest(t.Context(), url.Values{"refresh_token": {"secret-refresh"}})
	if err == nil || strings.Contains(err.Error(), "secret-sentinel") {
		t.Fatalf("unsafe OAuth error: %v", err)
	}
}

func TestLogoutSerializesWithRefreshAndRevokesRotatedTokens(t *testing.T) {
	store := &Store{Path: filepath.Join(privateAuthDir(t), "oauth.json")}
	session := testSession()
	if err := store.Save(session); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var revoked []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.URL.Path == "/refresh" {
			close(entered)
			<-release
			fmt.Fprint(w, `{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600}`)
		} else {
			revoked = append(revoked, r.Form.Get("token"))
		}
	}))
	defer server.Close()
	client := NewClient()
	client.TokenURL, client.RevokeURL = server.URL+"/refresh", server.URL+"/revoke"
	done := make(chan error, 1)
	go func() { _, err := NewTokenSource(client, store, session).Token(t.Context()); done <- err }()
	<-entered
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	err := store.Logout(ctx, client)
	close(release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("logout bypassed refresh lock: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := store.Logout(t.Context(), client); err != nil {
		t.Fatal(err)
	}
	if strings.Join(revoked, ",") != "new-refresh,new-access" {
		t.Fatal("logout did not revoke both rotated tokens")
	}
	if _, err := store.Load(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("logout left a saved login: %v", err)
	}
	if _, err := NewTokenSource(client, store, session).Token(t.Context()); err == nil {
		t.Fatal("stale token source resurrected a deleted login")
	}
}

func TestBrowserOpenerDoesNotInheritAPICredentials(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux browser opener fixture")
	}
	dir := t.TempDir()
	// Simulate a desktop opener without opening a browser or accessing a URL.
	script := "#!/bin/sh\n[ -z \"${CLOUDFLARE_API_TOKEN-}${CLOUDFLARE_API_KEY-}${CF_API_TOKEN-}${CF_API_KEY-}\" ]\n"
	if err := os.WriteFile(filepath.Join(dir, "xdg-open"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	for _, name := range []string{"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY", "CF_API_TOKEN", "CF_API_KEY"} {
		t.Setenv(name, "not-for-the-browser")
	}
	if err := openBrowser("https://example.invalid/"); err != nil {
		t.Fatal("browser opener inherited an API credential")
	}
}

func TestNewLoginWaitsForRefreshLock(t *testing.T) {
	store := &Store{Path: filepath.Join(privateAuthDir(t), "oauth.json")}
	if err := store.Save(testSession()); err != nil {
		t.Fatal(err)
	}
	release, err := store.lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	next := testSession()
	next.AccessToken = "replacement"
	if err := store.SaveLogin(ctx, next); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("new login bypassed lock: %v", err)
	}
	saved, err := store.Load()
	if err != nil || saved.AccessToken != testSession().AccessToken {
		t.Fatal("blocked login overwrote the active session")
	}
}
