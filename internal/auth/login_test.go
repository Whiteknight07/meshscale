package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoginPKCEAndState(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprint("mismatch=", mismatch), func(t *testing.T) {
			var exchangeCount atomic.Int32
			var expectedChallenge, expectedRedirect string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/authorize":
					q := r.URL.Query()
					if q.Get("client_id") != "test-client" || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
						t.Error("missing public-client PKCE parameters")
					}
					if len(q.Get("state")) < 43 || len(q.Get("code_challenge")) != 43 {
						t.Error("state or challenge too short")
					}
					if !strings.Contains(q.Get("scope"), "offline_access") || !strings.Contains(q.Get("scope"), "teams.write") || !strings.Contains(q.Get("scope"), "access.write") || !strings.Contains(q.Get("scope"), "access-ssh-auditing.write") {
						t.Error("missing scopes")
					}
					expectedChallenge, expectedRedirect = q.Get("code_challenge"), q.Get("redirect_uri")
					state := q.Get("state")
					if mismatch {
						for _, invalid := range []string{"wrong-state", "", "missing-state"} {
							query := url.Values{"state": {invalid}, "code": {"test-code"}}
							if invalid == "missing-state" {
								query.Del("state")
							}
							response, err := http.Get(expectedRedirect + "?" + query.Encode())
							if err != nil {
								t.Error(err)
								return
							}
							response.Body.Close()
							if response.StatusCode != http.StatusBadRequest {
								t.Errorf("wrong state status = %d", response.StatusCode)
							}
						}
					}
					http.Redirect(w, r, expectedRedirect+"?"+url.Values{"state": {state}, "code": {"test-code"}}.Encode(), http.StatusFound)
				case "/token":
					exchangeCount.Add(1)
					if err := r.ParseForm(); err != nil {
						t.Error(err)
					}
					verifier := r.Form.Get("code_verifier")
					challenge := sha256.Sum256([]byte(verifier))
					if len(verifier) < 43 || base64.RawURLEncoding.EncodeToString(challenge[:]) != expectedChallenge {
						t.Error("token verifier does not match the authorization challenge")
					}
					if r.Form.Get("client_id") != "test-client" || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "test-code" || r.Form.Get("redirect_uri") != expectedRedirect {
						t.Error("incorrect authorization code exchange")
					}
					if r.Form.Has("client_secret") || r.Header.Get("Authorization") != "" {
						t.Error("public client attempted secret authentication")
					}
					json.NewEncoder(w).Encode(tokenResponse{AccessToken: "access", RefreshToken: "refresh", TokenType: "Bearer", ExpiresIn: 3600})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client := NewClient()
			client.ClientID, client.AuthorizeURL, client.TokenURL = "test-client", server.URL+"/authorize", server.URL+"/token"
			client.RedirectURI = "http://127.0.0.1:0/callback"
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			session, err := client.Login(ctx, LoginOptions{OpenBrowser: func(rawURL string) error {
				resp, err := server.Client().Get(rawURL)
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				io.Copy(io.Discard, resp.Body)
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			if session.AccessToken != "access" || session.RefreshToken != "refresh" || session.ClientID != "test-client" || time.Until(session.Expiry) < 59*time.Minute || exchangeCount.Load() != 1 {
				t.Fatal("incorrect login session")
			}
		})
	}
}

type urlCapture struct {
	bytes.Buffer
	urls chan string
}

func (w *urlCapture) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	for _, field := range strings.Fields(string(p)) {
		if strings.HasPrefix(field, "https://") {
			w.urls <- field
		}
	}
	return n, err
}

func TestNoBrowserPrintsURLAndCancels(t *testing.T) {
	client := NewClient()
	client.RedirectURI = "http://127.0.0.1:0/callback"
	output := &urlCapture{urls: make(chan string, 1)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.Login(ctx, LoginOptions{NoBrowser: true, Output: output, OpenBrowser: func(string) error {
			t.Error("browser opened in no-browser mode")
			return nil
		}})
		done <- err
	}()
	select {
	case rawURL := <-output.urls:
		u, err := url.Parse(rawURL)
		if err != nil || u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("state") == "" {
			t.Fatal("printed URL is missing PKCE or state")
		}
		cancel()
	case <-ctx.Done():
		t.Fatal("login did not print the URL")
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if !strings.Contains(output.String(), "ssh -N -L") {
		t.Fatal("missing SSH instructions")
	}
}

func TestClientIDOverride(t *testing.T) {
	t.Setenv("MESHSCALE_OAUTH_CLIENT_ID", "custom-client")
	if NewClient().ClientID != "custom-client" {
		t.Fatal("client ID override ignored")
	}
}

func TestParsePastedCode(t *testing.T) {
	for _, test := range []struct {
		name, input, want string
		wantErr           bool
	}{
		{name: "full URL", input: RedirectURI + "?code=code-123&state=expected", want: "code-123"},
		{name: "bare code", input: "  code-123\n", want: "code-123"},
		{name: "padded code", input: "code+123/==", want: "code+123/=="},
		{name: "wrong state", input: RedirectURI + "?code=code-123&state=wrong", wantErr: true},
		{name: "missing state", input: RedirectURI + "?code=code-123", wantErr: true},
		{name: "duplicate state", input: RedirectURI + "?code=code-123&state=expected&state=expected", wantErr: true},
		{name: "duplicate code", input: RedirectURI + "?code=one&code=two&state=expected", wantErr: true},
		{name: "other URL", input: "https://example.com/callback?code=code-123&state=expected", wantErr: true},
		{name: "wrong port", input: "http://127.0.0.1:9999/callback?code=code-123&state=expected", wantErr: true},
		{name: "denied", input: RedirectURI + "?error=access_denied&state=expected", wantErr: true},
		{name: "garbage", input: "this is not a callback", wantErr: true},
		{name: "query only", input: "code=code-123&state=expected", wantErr: true},
		{name: "empty", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parsePastedCode(test.input, RedirectURI, "expected")
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("code=%q, error=%v", got, err)
			}
		})
	}
}

func TestLoginPastedResponse(t *testing.T) {
	for _, fullURL := range []bool{false, true} {
		t.Run(fmt.Sprint("fullURL=", fullURL), func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				r.ParseForm()
				if r.Form.Get("code") != "pasted-code" || r.Form.Get("code_verifier") == "" {
					t.Error("missing pasted code or PKCE verifier")
				}
				json.NewEncoder(w).Encode(tokenResponse{AccessToken: "access", RefreshToken: "refresh", TokenType: "Bearer", ExpiresIn: 3600})
			}))
			defer server.Close()
			client := NewClient()
			client.TokenURL, client.RedirectURI = server.URL, "http://127.0.0.1:0/callback"
			output := &urlCapture{urls: make(chan string, 1)}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			session, err := client.Login(ctx, LoginOptions{
				NoBrowser: fullURL, Output: output,
				OpenBrowser: func(string) error { return fmt.Errorf("no desktop") },
				ReadLine: func(ctx context.Context) (string, error) {
					select {
					case rawURL := <-output.urls:
						u, err := url.Parse(rawURL)
						if err != nil {
							return "", err
						}
						if fullURL {
							return u.Query().Get("redirect_uri") + "?" + url.Values{"code": {"pasted-code"}, "state": {u.Query().Get("state")}}.Encode(), io.EOF
						}
						return "pasted-code\n", nil
					case <-ctx.Done():
						return "", ctx.Err()
					}
				},
			})
			if err != nil || session.AccessToken != "access" || requests.Load() != 1 {
				t.Fatalf("pasted login: session=%v, error=%v, requests=%d", session != nil, err, requests.Load())
			}
			if !strings.Contains(output.String(), "Copy that full address and paste it here.") || !strings.Contains(output.String(), "ssh -N -L") {
				t.Fatal("missing paste instructions or tunnel hint")
			}
		})
	}
}

func TestLoginListenerAndStdinRace(t *testing.T) {
	for _, mode := range []string{"listener first", "paste first", "simultaneous", "stdin EOF"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				r.ParseForm()
				code := r.Form.Get("code")
				if mode == "listener first" || mode == "stdin EOF" {
					if code != "listener-code" {
						t.Errorf("listener lost: code=%q", code)
					}
				} else if mode == "paste first" && code != "pasted-code" {
					t.Errorf("paste lost: code=%q", code)
				}
				json.NewEncoder(w).Encode(tokenResponse{AccessToken: "access", RefreshToken: "refresh", TokenType: "Bearer", ExpiresIn: 3600})
			}))
			defer server.Close()
			client := NewClient()
			client.TokenURL, client.RedirectURI = server.URL, "http://127.0.0.1:0/callback"
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var callback string
			release := make(chan struct{})
			callbackDone := make(chan struct{})
			getCallback := func() {
				defer close(callbackDone)
				resp, err := http.Get(callback)
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				} else if mode == "listener first" || mode == "stdin EOF" {
					t.Errorf("callback failed: %v", err)
				}
			}
			session, err := client.Login(ctx, LoginOptions{
				OpenBrowser: func(rawURL string) error {
					u, _ := url.Parse(rawURL)
					callback = u.Query().Get("redirect_uri") + "?" + url.Values{"state": {u.Query().Get("state")}, "code": {"listener-code"}}.Encode()
					if mode == "listener first" {
						getCallback()
					} else if mode != "paste first" {
						go func() {
							<-release
							getCallback()
						}()
					}
					return fmt.Errorf("browser unavailable")
				},
				ReadLine: func(ctx context.Context) (string, error) {
					switch mode {
					case "listener first", "paste first":
						return "pasted-code", nil
					case "simultaneous":
						close(release)
						return "pasted-code", nil
					default:
						close(release)
						return "", io.EOF
					}
				},
			})
			if mode != "paste first" {
				<-callbackDone
			}
			if err != nil || session.AccessToken != "access" || requests.Load() != 1 {
				t.Fatalf("race: session=%v, error=%v, requests=%d", session != nil, err, requests.Load())
			}
		})
	}
}

func TestLoginListenerCancelsStdin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(tokenResponse{AccessToken: "access", RefreshToken: "refresh", TokenType: "Bearer", ExpiresIn: 3600})
	}))
	defer server.Close()
	client := NewClient()
	client.TokenURL, client.RedirectURI = server.URL, "http://127.0.0.1:0/callback"
	output := &urlCapture{urls: make(chan string, 1)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	inputStarted, inputStopped := make(chan struct{}), make(chan struct{})
	callbackDone := make(chan error, 1)
	go func() {
		select {
		case rawURL := <-output.urls:
			u, _ := url.Parse(rawURL)
			<-inputStarted
			callback := u.Query().Get("redirect_uri") + "?" + url.Values{"state": {u.Query().Get("state")}, "code": {"callback-code"}}.Encode()
			resp, err := http.Get(callback)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			callbackDone <- err
		case <-ctx.Done():
			callbackDone <- ctx.Err()
		}
	}()
	_, err := client.Login(ctx, LoginOptions{
		NoBrowser: true, Output: output,
		ReadLine: func(ctx context.Context) (string, error) {
			close(inputStarted)
			defer close(inputStopped)
			<-ctx.Done()
			return "", ctx.Err()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-callbackDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-inputStopped:
	default:
		t.Fatal("stdin reader was not canceled before Login returned")
	}
}
