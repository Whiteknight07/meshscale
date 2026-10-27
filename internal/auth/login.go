package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Whiteknight07/meshscale/internal/config"
)

type LoginOptions struct {
	Compact   bool // short progress for the integrated up flow
	NoBrowser bool
	Output    io.Writer
	// ReadLine reads one pasted response and must return when ctx is canceled.
	// Nil disables paste input; the loopback callback remains available.
	ReadLine func(context.Context) (string, error)
	// OpenBrowser is optional; nil uses the operating system's URL opener.
	OpenBrowser func(string) error
}

func randomString() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand cannot fail on supported Go platforms.
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (c *Client) authorizationURL(redirect, state, verifier string) (string, error) {
	u, err := url.Parse(c.AuthorizeURL)
	if err != nil {
		return "", err
	}
	challenge := sha256.Sum256([]byte(verifier))
	q := u.Query()
	q.Set("client_id", c.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirect)
	q.Set("scope", scopes)
	q.Set("state", state)
	q.Set("code_challenge_method", "S256")
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Login completes browser consent and the code exchange. The caller selects an
// account before saving the returned session.
func (c *Client) Login(ctx context.Context, opts LoginOptions) (*Session, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	output := opts.Output
	if output == nil {
		output = io.Discard
	}
	redirect, err := url.Parse(c.RedirectURI)
	if err != nil {
		return nil, err
	}
	if redirect.Scheme != "http" || (redirect.Hostname() != "127.0.0.1" && redirect.Hostname() != "localhost") || redirect.Path != "/callback" || redirect.RawQuery != "" || redirect.Fragment != "" || redirect.User != nil {
		return nil, errors.New("OAuth redirect must be an HTTP loopback /callback URL")
	}
	port := redirect.Port()
	if port == "" {
		port = "80"
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		return nil, fmt.Errorf("listen for OAuth callback on port %s: %w (close another meshscale login if running)", port, err)
	}
	defer listener.Close()
	if port == "0" {
		redirect.Host = net.JoinHostPort(redirect.Hostname(), fmt.Sprint(listener.Addr().(*net.TCPAddr).Port))
	}
	state, verifier := randomString(), randomString()
	authorizeURL, err := c.authorizationURL(redirect.String(), state, verifier)
	if err != nil {
		return nil, err
	}
	type result struct {
		code             string
		err              error
		inputUnavailable bool
	}
	results := make(chan result, 2)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodGet {
			http.Error(w, "Expected GET", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		if len(q["state"]) != 1 || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
			http.Error(w, "OAuth state mismatch. Continue with the original sign-in link.", http.StatusBadRequest)
			return
		}
		var outcome result
		switch {
		case q.Get("error") != "":
			outcome.err = errors.New("authorization through Cloudflare was denied or failed")
		case len(q["code"]) != 1 || q.Get("code") == "":
			outcome.err = errors.New("callback from Cloudflare is missing an authorization code")
		default:
			outcome.code = q.Get("code")
		}
		select {
		case results <- outcome:
		default:
			http.Error(w, "Callback already received", http.StatusConflict)
			return
		}
		if outcome.err != nil {
			http.Error(w, "Sign-in failed. Return to the terminal.", http.StatusBadRequest)
			return
		}
		fmt.Fprintln(w, "Authorization received. Return to the meshscale terminal to finish sign-in.")
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	defer func() {
		// A callback can deliver its result before its HTTP response is flushed.
		// Let that handler finish even when login or its context has completed.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
		server.Close()
	}()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case results <- result{err: fmt.Errorf("OAuth callback server: %w", err)}:
			default:
			}
		}
	}()
	fmt.Fprintf(output, "Sign in with Cloudflare:\n%s\n", authorizeURL)
	paste := opts.NoBrowser
	if !opts.NoBrowser {
		open := opts.OpenBrowser
		if open == nil {
			open = openBrowser
		}
		fmt.Fprintln(output, "Opening your browser...")
		if err := open(authorizeURL); err != nil {
			fmt.Fprintln(output, "Could not open a browser.")
			paste = true
		}
	}
	if paste {
		callbackPort := fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)
		if opts.Compact {
			fmt.Fprintf(output, "Paste the callback URL or code here (or forward SSH port %s).\n", callbackPort)
		} else {
			fmt.Fprintf(output, "After approving, your browser will land on a page that fails to load (%s?...). Copy that full address and paste it here.\n", redirect.String())
			fmt.Fprintln(output, "You can also paste just the code value.")
			fmt.Fprintf(output, "Alternatively, forward the callback port from another local terminal:\n  ssh -N -L 127.0.0.1:%s:127.0.0.1:%s <user>@<ssh-host>\n", callbackPort, callbackPort)
			fmt.Fprintln(output, "Waiting for consent (up to 10 minutes)...")
		}
		if opts.ReadLine != nil {
			inputCtx, stopInput := context.WithCancel(ctx)
			done := make(chan struct{})
			defer func() {
				stopInput()
				<-done
			}()
			go func() {
				defer close(done)
				line, err := opts.ReadLine(inputCtx)
				outcome := result{inputUnavailable: true}
				if err == nil || errors.Is(err, io.EOF) && strings.TrimSpace(line) != "" {
					outcome.code, outcome.err = parsePastedCode(line, redirect.String(), state)
					outcome.inputUnavailable = false
				}
				select {
				case results <- outcome:
				case <-inputCtx.Done():
				}
			}()
		} else {
			fmt.Fprintln(output, "Paste input unavailable; waiting for the browser callback.")
		}
	}
	var outcome result
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for Cloudflare authorization: %w", ctx.Err())
		case outcome = <-results:
			// EOF (including redirected /dev/null) leaves the listener active.
			if outcome.inputUnavailable {
				fmt.Fprintln(output, "Paste input unavailable; waiting for the browser callback.")
				continue
			}
		}
		break
	}

	if outcome.err != nil {
		return nil, outcome.err
	}
	token, err := c.tokenRequest(ctx, url.Values{
		"grant_type": {"authorization_code"}, "code": {outcome.code},
		"redirect_uri": {redirect.String()}, "code_verifier": {verifier},
	})
	if err != nil {
		return nil, err
	}
	if token.RefreshToken == "" {
		return nil, errors.New("no refresh token returned by Cloudflare; authorize offline_access and retry login")
	}
	return &Session{
		ClientID: c.ClientID, AccessToken: token.AccessToken, RefreshToken: token.RefreshToken,
		TokenType: token.TokenType, Expiry: time.Now().Add(time.Duration(token.ExpiresIn) * time.Second), Scope: token.Scope,
	}, nil
}

func parsePastedCode(input, redirect, state string) (string, error) {
	input = strings.TrimSpace(input)
	fail := func(message string) (string, error) {
		return "", fmt.Errorf("invalid pasted OAuth response: %s", message)
	}
	if strings.Contains(input, "://") {
		u, err := url.Parse(input)
		if err != nil {
			return fail("expected the full callback URL or authorization code")
		}
		expected, err := url.Parse(redirect)
		if err != nil || u.Scheme != expected.Scheme || u.Host != expected.Host || u.Path != expected.Path || u.User != nil || u.Fragment != "" {
			return fail("URL does not match the loopback callback")
		}
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return fail("invalid callback query")
		}
		if len(q["state"]) != 1 || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
			return fail("OAuth state mismatch; run `meshscale login` again")
		}
		if q.Get("error") != "" {
			return fail("authorization through Cloudflare was denied or failed")
		}
		if len(q["code"]) != 1 || !validCode(q.Get("code")) {
			return fail("callback is missing a valid authorization code")
		}
		return q.Get("code"), nil
	}
	if !validCode(input) {
		return fail("expected the full callback URL or authorization code")
	}
	// A bare code has no state to validate; the PKCE verifier still binds the
	// exchange to this login, so a code issued to another login cannot be used.
	return input, nil
}

func validCode(code string) bool {
	if code == "" || len(code) > 8192 {
		return false
	}
	for _, r := range code {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~+/=", r)) {
			return false
		}
	}
	return true
}

func openBrowser(rawURL string) error {
	var command string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		command, args = "open", []string{rawURL}
	case "windows":
		command, args = "rundll32", []string{"url.dll,FileProtocolHandler", rawURL}
	default:
		command, args = "xdg-open", []string{rawURL}
	}
	// No shell: URL metacharacters are passed as a single argument.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = config.ChildEnvironment()
	return cmd.Run()
}
