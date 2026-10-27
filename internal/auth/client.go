package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// DefaultClientID is the secretless "meshscale" Sign in with Cloudflare client,
// verified for https://meshscale.stavan.ai. MESHSCALE_OAUTH_CLIENT_ID overrides
// it for self-registered clients.
const DefaultClientID = "729d292b876c17b76bdb960f02410abd"

const RedirectURI = "http://127.0.0.1:8976/callback"

const scopes = "teams.write teams-connector-warp.write teams-connectors.write teams-networks.write access-acct.write access.write access-ssh-auditing.write access-service-token.write account-settings.read user-details.read offline_access"

type Client struct {
	ClientID     string
	AuthorizeURL string
	TokenURL     string
	RevokeURL    string
	UserInfoURL  string
	APIURL       string
	RedirectURI  string
	HTTPClient   *http.Client
}

func NewClient() *Client {
	id := os.Getenv("MESHSCALE_OAUTH_CLIENT_ID")
	if id == "" {
		id = DefaultClientID
	}
	return &Client{
		ClientID: id, AuthorizeURL: "https://dash.cloudflare.com/oauth2/auth",
		TokenURL:    "https://dash.cloudflare.com/oauth2/token",
		RevokeURL:   "https://dash.cloudflare.com/oauth2/revoke",
		UserInfoURL: "https://dash.cloudflare.com/oauth2/userinfo",
		APIURL:      "https://api.cloudflare.com/client/v4", RedirectURI: RedirectURI,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

func (c *Client) tokenRequest(ctx context.Context, values url.Values) (*tokenResponse, error) {
	values.Set("client_id", c.ClientID)
	resp, err := c.postForm(ctx, c.TokenURL, values)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Error bodies may contain credentials; report only the status.
		return nil, fmt.Errorf("OAuth token request failed (HTTP %d); run `meshscale login` again", resp.StatusCode)
	}
	var token tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&token); err != nil {
		return nil, errors.New("invalid OAuth token response")
	}
	if token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") || token.ExpiresIn <= 0 || token.ExpiresIn > 315360000 {
		return nil, errors.New("OAuth token response is missing a bearer token or valid expiry")
	}
	return &token, nil
}

func (c *Client) postForm(ctx context.Context, endpoint string, values url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return c.do(req)
}

// OAuth credentials are bound to these endpoints. In particular, 307/308
// redirects must never replay a refresh token or authorization code elsewhere.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	client := *c.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		// Transport and redirect errors can embed an attacker-controlled URL.
		// Preserve cancellation without disclosing any response-provided text.
		if req.Context().Err() != nil {
			return nil, req.Context().Err()
		}
		return nil, errors.New("OAuth HTTP request failed (details withheld)")
	}
	return resp, nil
}

// Revoke invalidates both tokens before the saved login is removed.
func (c *Client) Revoke(ctx context.Context, session *Session) error {
	client := *c
	client.ClientID = session.ClientID
	for _, token := range []struct{ value, hint string }{
		{session.RefreshToken, "refresh_token"}, {session.AccessToken, "access_token"},
	} {
		if token.value == "" {
			continue
		}
		resp, err := client.postForm(ctx, client.RevokeURL, url.Values{
			"client_id": {client.ClientID}, "token": {token.value}, "token_type_hint": {token.hint},
		})
		if err != nil {
			return fmt.Errorf("revoke OAuth login: %w", err)
		}
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("OAuth revocation failed (HTTP %d); login retained so logout can be retried", resp.StatusCode)
		}
	}
	return nil
}
