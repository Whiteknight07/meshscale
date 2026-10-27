package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

type Account = cfapi.Account

func (c *Client) api(source cfapi.TokenSource) *cfapi.Client {
	api := cfapi.New(source, "auth")
	api.BaseURL, api.HTTPClient = c.APIURL, c.HTTPClient
	return api
}
func (c *Client) Accounts(ctx context.Context, source cfapi.TokenSource) ([]Account, error) {
	return c.api(source).ListAccounts(ctx)
}
func (c *Client) Account(ctx context.Context, source cfapi.TokenSource, id string) (*Account, error) {
	account, err := c.api(source).Account(ctx, id)
	if err != nil {
		return nil, err
	}
	if account.ID == "" {
		return nil, errors.New("could not read the selected Cloudflare account")
	}
	return &account, nil
}

// userInfo is OAuth's bare JSON endpoint, rather than a Cloudflare API envelope.
func (c *Client) userInfo(ctx context.Context, source cfapi.TokenSource) (string, error) {
	token, err := source.Token(ctx)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.UserInfoURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OAuth userinfo failed (HTTP %d)", resp.StatusCode)
	}
	var info struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&info); err != nil {
		return "", errors.New("invalid OAuth userinfo response")
	}
	return info.Email, nil
}

// Email falls back to the API when userinfo has no email (or returns a JWT).
func (c *Client) Email(ctx context.Context, source cfapi.TokenSource, oauth bool) (string, error) {
	if oauth {
		if email, err := c.userInfo(ctx, source); err == nil && email != "" {
			return email, nil
		}
	}
	user, err := c.api(source).User(ctx)
	if err != nil {
		return "", err
	}
	if user.Email == "" {
		return "", errors.New("no user email returned by Cloudflare")
	}
	return user.Email, nil
}

// ResolveOwnerEmail uses OAuth identity when available. Only account-scoped
// tokens may fall back to a sole, accepted account owner.
func (c *Client) ResolveOwnerEmail(ctx context.Context, api *cfapi.Client, account string) (string, error) {
	_, oauth := api.Tokens.(*TokenSource)
	identity := *c
	identity.APIURL, identity.HTTPClient = api.BaseURL, api.HTTPClient
	email, err := identity.Email(ctx, api.Tokens, oauth)
	if err != nil && !oauth {
		return api.SoleAccountOwnerEmail(ctx, account)
	}
	return email, err
}
func ResolveOwnerEmail(ctx context.Context, api *cfapi.Client, account string) (string, error) {
	return NewClient().ResolveOwnerEmail(ctx, api, account)
}
