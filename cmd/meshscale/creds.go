package main

import (
	"errors"
	"os"

	"github.com/Whiteknight07/meshscale/internal/auth"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
)

var errNotLoggedIn = errors.New("not logged in: run `meshscale up` or set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID")

// resolveCredentials returns the account ID and token source to use.
// Order: CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID env vars, then the
// dev file (~/.config/meshscale/dev.env), then the saved OAuth login.
func resolveCredentials() (accountID string, ts cfapi.TokenSource, err error) {
	env, err := config.LoadEnv()
	if err != nil {
		return "", nil, err
	}
	tok, acc := env["CLOUDFLARE_API_TOKEN"], env["CLOUDFLARE_ACCOUNT_ID"]
	if tok != "" && acc != "" {
		return acc, cfapi.StaticToken(tok), nil
	}
	store, err := auth.DefaultStore()
	if err != nil {
		return "", nil, err
	}
	session, err := store.Load()
	if errors.Is(err, os.ErrNotExist) {
		return "", nil, errNotLoggedIn
	}
	if err != nil {
		return "", nil, err
	}
	return session.Account.ID, auth.NewTokenSource(auth.NewClient(), store, session), nil
}
