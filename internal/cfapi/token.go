// Package cfapi is a small client for the parts of the Cloudflare API that
// meshscale uses (Zero Trust devices, Mesh nodes, routes, Access).
package cfapi

import "context"

// TokenSource supplies a bearer token for each request. API tokens are
// static; OAuth tokens refresh themselves.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken is a TokenSource for a fixed API token.
type StaticToken string

func (t StaticToken) Token(context.Context) (string, error) { return string(t), nil }
