package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/auth"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
)

func TestResolveCredentialsPrecedence(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "")
	if _, _, err := resolveCredentials(); err == nil {
		t.Fatal("expected not-logged-in error")
	}
	store, err := auth.DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	session := &auth.Session{ClientID: "client", AccessToken: "oauth-token", RefreshToken: "refresh", Expiry: time.Now().Add(time.Hour), Account: auth.Account{ID: "oauth-account"}}
	if err := store.Save(session); err != nil {
		t.Fatal(err)
	}
	account, source, err := resolveCredentials()
	if err != nil || account != "oauth-account" {
		t.Fatalf("OAuth fallback: %v", err)
	}
	if _, ok := source.(*auth.TokenSource); !ok {
		t.Fatal("OAuth login did not return an OAuth source")
	}
	if token, err := source.Token(context.Background()); err != nil || token != "oauth-token" {
		t.Fatalf("stored OAuth token: %v", err)
	}
	dir, _ := config.Dir()
	if err := os.WriteFile(filepath.Join(dir, "dev.env"), []byte("CLOUDFLARE_API_TOKEN=dev-token\nCLOUDFLARE_ACCOUNT_ID=dev-account\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	account, source, err = resolveCredentials()
	if err != nil || account != "dev-account" || source != cfapi.StaticToken("dev-token") {
		t.Fatal("dev.env should override stored OAuth")
	}
	t.Setenv("CLOUDFLARE_API_TOKEN", "env-token")
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "env-account")
	account, source, err = resolveCredentials()
	if err != nil || account != "env-account" || source != cfapi.StaticToken("env-token") {
		t.Fatal("environment should override dev.env")
	}
}
