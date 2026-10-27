package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/auth"
)

type identityTransport func(*http.Request) (*http.Response, error)

func (f identityTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWhoamiOAuthEmailAndAccount(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "")
	store, err := auth.DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(&auth.Session{
		ClientID: "client", AccessToken: "oauth-token", Expiry: time.Now().Add(time.Hour),
		Account: auth.Account{ID: "account-id", Name: "Old name"}, Email: "old@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	http.DefaultTransport = identityTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer oauth-token" {
			t.Error("missing OAuth bearer token")
		}
		var body string
		switch r.URL.Path {
		case "/oauth2/userinfo":
			body = `{"email":"current@example.com"}`
		case "/client/v4/accounts/account-id":
			body = `{"success":true,"result":{"id":"account-id","name":"Current account"}}`
		default:
			return nil, fmt.Errorf("unexpected identity request: %s", r.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	originalStdout := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = originalStdout }()
	err = runWhoami(context.Background(), nil)
	writer.Close()
	output, readErr := io.ReadAll(reader)
	if err != nil || readErr != nil {
		t.Fatalf("whoami=%v, read=%v", err, readErr)
	}
	want := "Credentials: OAuth\nUser: current@example.com\nAccount: Current account (account-id)\n"
	if string(output) != want {
		t.Fatalf("output = %q, want %q", output, want)
	}
	// The new flag must use the same authenticated identity lookup and emit only
	// one JSON object; the existing human-readable output above remains unchanged.
	jsonReader, jsonWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer jsonReader.Close()
	os.Stdout = jsonWriter
	jsonErr := runWhoami(context.Background(), []string{"--json"})
	jsonWriter.Close()
	identityOutput, readErr := io.ReadAll(jsonReader)
	if jsonErr != nil || readErr != nil {
		t.Fatalf("JSON whoami=%v, read=%v", jsonErr, readErr)
	}
	var identity map[string]string
	if err := json.Unmarshal(identityOutput, &identity); err != nil {
		t.Fatal(err)
	}
	if identity["id"] != "account-id" || identity["name"] != "Current account" || identity["email"] != "current@example.com" || identity["credentials"] != "OAuth" {
		t.Fatalf("identity=%v", identity)
	}

}

func TestIdentityJSON(t *testing.T) {
	for _, email := range []string{"current@example.com", ""} {
		var out bytes.Buffer
		if err := writeIdentityJSON(&out, "account-id", "Personal account", email, "OAuth"); err != nil {
			t.Fatal(err)
		}
		var got map[string]string
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got["id"] != "account-id" || got["name"] != "Personal account" || got["email"] != email || got["credentials"] != "OAuth" {
			t.Fatalf("unexpected identity: %v", got)
		}
		if len(got) != 3 && email == "" {
			t.Fatal("missing email must be omitted")
		}
	}
}

func TestWhoamiFlagValidation(t *testing.T) {
	if err := runWhoami(context.Background(), []string{"--help"}); err != nil {
		t.Fatal(err)
	}
	if err := runWhoami(context.Background(), []string{"unexpected"}); err == nil {
		t.Fatal("accepted positional argument")
	}
}
