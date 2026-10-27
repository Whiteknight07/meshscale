package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

func TestAccountsPaginationAndIdentityFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing bearer token")
		}
		switch r.URL.Path {
		case "/accounts":
			if r.URL.Query().Get("per_page") != "100" {
				t.Error("missing page size")
			}
			fmt.Fprintf(w, `{"success":true,"result":[{"id":"account-%s","name":"Test"}],"result_info":{"total_pages":2}}`, r.URL.Query().Get("page"))
		case "/accounts/account-2":
			fmt.Fprint(w, `{"success":true,"result":{"id":"account-2","name":"Test"}}`)
		case "/userinfo":
			fmt.Fprint(w, `jwt-response`)
		case "/user":
			fmt.Fprint(w, `{"success":true,"result":{"email":"me@example.com"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := NewClient()
	client.APIURL, client.UserInfoURL = server.URL, server.URL+"/userinfo"
	source := cfapi.StaticToken("test-token")
	accounts, err := client.Accounts(context.Background(), source)
	if err != nil || len(accounts) != 2 || accounts[1].ID != "account-2" {
		t.Fatalf("account pagination: %v", err)
	}
	account, err := client.Account(context.Background(), source, "account-2")
	if err != nil || account.ID != "account-2" {
		t.Fatalf("account lookup: %v", err)
	}
	email, err := client.Email(context.Background(), source, true)
	if err != nil || email != "me@example.com" {
		t.Fatalf("email fallback: %v", err)
	}
}

func TestRevokeTokensWithOriginalClientID(t *testing.T) {
	var hints []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("client_id") != "saved-client" || r.Form.Get("token") == "" || r.Form.Has("client_secret") {
			t.Error("incorrect revocation request")
		}
		hints = append(hints, r.Form.Get("token_type_hint"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := NewClient()
	client.RevokeURL = server.URL
	if err := client.Revoke(context.Background(), testSession()); err != nil {
		t.Fatal(err)
	}
	if len(hints) != 2 || hints[0] != "refresh_token" || hints[1] != "access_token" {
		t.Fatal("did not revoke both tokens")
	}
}

func TestEmailUsesOAuthUserInfo(t *testing.T) {
	var userInfoCalls, apiCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer oauth-token" {
			t.Error("missing OAuth bearer token")
		}
		if r.URL.Path == "/userinfo" {
			userInfoCalls++
			fmt.Fprint(w, `{"sub":"user-id","email":"oauth@example.com"}`)
			return
		}
		apiCalls++
		http.Error(w, "unexpected API request", http.StatusForbidden)
	}))
	defer server.Close()
	client := NewClient()
	client.UserInfoURL, client.APIURL = server.URL+"/userinfo", server.URL
	email, err := client.Email(context.Background(), cfapi.StaticToken("oauth-token"), true)
	if err != nil || email != "oauth@example.com" || userInfoCalls != 1 || apiCalls != 0 {
		t.Fatalf("email=%q, error=%v, userinfo=%d, API=%d", email, err, userInfoCalls, apiCalls)
	}
}
