package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

func TestResolveOwnerEmailFallbackOrder(t *testing.T) {
	for _, mode := range []string{"oauth", "user", "owner", "ambiguous"} {
		t.Run(mode, func(t *testing.T) {
			var calls []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.URL.Path)
				switch r.URL.Path {
				case "/userinfo":
					fmt.Fprint(w, `{"email":"oauth@example.com"}`)
				case "/user":
					if mode == "user" {
						fmt.Fprint(w, `{"success":true,"result":{"email":"user@example.com"}}`)
					} else {
						w.WriteHeader(403)
					}
				case "/accounts/account/members":
					if mode == "ambiguous" {
						fmt.Fprint(w, `{"success":true,"result":[]}`)
					} else {
						fmt.Fprint(w, `{"success":true,"result":[{"status":"accepted","user":{"email":"owner@example.com"},"roles":[{"name":"Super Administrator - All Privileges"}]}]}`)
					}
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			identity := NewClient()
			identity.UserInfoURL = server.URL + "/userinfo"
			api := cfapi.New(cfapi.StaticToken("test-token"), "test")
			api.BaseURL, api.HTTPClient = server.URL, server.Client()
			if mode == "oauth" {
				session := testSession()
				session.Expiry = time.Now().Add(time.Hour)
				api.Tokens = &TokenSource{session: *session}
			}
			email, err := identity.ResolveOwnerEmail(t.Context(), api, "account")
			if mode == "ambiguous" {
				if err == nil {
					t.Fatal("accepted ambiguous owner")
				}
				return
			}
			if err != nil || email != mode+"@example.com" {
				t.Fatalf("email=%q error=%v calls=%v", email, err, calls)
			}
			wantCalls := 1
			if mode == "owner" {
				wantCalls = 2
			}
			if len(calls) != wantCalls {
				t.Fatalf("unexpected fallback calls %v", calls)
			}
		})
	}
}

func TestAccountsUseCFAPIPaginationMetadata(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprintf(w, `{"success":true,"result":[{"id":%q}],"result_info":{"total_count":2}}`, r.URL.Query().Get("page"))
	}))
	defer server.Close()
	client := NewClient()
	client.APIURL = server.URL
	accounts, err := client.Accounts(t.Context(), cfapi.StaticToken("test-token"))
	if err != nil || len(accounts) != 2 || calls != 2 {
		t.Fatalf("accounts=%v error=%v calls=%d", accounts, err, calls)
	}
}
