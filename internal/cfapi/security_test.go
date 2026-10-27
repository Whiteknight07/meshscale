package cfapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAPIClientDoesNotFollowRedirects(t *testing.T) {
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/redirected" {
			reply(w, Account{ID: "other"})
			return
		}
		w.Header().Set("Location", "/redirected")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	_, err := c.Account(t.Context(), "account")
	if err == nil || calls != 1 {
		t.Fatalf("followed credential-bearing redirect: calls=%d err=%v", calls, err)
	}
}

func TestAPIClientRedactsTokenFromErrors(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"success":false,"errors":[{"message":"Bearer test-token","error_chain":[{"message":"test-token"}]}],"messages":["test-token"]}`)
	})
	_, err := c.Account(t.Context(), "account")
	var api *APIError
	if !errors.As(err, &api) {
		t.Fatalf("expected APIError: %v", err)
	}
	if strings.Contains(err.Error(), "test-token") || strings.Contains(fmt.Sprint(api.Errors, api.Messages), "test-token") {
		t.Fatal("API error disclosed credentials")
	}
	cause := errors.New("transport rejected Bearer test-token")
	c.HTTPClient = &http.Client{Transport: publicationTransport(func(*http.Request) (*http.Response, error) { return nil, cause })}
	_, err = c.Account(t.Context(), "account")
	if err == nil || strings.Contains(err.Error(), "test-token") || !errors.Is(err, cause) {
		t.Fatalf("unsafe transport error or lost cause: %v", err)
	}
}

func TestAPIClientBoundsAndValidatesResponse(t *testing.T) {
	for _, body := range []string{
		`{"success":true,"result":null}`,
		`{"success":true,"result":{"id":"account"}} trailing`,
		`{"success":true,"result":{"id":"account"}}` + strings.Repeat(" ", 16<<20),
	} {
		c := New(StaticToken("test-token"), "test")
		c.HTTPClient = &http.Client{Transport: publicationTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		if _, err := c.Account(t.Context(), "account"); err == nil {
			t.Fatal("accepted null, trailing, or oversized response")
		}
	}
}

func TestPaginationRejectsIncompleteAndInconsistentInventory(t *testing.T) {
	for _, metadata := range []string{
		`{"page":1,"total_count":2}`, // Empty batch despite outstanding rows.
		`{"page":9,"total_count":0}`, // Invalid page even on terminal response.
		`{"page":1,"total_count":-1}`,
		`{"page":1,"total_pages":2}`,
	} {
		c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"success":true,"result":[],"result_info":%s}`, metadata)
		})
		if _, err := c.ListAccounts(context.Background()); err == nil {
			t.Fatalf("accepted incomplete pagination %s", metadata)
		}
	}
}
