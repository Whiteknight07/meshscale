package cfapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"unicode"
)

// fuzzClient serves body for the first request and an empty final page after,
// so arbitrary pagination metadata cannot turn one input into 10,000 pages.
func fuzzClient(status int, body []byte) *Client {
	c := New(StaticToken("test-token"), "test")
	calls := 0
	c.HTTPClient = &http.Client{Transport: publicationTransport(func(*http.Request) (*http.Response, error) {
		calls++
		data := body
		if calls > 1 {
			data = []byte(`{"success":true,"result":[]}`)
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(data)))}, nil
	})}
	return c
}

func FuzzResponseDecoding(f *testing.F) {
	for _, seed := range []string{
		`{"success":true,"result":[{"id":"r","device":{"id":"d","name":"laptop"},"user":{"email":"a@b"},"virtual_ipv4":"100.96.0.1"}],"result_info":{"page":1,"per_page":100,"total_count":1}}`,
		`{"success":true,"result":[],"result_info":{"cursor":"x"}}`,
		`{"success":false,"errors":[{"code":1,"message":"bad\u001b[2J\r\nforged: yes","error_chain":[{"message":"test-token"}]}],"messages":["m"]}`,
		`{"success":true,"result":{"id":"account"}}`,
		`{"success":true,"result":null}`,
		`{"success":true,"result":[{"id":1}]}`,
		`<html>502 Bad Gateway</html>`,
		`{"success":true,"result":[`,
		``,
	} {
		f.Add(200, []byte(seed))
		f.Add(403, []byte(seed))
	}
	f.Fuzz(func(t *testing.T, status int, body []byte) {
		// Retryable statuses wait between attempts; retries are covered elsewhere.
		if status < 100 || status > 999 || status == 429 || status >= 500 && status < 600 || status == http.StatusNoContent {
			return
		}
		ctx := context.Background()
		for _, call := range []func(*Client) error{
			func(c *Client) error { _, err := c.ListRegistrations(ctx, "account"); return err },
			func(c *Client) error { _, err := c.Account(ctx, "account"); return err },
			func(c *Client) error { _, err := c.ListGatewayRules(ctx, "account"); return err },
			func(c *Client) error { _, err := c.ListGatewayLists(ctx, "account"); return err },
		} {
			err := call(fuzzClient(status, body))
			if err == nil {
				if status < 200 || status >= 300 {
					t.Fatalf("HTTP %d accepted", status)
				}
				continue
			}
			message := err.Error()
			if strings.Contains(message, "test-token") {
				t.Fatalf("error disclosed the token: %s", message)
			}
			var api *APIError
			if errors.As(err, &api) && strings.ContainsFunc(message, unicode.IsControl) {
				t.Fatalf("API error carries control characters: %q", message)
			}
		}
	})
}

// Cloudflare messages can echo account data such as a rule or device name.
func TestAPIErrorEscapesControlCharacters(t *testing.T) {
	c := fuzzClient(400, []byte(`{"success":false,"errors":[{"code":7,"message":"name \"x\u001b[31m\r\n2026/10/26 ssh decision=accept\u202e\" exists"}]}`))
	_, err := c.Account(t.Context(), "account")
	if err == nil {
		t.Fatal("accepted error response")
	}
	if strings.ContainsAny(err.Error(), "\x1b\r\n\u202e") || !strings.Contains(err.Error(), `\u001b[31m\u000d\u000a2026/10/26`) {
		t.Fatalf("unescaped API message: %q", err.Error())
	}
}

// A page larger than requested is refused, so a list stays bounded by the
// page limit however the server pads each response.
func TestListRefusesOversizedPage(t *testing.T) {
	items := strings.TrimSuffix(strings.Repeat(`{"id":"r"},`, 101), ",")
	page := func(info string) []byte {
		return []byte(`{"success":true,"result":[` + items + `],"result_info":` + info + `}`)
	}
	if _, err := fuzzClient(200, page(`{"cursor":"","per_page":100}`)).ListRegistrations(t.Context(), "account"); err == nil {
		t.Fatal("accepted a cursor page beyond its per_page")
	}
	if _, err := fuzzClient(200, page(`{"page":1,"per_page":100,"total_count":101}`)).ListMeshNodes(t.Context(), "account"); err == nil {
		t.Fatal("accepted a numbered page beyond its per_page")
	}
	// Endpoints that ignore per_page and return everything stay readable.
	if nodes, err := fuzzClient(200, page(`{"page":1,"per_page":101,"total_count":101}`)).ListMeshNodes(t.Context(), "account"); err != nil || len(nodes) != 101 {
		t.Fatalf("ListMeshNodes = %d, %v", len(nodes), err)
	}
}
