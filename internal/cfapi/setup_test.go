package cfapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMissingResourceDoesNotIncludeAuthorizationOrRouterErrors(t *testing.T) {
	for _, test := range []struct {
		status, code int
		want         bool
	}{
		{404, 1212, true}, {404, 0, true}, {403, 10000, false}, {401, 10000, false}, {404, 7003, false}, {404, 7000, false}, {500, 1212, false},
	} {
		got := IsMissing(&APIError{StatusCode: test.status, Errors: []APIMessage{{Code: test.code}}})
		if got != test.want {
			t.Errorf("status=%d code=%d got=%v", test.status, test.code, got)
		}
	}
	if IsMissing(nil) {
		t.Fatal("nil error treated as absent")
	}
}

func TestSubscriptionsUsesBillingPageLimit(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/accounts/a/subscriptions" || r.URL.Query().Get("per_page") != "50" {
			t.Errorf("bad billing request: %s %s", r.Method, r.URL)
		}
		page := r.URL.Query().Get("page")
		if page != "1" && page != "2" {
			t.Errorf("bad page %s", page)
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{map[string]any{"state": "Paid", "rate_plan": map[string]any{"id": "teams_free"}}}, "result_info": map[string]any{"total_pages": 2}})
	}))
	defer server.Close()
	c := New(StaticToken("test"), "test")
	c.BaseURL = server.URL
	subs, err := c.Subscriptions(context.Background(), "a")
	if err != nil || len(subs) != 2 || calls != 2 {
		t.Fatalf("subscriptions=%v calls=%d err=%v", subs, calls, err)
	}
}
