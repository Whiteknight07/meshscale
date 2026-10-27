package cfapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestGatewayLists(t *testing.T) {
	reads, writes := 0, 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			reads++
			if r.URL.Path != "/accounts/acc/gateway/lists" {
				t.Errorf("path=%s", r.URL.Path)
			}
			page := r.URL.Query().Get("page")
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []GatewayList{{ID: page, Name: "list-" + page, Type: "IP"}}, "result_info": map[string]int{"page": reads, "total_pages": 2}})
			return
		}
		writes++
		if r.Method == "POST" && r.URL.Path != "/accounts/acc/gateway/lists" || r.Method == "PUT" && r.URL.Path != "/accounts/acc/gateway/lists/id" {
			t.Errorf("path=%s", r.URL.Path)
		}
		var body GatewayList
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.ID != "" || body.Type != "IP" || len(body.Items) != 1 || body.Items[0].Value != "100.96.0.1" {
			t.Errorf("body=%+v", body)
		}
		body.ID = "id"
		reply(w, body)
	})
	lists, err := c.ListGatewayLists(t.Context(), "acc")
	if err != nil || len(lists) != 2 || reads != 2 {
		t.Fatalf("pagination: %v %v", lists, err)
	}
	l := GatewayList{ID: "not-sent", Name: "list", Type: "IP", Description: "record", Items: []GatewayListItem{{Value: "100.96.0.1"}}}
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"create", func() error { _, err := c.CreateGatewayList(t.Context(), "acc", l); return err }},
		{"update", func() error { _, err := c.UpdateGatewayList(t.Context(), "acc", "id", l); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err != nil {
				t.Fatal(err)
			}
		})
	}
	if writes != 2 {
		t.Fatalf("writes=%d", writes)
	}
}
