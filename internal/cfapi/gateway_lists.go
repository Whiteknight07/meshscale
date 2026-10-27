package cfapi

import (
	"context"
	"net/http"
	"net/url"
)

// GatewayList is an account-owned Zero Trust list. Secure mode uses one small
// list per registration; it is never referenced by a Gateway traffic policy.
type GatewayList struct {
	ID          string            `json:"id,omitempty"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Description string            `json:"description"`
	Items       []GatewayListItem `json:"items,omitempty"`
}
type GatewayListItem struct {
	Value string `json:"value"`
}

func (c *Client) ListGatewayLists(ctx context.Context, account string) ([]GatewayList, error) {
	return list[GatewayList](ctx, c, accountPath(account, "/gateway/lists"), pages)
}
func (c *Client) CreateGatewayList(ctx context.Context, account string, l GatewayList) (GatewayList, error) {
	l.ID = ""
	return send[GatewayList](ctx, c, http.MethodPost, accountPath(account, "/gateway/lists"), l)
}
func (c *Client) UpdateGatewayList(ctx context.Context, account, id string, l GatewayList) (GatewayList, error) {
	l.ID = ""
	return send[GatewayList](ctx, c, http.MethodPut, accountPath(account, "/gateway/lists/"+url.PathEscape(id)), l)
}
