package cfapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// GatewayRule contains the fields used by meshscale's DNS and network rules.
type GatewayRule struct {
	ID            string              `json:"id,omitempty"`
	Name          string              `json:"name"`
	Description   string              `json:"description"`
	Action        string              `json:"action"`
	Enabled       bool                `json:"enabled"`
	Filters       []string            `json:"filters"`
	Traffic       string              `json:"traffic"`
	Identity      string              `json:"identity"`
	DevicePosture string              `json:"device_posture"`
	Precedence    int64               `json:"precedence"`
	RuleSettings  GatewayRuleSettings `json:"rule_settings"`
	Schedule      json.RawMessage     `json:"schedule"`
	Expiration    json.RawMessage     `json:"expiration"`
	ReadOnly      bool                `json:"read_only,omitempty"`
}

type GatewayRuleSettings struct {
	OverrideIPs  []string `json:"override_ips"`
	OverrideHost string   `json:"override_host"`
}

func (c *Client) ListGatewayRules(ctx context.Context, account string) ([]GatewayRule, error) {
	// The Gateway rules endpoint returns the entire collection, without pagination.
	return list[GatewayRule](ctx, c, accountPath(account, "/gateway/rules"), unpaginated)
}

func (c *Client) CreateGatewayRule(ctx context.Context, account string, rule GatewayRule) (GatewayRule, error) {
	rule.ID, rule.ReadOnly = "", false
	return send[GatewayRule](ctx, c, http.MethodPost, accountPath(account, "/gateway/rules"), rule)
}

func (c *Client) UpdateGatewayRule(ctx context.Context, account, id string, rule GatewayRule) (GatewayRule, error) {
	rule.ID, rule.ReadOnly = "", false
	return send[GatewayRule](ctx, c, http.MethodPut, accountPath(account, "/gateway/rules/"+url.PathEscape(id)), rule)
}

func (c *Client) DeleteGatewayRule(ctx context.Context, account, id string) error {
	_, err := c.request(ctx, http.MethodDelete, accountPath(account, "/gateway/rules/"+url.PathEscape(id)), nil, nil, nil)
	return err
}
