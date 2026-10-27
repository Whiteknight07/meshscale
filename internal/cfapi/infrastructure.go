package cfapi

import (
	"context"
	"net/http"
	"net/url"
)

type SSHCA struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
}

func (c *Client) SSHCA(ctx context.Context, account string) (SSHCA, error) {
	return get[SSHCA](ctx, c, accountPath(account, "/access/gateway_ca"))
}
func (c *Client) CreateSSHCA(ctx context.Context, account string) (SSHCA, error) {
	return send[SSHCA](ctx, c, http.MethodPost, accountPath(account, "/access/gateway_ca"), nil)
}

type TargetIP struct {
	Address          string `json:"ip_addr"`
	VirtualNetworkID string `json:"virtual_network_id,omitempty"`
}
type InfrastructureTarget struct {
	ID       string `json:"id,omitempty"`
	Hostname string `json:"hostname"`
	IP       struct {
		IPv4 *TargetIP `json:"ipv4,omitempty"`
		IPv6 *TargetIP `json:"ipv6,omitempty"`
	} `json:"ip"`
}

func (c *Client) ListInfrastructureTargets(ctx context.Context, account string) ([]InfrastructureTarget, error) {
	return list[InfrastructureTarget](ctx, c, accountPath(account, "/infrastructure/targets"), pages)
}
func (c *Client) PutInfrastructureTarget(ctx context.Context, account string, target InfrastructureTarget) (InfrastructureTarget, error) {
	method, path := http.MethodPost, "/infrastructure/targets"
	if target.ID != "" {
		method = http.MethodPut
		path += "/" + url.PathEscape(target.ID)
	}
	return send[InfrastructureTarget](ctx, c, method, accountPath(account, path), target)
}
func (c *Client) DeleteInfrastructureTarget(ctx context.Context, account, id string) error {
	_, err := c.request(ctx, http.MethodDelete, accountPath(account, "/infrastructure/targets/"+url.PathEscape(id)), nil, nil, nil)
	return err
}

type InfrastructurePolicy struct {
	ID              string           `json:"id,omitempty"`
	Name            string           `json:"name"`
	Decision        string           `json:"decision"`
	Include         []map[string]any `json:"include"`
	Exclude         []map[string]any `json:"exclude,omitempty"`
	Require         []map[string]any `json:"require,omitempty"`
	ConnectionRules struct {
		SSH struct {
			Usernames []string `json:"usernames"`
		} `json:"ssh"`
	} `json:"connection_rules"`
}
type InfrastructureCriterion struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Include  struct {
		TargetAttributes struct {
			Hostname []string `json:"hostname"`
		} `json:"target_attributes"`
	} `json:"include"`
}
type InfrastructureApplication struct {
	ID              string                    `json:"id,omitempty"`
	Name            string                    `json:"name"`
	Type            string                    `json:"type"`
	SessionDuration string                    `json:"session_duration"`
	TargetCriteria  []InfrastructureCriterion `json:"target_criteria"`
	Policies        []InfrastructurePolicy    `json:"policies"`
}

func (c *Client) PutInfrastructureApplication(ctx context.Context, account string, app InfrastructureApplication) (InfrastructureApplication, error) {
	method, path := http.MethodPost, "/access/apps"
	if app.ID != "" {
		method = http.MethodPut
		path += "/" + url.PathEscape(app.ID)
	}
	return send[InfrastructureApplication](ctx, c, method, accountPath(account, path), app)
}
func (c *Client) DeleteInfrastructureApplication(ctx context.Context, account, id string) error {
	_, err := c.request(ctx, http.MethodDelete, accountPath(account, "/access/apps/"+url.PathEscape(id)), nil, nil, nil)
	return err
}

func (c *Client) InfrastructureTarget(ctx context.Context, account, id string) (InfrastructureTarget, error) {
	return get[InfrastructureTarget](ctx, c, accountPath(account, "/infrastructure/targets/"+url.PathEscape(id)))
}
func (c *Client) InfrastructureApplication(ctx context.Context, account, id string) (InfrastructureApplication, error) {
	app, err := get[InfrastructureApplication](ctx, c, accountPath(account, "/access/apps/"+url.PathEscape(id)))
	if err == nil {
		app.Policies, err = list[InfrastructurePolicy](ctx, c, accountPath(account, "/access/apps/"+url.PathEscape(id)+"/policies"), pages)
	}
	return app, err
}
func (c *Client) ListInfrastructureApplications(ctx context.Context, account string) ([]InfrastructureApplication, error) {
	return list[InfrastructureApplication](ctx, c, accountPath(account, "/access/apps"), pages)
}
