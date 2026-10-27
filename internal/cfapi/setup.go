package cfapi

import (
	"context"
	"errors"
	"net/http"
)

// IsMissing distinguishes absent resources from authorization and routing errors.
func IsMissing(err error) bool {
	var api *APIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusNotFound {
		return false
	}
	for _, e := range api.Errors {
		if e.Code == 7000 || e.Code == 7003 {
			return false
		}
	}
	return true
}

// IsAuthorizationError reports a 401 or 403: the credentials can no longer
// read or change the resource, as opposed to a transient outage.
func IsAuthorizationError(err error) bool {
	var api *APIError
	return errors.As(err, &api) && (api.StatusCode == http.StatusUnauthorized || api.StatusCode == http.StatusForbidden)
}

// Cloudflare generates a unique team domain when auth_domain is omitted.
func (c *Client) CreateOrganization(ctx context.Context, account string) (Organization, error) {
	return send[Organization](ctx, c, http.MethodPost, accountPath(account, "/access/organizations"), struct{}{})
}

type GatewayAccount struct {
	ID string `json:"id"`
}

func (c *Client) GatewayAccount(ctx context.Context, account string) (GatewayAccount, error) {
	return get[GatewayAccount](ctx, c, accountPath(account, "/gateway"))
}

func (c *Client) CreateGatewayAccount(ctx context.Context, account string) (GatewayAccount, error) {
	return send[GatewayAccount](ctx, c, http.MethodPost, accountPath(account, "/gateway"), nil)
}

type ConnectivitySettings struct {
	OfframpWARPEnabled bool `json:"offramp_warp_enabled"`
	ICMPProxyEnabled   bool `json:"icmp_proxy_enabled"`
}

func (c *Client) ConnectivitySettings(ctx context.Context, account string) (ConnectivitySettings, error) {
	return get[ConnectivitySettings](ctx, c, accountPath(account, "/zerotrust/connectivity_settings"))
}

func (c *Client) EnableMeshReachability(ctx context.Context, account string) (ConnectivitySettings, error) {
	// Omit ICMP and all unrelated settings; never reset an existing value.
	return send[ConnectivitySettings](ctx, c, http.MethodPatch, accountPath(account, "/zerotrust/connectivity_settings"), struct {
		Enabled bool `json:"offramp_warp_enabled"`
	}{true})
}

type Subscription struct {
	State    string `json:"state"`
	RatePlan struct {
		ID string `json:"id"`
	} `json:"rate_plan"`
	Product struct {
		Name string `json:"name"`
	} `json:"product"`
}

func (c *Client) Subscriptions(ctx context.Context, account string) ([]Subscription, error) {
	// Unlike most account endpoints, billing caps per_page at 50.
	return listPageSize[Subscription](ctx, c, accountPath(account, "/subscriptions"), pages, 50)
}
