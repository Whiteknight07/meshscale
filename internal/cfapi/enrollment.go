package cfapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// AccessRule retains unknown selectors so enrollment checks fail closed.
type AccessRule map[string]json.RawMessage
type EnrollmentPolicy struct {
	ID         string       `json:"id,omitempty"`
	Name       string       `json:"name"`
	Decision   string       `json:"decision"`
	Precedence int          `json:"precedence"`
	Include    []AccessRule `json:"include"`
	Exclude    []AccessRule `json:"exclude"`
	Require    []AccessRule `json:"require"`
}
type EnrollmentApp struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Type        string             `json:"type"`
	AllowedIDPs []string           `json:"allowed_idps"`
	Policies    []EnrollmentPolicy `json:"policies"`
}
type EnrollmentIDP struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

func (c *Client) CreatePINProvider(ctx context.Context, account string) (EnrollmentIDP, error) {
	return send[EnrollmentIDP](ctx, c, http.MethodPost, accountPath(account, "/access/identity_providers"), struct {
		Name   string   `json:"name"`
		Type   string   `json:"type"`
		Config struct{} `json:"config"`
	}{Name: "meshscale email code", Type: "onetimepin"})
}

// Create the enrollment app with its owner-only policy in the same request.
func (c *Client) CreateEnrollmentApp(ctx context.Context, account string, idps []string, policy EnrollmentPolicy) (EnrollmentApp, error) {
	return send[EnrollmentApp](ctx, c, http.MethodPost, accountPath(account, "/access/apps"), struct {
		Type        string             `json:"type"`
		AllowedIDPs []string           `json:"allowed_idps"`
		Policies    []EnrollmentPolicy `json:"policies"`
	}{"warp", idps, []EnrollmentPolicy{policy}})
}

func (c *Client) ListEnrollmentApps(ctx context.Context, account string) ([]EnrollmentApp, error) {
	return list[EnrollmentApp](ctx, c, accountPath(account, "/access/apps"), pages)
}
func (c *Client) ListEnrollmentIDPs(ctx context.Context, account string) ([]EnrollmentIDP, error) {
	return list[EnrollmentIDP](ctx, c, accountPath(account, "/access/identity_providers"), pages)
}
func (c *Client) EnrollmentPolicies(ctx context.Context, account, app string) ([]EnrollmentPolicy, error) {
	return list[EnrollmentPolicy](ctx, c, accountPath(account, "/access/apps/"+url.PathEscape(app)+"/policies"), pages)
}
func (c *Client) CreateEnrollmentPolicy(ctx context.Context, account, app string, policy EnrollmentPolicy) (EnrollmentPolicy, error) {
	return send[EnrollmentPolicy](ctx, c, http.MethodPost, accountPath(account, "/access/apps/"+url.PathEscape(app)+"/policies"), policy)
}
func (c *Client) DeviceProfile(ctx context.Context, account, id string) (DeviceProfile, error) {
	return get[DeviceProfile](ctx, c, accountPath(account, "/devices/policy/"+url.PathEscape(id)))
}

// SoleAccountOwnerEmail is a fallback for account-scoped tokens that cannot
// read /user. Multiple members or an unaccepted/non-owner membership fail closed.
func (c *Client) SoleAccountOwnerEmail(ctx context.Context, account string) (string, error) {
	type member struct {
		Status string `json:"status"`
		User   User   `json:"user"`
		Roles  []struct {
			Name string `json:"name"`
		} `json:"roles"`
	}
	members, err := list[member](ctx, c, accountPath(account, "/members"), pages)
	if err != nil {
		return "", err
	}
	if len(members) == 1 && members[0].Status == "accepted" && members[0].User.Email != "" {
		for _, role := range members[0].Roles {
			if role.Name == "Super Administrator - All Privileges" {
				return members[0].User.Email, nil
			}
		}
	}
	return "", fmt.Errorf("cannot identify a sole account owner; sign in with OAuth or grant User Details Read")
}
