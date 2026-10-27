package cfapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

type Zone struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Account struct {
		ID string `json:"id"`
	} `json:"account"`
}

func (c *Client) PublicationZones(ctx context.Context, account string) ([]Zone, error) {
	zones, err := listQuery[Zone](ctx, c, "/zones", pages, 50, url.Values{"account.id": {account}, "status": {"active"}})
	if err != nil {
		return nil, err
	}
	var out []Zone
	for _, z := range zones {
		if z.Account.ID == account && z.Status == "active" {
			out = append(out, z)
		}
	}
	return out, nil
}

type DNSRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment"`
}

func zonePath(zone, suffix string) string { return "/zones/" + url.PathEscape(zone) + suffix }
func (c *Client) PublicationRecords(ctx context.Context, zone string) ([]DNSRecord, error) {
	return list[DNSRecord](ctx, c, zonePath(zone, "/dns_records"), pages)
}
func (c *Client) CreatePublicationRecord(ctx context.Context, zone string, r DNSRecord) (DNSRecord, error) {
	created, err := send[DNSRecord](ctx, c, http.MethodPost, zonePath(zone, "/dns_records"), r)
	if !unknownOutcome(err) || CreationNonce(r.Comment) == "" {
		return created, err
	}
	reconcileCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	records, lookupErr := c.PublicationRecordsByName(reconcileCtx, zone, r.Name)
	if lookupErr != nil {
		return created, errors.Join(err, fmt.Errorf("reconcile DNS create: %w", lookupErr))
	}
	matches := []DNSRecord{}
	for _, candidate := range records {
		if candidate.ID != "" && candidate.Name == r.Name && candidate.Content == r.Content && candidate.Comment == r.Comment && candidate.Type == r.Type && candidate.Proxied == r.Proxied {
			matches = append(matches, candidate)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	return created, err
}
func (c *Client) PublicationRecord(ctx context.Context, zone, id string) (DNSRecord, error) {
	return get[DNSRecord](ctx, c, zonePath(zone, "/dns_records/"+url.PathEscape(id)))
}
func (c *Client) DeletePublicationRecord(ctx context.Context, zone, id string) error {
	_, err := c.request(ctx, http.MethodDelete, zonePath(zone, "/dns_records/"+url.PathEscape(id)), nil, nil, nil)
	return err
}

type PublicTunnel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (c *Client) CreatePublicTunnel(ctx context.Context, account, name string) (PublicTunnel, error) {
	created, err := send[PublicTunnel](ctx, c, http.MethodPost, accountPath(account, "/cfd_tunnel"), struct {
		Name         string `json:"name"`
		ConfigSource string `json:"config_src"`
	}{name, "cloudflare"})
	if !unknownOutcome(err) || CreationNonce(name) == "" {
		return created, err
	}
	reconcileCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	tunnel, lookupErr := c.FindPublicTunnel(reconcileCtx, account, name)
	if lookupErr != nil {
		return PublicTunnel{}, errors.Join(err, fmt.Errorf("reconcile tunnel create: %w", lookupErr))
	}
	if tunnel.ID != "" {
		return tunnel, nil
	}
	return PublicTunnel{}, err
}

func (c *Client) FindPublicTunnel(ctx context.Context, account, name string) (PublicTunnel, error) {
	if CreationNonce(name) == "" {
		return PublicTunnel{}, fmt.Errorf("tunnel creation nonce missing")
	}
	tunnels, err := listQuery[PublicTunnel](ctx, c, accountPath(account, "/cfd_tunnel"), pages, 100, url.Values{"name": {name}, "is_deleted": {"false"}})
	if err != nil {
		return PublicTunnel{}, err
	}
	var match PublicTunnel
	for _, candidate := range tunnels {
		if candidate.ID != "" && candidate.Name == name {
			if match.ID != "" {
				return PublicTunnel{}, fmt.Errorf("ambiguous tunnel creation nonce")
			}
			match = candidate
		}
	}
	return match, nil
}

type TunnelOrigin struct {
	Access           *TunnelAccess `json:"access,omitempty"`
	OriginServerName string        `json:"originServerName,omitempty"`
}
type TunnelAccess struct {
	TeamName string   `json:"teamName"`
	AudTag   []string `json:"audTag"`
	Required bool     `json:"required"`
}

func (c *Client) ConfigurePublicTunnel(ctx context.Context, account, id, host, origin string, options *TunnelOrigin) error {
	ingress := map[string]any{"hostname": host, "service": origin}
	if options != nil {
		ingress["originRequest"] = options
	}
	body := map[string]any{"config": map[string]any{"ingress": []map[string]any{ingress, {"service": "http_status:404"}}}}
	_, err := c.request(ctx, http.MethodPut, accountPath(account, "/cfd_tunnel/"+url.PathEscape(id)+"/configurations"), nil, body, nil)
	return err
}
func (c *Client) PublicTunnelToken(ctx context.Context, account, id string) (string, error) {
	return get[string](ctx, c, accountPath(account, "/cfd_tunnel/"+url.PathEscape(id)+"/token"))
}
func (c *Client) DeletePublicTunnel(ctx context.Context, account, id string) error {
	_, err := c.request(ctx, http.MethodDelete, accountPath(account, "/cfd_tunnel/"+url.PathEscape(id)), nil, nil, nil)
	return err
}

type PublicApplication struct {
	AUD             string             `json:"aud,omitempty"`
	ID              string             `json:"id,omitempty"`
	Name            string             `json:"name"`
	Type            string             `json:"type"`
	Domain          string             `json:"domain"`
	SessionDuration string             `json:"session_duration"`
	Policies        []EnrollmentPolicy `json:"policies"`
}

func (c *Client) CreatePublicApplication(ctx context.Context, account string, app PublicApplication) (PublicApplication, error) {
	created, err := send[PublicApplication](ctx, c, http.MethodPost, accountPath(account, "/access/apps"), app)
	if err == nil && CreationNonce(app.Name) != "" {
		if created.ID == "" {
			return PublicApplication{}, fmt.Errorf("created Access application has no ID")
		}
		verified, verifyErr := c.PublicApplication(ctx, account, created.ID)
		if verifyErr != nil {
			return PublicApplication{}, fmt.Errorf("verify created Access application: %w", verifyErr)
		}
		if verifyErr := VerifyPublicApplication(verified, app); verifyErr != nil {
			return PublicApplication{}, verifyErr
		}
		return verified, nil
	}

	if !unknownOutcome(err) || CreationNonce(app.Name) == "" {
		return created, err
	}
	reconcileCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	candidate, lookupErr := c.FindPublicApplication(reconcileCtx, account, app)
	if lookupErr != nil {
		return PublicApplication{}, errors.Join(err, fmt.Errorf("reconcile Access create: %w", lookupErr))
	}
	if candidate.ID != "" {
		return candidate, nil
	}
	return PublicApplication{}, err
}
func (c *Client) FindPublicApplication(ctx context.Context, account string, app PublicApplication) (PublicApplication, error) {
	if CreationNonce(app.Name) == "" {
		return PublicApplication{}, fmt.Errorf("access creation nonce missing")
	}
	apps, err := list[PublicApplication](ctx, c, accountPath(account, "/access/apps"), pages)
	if err != nil {
		return PublicApplication{}, err
	}
	var match PublicApplication
	for _, candidate := range apps {
		// Only an exact nonce qualifies, even when the predictable domain/name match.
		if candidate.ID == "" || CreationNonce(candidate.Name) != CreationNonce(app.Name) {
			continue
		}
		candidate.Policies, err = c.EnrollmentPolicies(ctx, account, candidate.ID)
		if err != nil {
			return PublicApplication{}, fmt.Errorf("verify reconciled Access policies: %w", err)
		}
		if err := VerifyPublicApplication(candidate, app); err != nil {
			return PublicApplication{}, err
		}
		if match.ID != "" {
			return PublicApplication{}, fmt.Errorf("ambiguous Access creation nonce")
		}
		match = candidate
	}
	return match, nil
}
func (c *Client) PublicApplication(ctx context.Context, account, id string) (PublicApplication, error) {
	app, err := get[PublicApplication](ctx, c, accountPath(account, "/access/apps/"+url.PathEscape(id)))
	if err == nil {
		app.Policies, err = c.EnrollmentPolicies(ctx, account, id)
	}
	return app, err
}
func (c *Client) PublicTunnel(ctx context.Context, account, id string) (PublicTunnel, error) {
	return get[PublicTunnel](ctx, c, accountPath(account, "/cfd_tunnel/"+url.PathEscape(id)))
}
func (c *Client) DeletePublicApplication(ctx context.Context, account, id string) error {
	_, err := c.request(ctx, http.MethodDelete, accountPath(account, "/access/apps/"+url.PathEscape(id)), nil, nil, nil)
	return err
}

// uncertainCreateError preserves the underlying error while recording that the
// request may have reached the server. Pre-send failures are never wrapped.
type uncertainCreateError struct{ error }

func (e *uncertainCreateError) Unwrap() error { return e.error }
func unknownOutcome(err error) bool {
	var api *APIError
	var uncertain *uncertainCreateError
	return errors.As(err, &uncertain) || errors.As(err, &api) && api.StatusCode >= 500 && api.StatusCode < 600
}

// CreationNonce extracts a 128-bit creation marker from a stored name/comment.
func CreationNonce(value string) string {
	_, nonce, ok := strings.Cut(value, " meshscale-create:")
	if !ok && strings.HasPrefix(value, "meshscale-funnel-") {
		nonce = strings.TrimPrefix(value, "meshscale-funnel-")
	}
	if len(nonce) != 32 {
		return ""
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return ""
	}
	return nonce
}

// VerifyPublicApplication fails closed on ownership, type and effective policy.
func VerifyPublicApplication(actual, intended PublicApplication) error {
	fail := func() error {
		return fmt.Errorf("access application ownership, type or owner-only policy mismatch; refusing adoption or deletion")
	}
	if CreationNonce(intended.Name) == "" || actual.Name != intended.Name || actual.Domain != intended.Domain || actual.Type != "self_hosted" || actual.Type != intended.Type {
		return fail()
	}
	if len(actual.Policies) != 1 || len(intended.Policies) != 1 {
		return fail()
	}
	a, b := actual.Policies[0], intended.Policies[0]
	if a.Decision != "allow" || b.Decision != "allow" || len(a.Include) != 1 || len(b.Include) != 1 || len(a.Exclude) != 0 || len(a.Require) != 0 || len(b.Exclude) != 0 || len(b.Require) != 0 {
		return fail()
	}
	if len(a.Include[0]) != 1 || len(b.Include[0]) != 1 {
		return fail()
	}
	var owner, wanted map[string]string
	if json.Unmarshal(a.Include[0]["email"], &owner) != nil || json.Unmarshal(b.Include[0]["email"], &wanted) != nil || len(owner) != 1 || owner["email"] == "" || !reflect.DeepEqual(owner, wanted) {
		return fail()
	}
	return nil
}

func (c *Client) PublicationRecordsByName(ctx context.Context, zone, name string) ([]DNSRecord, error) {
	return listQuery[DNSRecord](ctx, c, zonePath(zone, "/dns_records"), pages, 100, url.Values{"name": {name}})
}
func (c *Client) PublicationRecordCount(ctx context.Context, zone string) (int, error) {
	info, err := c.request(ctx, http.MethodGet, zonePath(zone, "/dns_records"), url.Values{"per_page": {"1"}}, nil, nil)
	if err != nil {
		return 0, err
	}
	if info == nil || info.TotalCount == nil {
		return 0, fmt.Errorf("DNS record count missing from Cloudflare response")
	}
	return *info.TotalCount, nil
}
func (c *Client) UpdatePublicationRecord(ctx context.Context, zone, id string, r DNSRecord) (DNSRecord, error) {
	return send[DNSRecord](ctx, c, http.MethodPut, zonePath(zone, "/dns_records/"+url.PathEscape(id)), r)
}
