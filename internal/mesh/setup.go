// Package mesh prepares an account for Linux Mesh nodes.
package mesh

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

const ProfileName = "meshscale nodes"

var ErrPlanRequired = errors.New("a Zero Trust plan is required")

type Report struct {
	Changed      []string
	AlreadyReady []string
	Manual       []string
	ProfileID    string
}

// EnsureAccountReady enables only the required flags and creates a narrowly
// scoped profile. It never edits an existing profile or enrollment policy.
func EnsureAccountReady(ctx context.Context, client *cfapi.Client, accountID string) (Report, error) {
	r := Report{}
	org, err := ensureOrganization(ctx, client, accountID, &r)
	if err != nil {
		return r, err
	}
	return ensureMesh(ctx, client, accountID, org, r)
}

func ensureOrganization(ctx context.Context, c *cfapi.Client, account string, r *Report) (cfapi.Organization, error) {
	org, err := c.Organization(ctx, account)
	if cfapi.IsMissing(err) || err == nil && org.AuthDomain == "" {
		org, err = c.CreateOrganization(ctx, account)
		if err == nil {
			r.Changed = append(r.Changed, "created Zero Trust organization "+org.AuthDomain)
		}
	} else if err == nil {
		r.AlreadyReady = append(r.AlreadyReady, "Zero Trust organization "+org.AuthDomain)
	}
	if err != nil {
		return org, fmt.Errorf("prepare Zero Trust organization: %w", err)
	}
	return org, nil
}

// EnsureSetup is the common login/setup flow. Billing is read-only: OAuth has
// no Billing scope, and setup must never subscribe to or replace a paid plan.
func EnsureSetup(ctx context.Context, c *cfapi.Client, account, email string) (Report, error) {
	r := Report{}
	org, err := ensureOrganization(ctx, c, account, &r)
	if err != nil {
		return r, fmt.Errorf("review Zero Trust organization at %s: %w", dashboardURL(account, "/settings/general"), err)
	}
	subscriptions, err := c.Subscriptions(ctx, account)
	var api *cfapi.APIError
	switch {
	case errors.As(err, &api) && api.StatusCode == http.StatusForbidden:
		r.Manual = append(r.Manual, planInstruction(account, "OAuth cannot verify or activate the Zero Trust plan (Cloudflare offers no Billing scope)."))
	case err != nil:
		return r, fmt.Errorf("read Zero Trust subscription (review %s): %w", dashboardURL(account, "/settings/billing"), err)
	default:
		active := false
		for _, sub := range subscriptions {
			// Preserve any existing Free, Standard or enterprise Zero Trust plan.
			if (sub.Product.Name == "prod_teams" || strings.HasPrefix(strings.ToLower(sub.RatePlan.ID), "teams_")) &&
				(strings.EqualFold(sub.State, "paid") || strings.EqualFold(sub.State, "trial") || strings.EqualFold(sub.State, "provisioned")) {
				active = true
				r.AlreadyReady = append(r.AlreadyReady, "Zero Trust subscription "+sub.RatePlan.ID)
				break
			}
		}
		if !active {
			instruction := planInstruction(account, "No active Zero Trust subscription was found.")
			r.Manual = append(r.Manual, instruction)
			return r, fmt.Errorf("%w; %s", ErrPlanRequired, instruction)
		}
	}
	r, err = ensureMesh(ctx, c, account, org, r)
	if err != nil {
		return r, fmt.Errorf("prepare Mesh (review %s): %w", dashboardURL(account, "/settings/warp-client"), err)
	}
	enrollment, err := EnsureDeviceEnrollment(ctx, c, account, email)
	r.Changed = append(r.Changed, enrollment.Changed...)
	r.AlreadyReady = append(r.AlreadyReady, enrollment.AlreadyReady...)
	if err != nil {
		return r, fmt.Errorf("prepare owner enrollment (review %s): %w", dashboardURL(account, "/settings/warp-client"), err)
	}
	return r, nil
}

func dashboardURL(account, path string) string {
	return "https://one.dash.cloudflare.com/" + url.PathEscape(account) + path
}

func planInstruction(account, reason string) string {
	return reason + " Open " + dashboardURL(account, "/settings/billing") + "; select Zero Trust Free (50 users, $0) if no plan is active, then run `meshscale up`."
}

func ensureMesh(ctx context.Context, client *cfapi.Client, accountID string, org cfapi.Organization, r Report) (Report, error) {
	gateway, err := client.GatewayAccount(ctx, accountID)
	if cfapi.IsMissing(err) || err == nil && gateway.ID == "" {
		gateway, err = client.CreateGatewayAccount(ctx, accountID)
		if err == nil {
			r.Changed = append(r.Changed, "created Zero Trust Gateway account")
		}
	} else if err == nil {
		r.AlreadyReady = append(r.AlreadyReady, "Zero Trust Gateway account")
	}
	if err != nil {
		return r, fmt.Errorf("prepare Gateway account: %w", err)
	}
	if gateway.ID == "" {
		return r, fmt.Errorf("response for Gateway account has no ID")
	}
	domain := strings.TrimSpace(org.AuthDomain)
	team := strings.TrimSuffix(domain, ".cloudflareaccess.com")
	if team == "" || team == domain || strings.ContainsAny(team, "/\" @\t\n") {
		return r, fmt.Errorf("invalid Access organization auth_domain %q; choose a Zero Trust team name first", domain)
	}
	match := fmt.Sprintf("identity.email == %q", "warp_connector@"+domain)
	profiles, err := client.ListDeviceProfiles(ctx, accountID)
	if err != nil && !cfapi.IsMissing(err) {
		return r, err
	}
	var found *cfapi.DeviceProfile
	precedence := float64(100)
	for i := range profiles {
		p := &profiles[i]
		if matchingProfile(*p, match) {
			found = p
			break
		}
	}
	if found == nil {
		for _, p := range profiles {
			if p.Name == ProfileName {
				return r, fmt.Errorf("device profile %q already exists with different settings; review it in the dashboard before retrying", ProfileName)
			}
			if !p.Default && p.ProfileType != "browser_extension" && p.Precedence <= precedence {
				precedence = p.Precedence / 2
			}
		}
		if precedence <= 0 {
			return r, fmt.Errorf("cannot place Mesh profile before precedence zero without changing existing profiles; adjust profile precedence in the dashboard")
		}
	}
	settings, err := client.DeviceSettings(ctx, accountID)
	if err != nil && !cfapi.IsMissing(err) {
		return r, err
	}
	yes := true
	patch := cfapi.DeviceSettingsPatch{}
	for _, s := range []struct {
		name    string
		enabled bool
		field   **bool
	}{
		{"use_zt_virtual_ip", settings.UseZTVirtualIP, &patch.UseZTVirtualIP},
		{"gateway_proxy_enabled", settings.GatewayProxyEnabled, &patch.GatewayProxyEnabled},
		{"gateway_udp_proxy_enabled", settings.GatewayUDPProxyEnabled, &patch.GatewayUDPProxyEnabled},
	} {
		if s.enabled {
			r.AlreadyReady = append(r.AlreadyReady, s.name+" = true")
		} else {
			*s.field = &yes
		}
	}
	if patch != (cfapi.DeviceSettingsPatch{}) {
		if settings, err = client.UpdateDeviceSettings(ctx, accountID, patch); err != nil {
			return r, err
		}
		if patch.UseZTVirtualIP != nil && settings.UseZTVirtualIP {
			r.Changed = append(r.Changed, "use_zt_virtual_ip = true")
		}
		if patch.GatewayProxyEnabled != nil && settings.GatewayProxyEnabled {
			r.Changed = append(r.Changed, "gateway_proxy_enabled = true")
		}
		if patch.GatewayUDPProxyEnabled != nil && settings.GatewayUDPProxyEnabled {
			r.Changed = append(r.Changed, "gateway_udp_proxy_enabled = true")
		}
	}
	if !settings.UseZTVirtualIP || !settings.GatewayProxyEnabled || !settings.GatewayUDPProxyEnabled {
		return r, fmt.Errorf("required device settings did not verify after update")
	}
	connectivity, err := client.ConnectivitySettings(ctx, accountID)
	if err != nil && !cfapi.IsMissing(err) {
		return r, err
	}
	if connectivity.OfframpWARPEnabled {
		r.AlreadyReady = append(r.AlreadyReady, "offramp_warp_enabled = true")
	} else {
		connectivity, err = client.EnableMeshReachability(ctx, accountID)
		if err != nil {
			return r, err
		}
		if !connectivity.OfframpWARPEnabled {
			return r, fmt.Errorf("reachability over Mesh did not verify after update")
		}
		r.Changed = append(r.Changed, "offramp_warp_enabled = true (allow Cloudflare One traffic to reach enrolled devices)")
	}

	if found != nil {
		r.ProfileID = found.PolicyID
		r.AlreadyReady = append(r.AlreadyReady, "reusing device profile "+found.Name)
		return r, nil
	}
	include := []cfapi.SplitTunnelEntry{{Address: meshaddr.IPv4Range.String()}}
	profile, err := client.CreateDeviceProfile(ctx, accountID, cfapi.CreateDeviceProfileParams{
		Name: ProfileName, Match: match, Precedence: &precedence, Enabled: &yes, ProfileType: "warp",
		TunnelProtocol: "masque", ServiceModeV2: &cfapi.ServiceMode{Mode: "warp"}, Include: &include,
	})
	if err != nil {
		return r, err
	}
	r.ProfileID = profile.PolicyID
	r.Changed = append(r.Changed, "created device profile "+ProfileName+" (Include "+meshaddr.IPv4Range.String()+", WARP, MASQUE)")
	if profile.PolicyID == "" || !matchingProfile(profile, match) {
		return r, fmt.Errorf("created Mesh profile did not verify")
	}
	return r, nil
}

func matchingProfile(p cfapi.DeviceProfile, match string) bool {
	return !p.Default && p.Enabled && p.ProfileType != "browser_extension" &&
		strings.Join(strings.Fields(p.Match), " ") == match && p.ServiceModeV2.Mode == "warp" && p.TunnelProtocol == "masque" &&
		len(p.Exclude) == 0 && len(p.Include) == 1 && p.Include[0].Address == meshaddr.IPv4Range.String() && p.Include[0].Host == ""
}
