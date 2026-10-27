package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"net/mail"
	"reflect"
	"slices"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

const UserProfileName = "meshscale user devices"
const UserProfileOwner = "Managed by meshscale device enrollment v1"
const EnrollmentPolicyPrefix = "meshscale device enrollment: "

type DeviceEnrollment struct {
	Changed      []string               `json:"changed,omitempty"`
	AlreadyReady []string               `json:"already_ready,omitempty"`
	Email        string                 `json:"email"`
	Team         string                 `json:"team"`
	Profile      cfapi.DeviceProfile    `json:"profile"`
	Policy       cfapi.EnrollmentPolicy `json:"policy"`
	LoginMethods []cfapi.EnrollmentIDP  `json:"login_methods"`
}

func ownerOnly(policy cfapi.EnrollmentPolicy, email string) bool {
	if policy.Decision != "allow" || len(policy.Include) != 1 || len(policy.Include[0]) != 1 {
		return false
	}
	var entry struct {
		Email string `json:"email"`
	}
	raw, ok := policy.Include[0]["email"]
	return ok && json.Unmarshal(raw, &entry) == nil && strings.EqualFold(entry.Email, email)
}
func userIncludes(domain string, idps []cfapi.EnrollmentIDP) []cfapi.SplitTunnelEntry {
	// Include only Mesh and the authentication destinations Cloudflare requires.
	entries := []cfapi.SplitTunnelEntry{{Address: meshaddr.IPv4Range.String()}, {Address: "2606:4700:cf1::/48"}, {Host: domain}}
	for _, idp := range idps {
		if idp.Type == "github" {
			if !slices.ContainsFunc(entries, func(e cfapi.SplitTunnelEntry) bool { return e.Host == "github.com" }) {
				entries = append(entries, cfapi.SplitTunnelEntry{Host: "github.com"}, cfapi.SplitTunnelEntry{Host: "api.github.com"})
			}
		}
	}
	return entries
}
func safeUserProfile(p cfapi.DeviceProfile, match string, include []cfapi.SplitTunnelEntry) bool {
	if p.Name != UserProfileName || p.Description != UserProfileOwner || p.Default || !p.Enabled || p.ProfileType == "browser_extension" || strings.Join(strings.Fields(p.Match), " ") != match || p.ServiceModeV2.Mode != "warp" || p.TunnelProtocol != "masque" || len(p.Exclude) != 0 {
		return false
	}
	actual := append([]cfapi.SplitTunnelEntry(nil), p.Include...)
	want := append([]cfapi.SplitTunnelEntry(nil), include...)
	for i := range actual {
		actual[i].Description = ""
	}
	less := func(a, b cfapi.SplitTunnelEntry) int {
		return strings.Compare(a.Address+"/"+a.Host, b.Address+"/"+b.Host)
	}
	slices.SortFunc(actual, less)
	slices.SortFunc(want, less)
	return reflect.DeepEqual(actual, want)
}

// EnsureDeviceEnrollment changes only our user profile and one enrollment
// policy. It refuses broader existing enrollment and never edits existing config.
func EnsureDeviceEnrollment(ctx context.Context, c *cfapi.Client, account, email string) (DeviceEnrollment, error) {
	r := DeviceEnrollment{Email: email}
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || strings.ContainsAny(email, "\r\n") {
		return r, fmt.Errorf("signed-in owner email is unavailable or invalid")
	}
	org, err := c.Organization(ctx, account)
	if err != nil {
		return r, err
	}
	r.Team = strings.TrimSuffix(org.AuthDomain, ".cloudflareaccess.com")
	if r.Team == "" || r.Team == org.AuthDomain || strings.ContainsAny(r.Team, "/\" @\t\n") {
		return r, fmt.Errorf("invalid Zero Trust team domain")
	}
	apps, err := c.ListEnrollmentApps(ctx, account)
	if err != nil {
		return r, err
	}
	var app cfapi.EnrollmentApp
	for _, a := range apps {
		if a.Type == "warp" {
			if app.ID != "" {
				return r, fmt.Errorf("multiple warp enrollment apps; review enrollment in the dashboard")
			}
			app = a
		}
	}
	idps, err := c.ListEnrollmentIDPs(ctx, account)
	if err != nil {
		return r, err
	}
	if len(idps) == 0 && len(apps) == 0 {
		idp, err := c.CreatePINProvider(ctx, account)
		if err != nil {
			return r, err
		}
		r.Changed = append(r.Changed, "created email one-time PIN login provider")
		if idp.ID == "" || idp.Type != "onetimepin" {
			return r, fmt.Errorf("created email login provider did not verify")
		}
		idps = append(idps, idp)
	}
	for _, idp := range idps {
		if len(app.AllowedIDPs) > 0 && !slices.Contains(app.AllowedIDPs, idp.ID) {
			continue
		}
		if idp.Type != "onetimepin" && idp.Type != "github" {
			return r, fmt.Errorf("unsupported existing enrollment login method %q; configure its required Include domains before enrollment", idp.Type)
		}
		r.LoginMethods = append(r.LoginMethods, idp)
	}
	if len(r.LoginMethods) == 0 {
		return r, fmt.Errorf("no usable existing enrollment login method; configure one-time PIN or GitHub in the dashboard (setup will not add a login method to an existing Access deployment)")
	}
	var policies []cfapi.EnrollmentPolicy
	if app.ID != "" {
		policies, err = c.EnrollmentPolicies(ctx, account, app.ID)
		if err != nil {
			return r, err
		}
		r.AlreadyReady = append(r.AlreadyReady, "device enrollment application")
	}
	name := EnrollmentPolicyPrefix + email
	var owned *cfapi.EnrollmentPolicy
	precedence := 1
	for i := range policies {
		p := &policies[i]
		if strings.HasPrefix(p.Name, EnrollmentPolicyPrefix) {
			if owned != nil {
				return r, fmt.Errorf("multiple meshscale enrollment policies; review before retrying")
			}
			owned = p
			continue
		}
		if p.Decision == "bypass" || p.Decision == "non_identity" || p.Decision == "allow" && (!ownerOnly(*p, email) || len(p.Require) != 0 || len(p.Exclude) != 0) {
			return r, fmt.Errorf("existing enrollment policy %q permits more than the signed-in owner; refusing to broaden enrollment or change unowned policies", p.Name)
		}
		if p.Precedence >= precedence {
			precedence = p.Precedence + 1
		}
	}
	if owned != nil && (owned.Name != name || !ownerOnly(*owned, email) || len(owned.Exclude) != 0 || len(owned.Require) != 0) {
		return r, fmt.Errorf("existing meshscale enrollment policy %q differs from the owner-only policy; refusing to change it", owned.Name)
	}
	profiles, err := c.ListDeviceProfiles(ctx, account)
	if err != nil && !cfapi.IsMissing(err) {
		return r, err
	}
	match := fmt.Sprintf("identity.email == %q", email)
	include := userIncludes(org.AuthDomain, r.LoginMethods)
	priority := float64(100)
	earliestOther := float64(1e30)
	for _, p := range profiles {
		if p.Name == UserProfileName {
			if r.Profile.PolicyID != "" {
				return r, fmt.Errorf("duplicate user profiles")
			}
			if !safeUserProfile(p, match, include) {
				return r, fmt.Errorf("profile %q differs from the safe owned Include profile; review it before enrollment", p.Name)
			}
			r.Profile = p
		} else if !p.Default && p.ProfileType != "browser_extension" {
			earliestOther = min(earliestOther, p.Precedence)
			if p.Precedence <= priority {
				priority = p.Precedence / 2
			}
		}
	}
	if priority <= 0 {
		return r, fmt.Errorf("cannot place user profile above existing profiles without editing them")
	}
	if r.Profile.PolicyID != "" && r.Profile.Precedence >= earliestOther {
		return r, fmt.Errorf("user profile is shadowed by another profile; review precedence before enrollment")
	}
	if r.Profile.PolicyID == "" {
		yes := true
		p, err := c.CreateDeviceProfile(ctx, account, cfapi.CreateDeviceProfileParams{Name: UserProfileName, Description: UserProfileOwner, Match: match, Precedence: &priority, Enabled: &yes, ProfileType: "warp", TunnelProtocol: "masque", ServiceModeV2: &cfapi.ServiceMode{Mode: "warp"}, Include: &include})
		if err != nil {
			return r, err
		}
		r.Profile = p
		r.Changed = append(r.Changed, "created device profile "+UserProfileName+" (owner-only, Include Mesh and authentication destinations, WARP, MASQUE)")
	} else {
		r.AlreadyReady = append(r.AlreadyReady, "device profile "+UserProfileName)
	}
	if r.Profile.PolicyID == "" {
		return r, fmt.Errorf("created user profile has no ID; enrollment policy was not written")
	}
	// Read back the exact profile before allowing anyone to enroll.
	r.Profile, err = c.DeviceProfile(ctx, account, r.Profile.PolicyID)
	if err != nil {
		return r, err
	}
	if !safeUserProfile(r.Profile, match, include) {
		return r, fmt.Errorf("safe Include profile did not verify; enrollment policy was not written")
	}
	emailJSON, _ := json.Marshal(struct {
		Email string `json:"email"`
	}{email})
	want := cfapi.EnrollmentPolicy{Name: name, Decision: "allow", Precedence: precedence, Include: []cfapi.AccessRule{{"email": emailJSON}}, Exclude: []cfapi.AccessRule{}, Require: []cfapi.AccessRule{}}
	if owned != nil {
		r.Policy = *owned
		r.AlreadyReady = append(r.AlreadyReady, "owner-only enrollment policy "+owned.Name)
		return r, nil
	}
	if app.ID == "" {
		allowed := make([]string, 0, len(r.LoginMethods))
		for _, idp := range r.LoginMethods {
			allowed = append(allowed, idp.ID)
		}
		app, err = c.CreateEnrollmentApp(ctx, account, allowed, want)
		if err != nil {
			return r, err
		}
		r.Changed = append(r.Changed, "created device enrollment application with owner-only policy for "+email)
		if app.ID == "" || app.Type != "warp" {
			return r, fmt.Errorf("created enrollment application did not verify")
		}
		// The app API may return policies without all fields; verify through the
		// policy endpoint, and never create a second policy after a partial response.
		policies, err = c.EnrollmentPolicies(ctx, account, app.ID)
		if err != nil {
			return r, err
		}
		if len(policies) != 1 {
			return r, fmt.Errorf("created enrollment application did not retain exactly one owner policy")
		}
		r.Policy = policies[0]
	} else {
		r.Policy, err = c.CreateEnrollmentPolicy(ctx, account, app.ID, want)
		if err == nil {
			r.Changed = append(r.Changed, "created owner-only enrollment policy for "+email)
		}
	}
	if err != nil {
		return r, err
	}
	if !ownerOnly(r.Policy, email) || len(r.Policy.Exclude) != 0 || len(r.Policy.Require) != 0 {
		return r, fmt.Errorf("enrollment policy response failed owner-only verification")
	}
	return r, nil
}
