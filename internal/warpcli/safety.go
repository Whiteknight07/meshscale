package warpcli

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

// ValidateSafety accepts the effective merged policy, never an API profile
// which might not be the one selected by this device.
func ValidateSafety(info RegistrationInfo, settings, team string) error {
	if team == "" || info.AccountType != "Team" || info.Organization != team {
		return fmt.Errorf("connection blocked: registration must be Team in the selected organization")
	}
	return ValidateSettings(settings, team)
}

func ValidateSettings(settings, team string) error {
	mesh := false
	include := false
	mode := false
	inEntries := false
	allowed := map[string]bool{team + ".cloudflareaccess.com": true, "github.com": true, "api.github.com": true}
	for _, line := range strings.Split(settings, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.Contains(lower, "exclude mode") {
			return fmt.Errorf("connection blocked: Exclude mode can tunnel all traffic; select the meshscale Include profile")
		}
		if strings.Contains(lower, "include mode") {
			if include || trimmed != "(network policy)\tInclude mode, with hosts/ips:" {
				return fmt.Errorf("connection blocked: unrecognized Include policy")
			}
			include, inEntries = true, true
			continue
		}
		if strings.HasPrefix(trimmed, "(") {
			inEntries = false
		}
		if strings.HasPrefix(trimmed, "(network policy)\tMode:") || strings.HasPrefix(trimmed, "(mdm)\tMode:") {
			_, value, _ := strings.Cut(trimmed, "Mode:")
			mode = strings.TrimSpace(value) == "WarpWithDnsOverHttps" || strings.TrimSpace(value) == "Warp"
		}
		if !inEntries || trimmed == "" {
			continue
		}
		value := strings.Fields(trimmed)[0]
		if allowed[value] {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return fmt.Errorf("connection blocked: unknown destination in Include profile")
		}
		prefix = prefix.Masked()
		// Keep Internet and Tailscale routes out, including paired /1 routes.
		safe := false
		for _, parent := range []netip.Prefix{meshaddr.IPv4Range, netip.MustParsePrefix("2606:4700:cf1::/48"), netip.MustParsePrefix("172.64.128.0/20")} {
			if parent.Bits() <= prefix.Bits() && parent.Contains(prefix.Addr()) {
				safe = true
			}
		}
		if !safe {
			return fmt.Errorf("connection blocked: Include profile contains a destination outside Mesh and authentication services")
		}
		if value == meshaddr.IPv4Range.String() {
			mesh = true
		}
	}
	if !include || !mesh || !mode {
		return fmt.Errorf("connection blocked: effective settings must use WARP and network-policy Include mode containing %s; wait for the meshscale profile, then retry", meshaddr.IPv4Range)
	}
	return nil
}

func (c *Client) Settings(ctx context.Context) (string, error) { return c.run(ctx, "", "settings") }

func (c *Client) CheckSafety(ctx context.Context) error {
	info, err := c.Registration(ctx)
	if err != nil {
		return err
	}
	settings, err := c.Settings(ctx)
	if err != nil {
		return err
	}
	return ValidateSafety(info, settings, c.Organization)
}

func (c *Client) RegistrationNew(ctx context.Context, team string) error {
	_, err := c.run(ctx, "", "registration", "new", team)
	return err
}

func (c *Client) RegistrationDelete(ctx context.Context) error {
	_, err := c.run(ctx, "", "registration", "delete")
	return err
}

func (c *Client) MDMRefresh(ctx context.Context) error {
	_, err := c.run(ctx, "", "mdm", "refresh")
	return err
}
