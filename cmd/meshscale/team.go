package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

func zeroTrustTeam(ctx context.Context, client *cfapi.Client, account string) (string, error) {
	org, err := client.Organization(ctx, account)
	if err != nil {
		return "", fmt.Errorf("read Zero Trust organization: %w", err)
	}
	team, ok := strings.CutSuffix(org.AuthDomain, ".cloudflareaccess.com")
	if !ok || !validTeamName(team) {
		return "", fmt.Errorf("invalid Access organization auth_domain; run meshscale setup --devices")
	}
	return team, nil
}

func validTeamName(team string) bool {
	valid, _ := regexp.MatchString(`^[a-z0-9][a-z0-9-]*$`, team)
	return valid
}
