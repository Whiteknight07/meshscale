package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/warpcli"
)

const macMDMPath = "/Library/Managed Preferences/com.cloudflare.warp.plist"

type macMDMCredentials struct {
	ID           string `json:"id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Team         string `json:"team"`
	ProfileID    string `json:"profile_id"`
}

func prepareMacNoLogin(ctx context.Context, client *cfapi.Client, account, team, path string, local *warpcli.Client) (func(context.Context) error, error) {
	if path == "" {
		return nil, fmt.Errorf("--no-login requires --service-token-file; see docs/macos-enrollment.md for the existing token, Service Auth rule, Include profile, and administrator approval")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	var credentials macMDMCredentials
	if err := localstate.Read(path, &credentials); err != nil {
		return nil, err
	}
	if credentials.ID == "" || credentials.ClientID == "" || credentials.ClientSecret == "" {
		return nil, fmt.Errorf("service token file requires id, client_id and client_secret")
	}
	credentials.Team = team
	credentials.ProfileID = ""
	tokens, err := client.ListServiceTokens(ctx, account)
	if err != nil {
		return nil, err
	}
	valid := false
	for _, token := range tokens {
		if token.ID == credentials.ID && token.ClientID == credentials.ClientID && (token.Enabled == nil || *token.Enabled) && (token.ExpiresAt == nil || token.ExpiresAt.After(time.Now())) {
			valid = true
		}
	}
	if !valid {
		return nil, fmt.Errorf("service token is absent, disabled, expired, or belongs to another account")
	}
	apps, err := client.ListEnrollmentApps(ctx, account)
	if err != nil {
		return nil, err
	}
	permitted := false
	for _, app := range apps {
		if app.Type != "warp" {
			continue
		}
		policies, err := client.EnrollmentPolicies(ctx, account, app.ID)
		if err != nil {
			return nil, err
		}
		for _, policy := range policies {
			if policy.Decision != "non_identity" || len(policy.Include) != 1 || len(policy.Include[0]) != 1 || len(policy.Require) != 0 || len(policy.Exclude) != 0 {
				continue
			}
			var selector struct {
				TokenID string `json:"token_id"`
			}
			if json.Unmarshal(policy.Include[0]["service_token"], &selector) == nil && selector.TokenID == credentials.ID {
				permitted = true
			}
		}
	}
	if !permitted {
		return nil, fmt.Errorf("no existing Service Auth enrollment policy permits exactly this service token; no account changes were made")
	}
	profiles, err := client.ListDeviceProfiles(ctx, account)
	if err != nil {
		return nil, err
	}
	for _, profile := range profiles {
		if profile.Match != fmt.Sprintf("identity.service_token_uuid == %q", credentials.ID) || profile.Default || !profile.Enabled || profile.ProfileType == "browser_extension" || len(profile.Exclude) != 0 || profile.ServiceModeV2.Mode != "warp" || profile.TunnelProtocol != "masque" {
			continue
		}
		merged := "(network policy)\tMode: WarpWithDnsOverHttps\n(network policy)\tInclude mode, with hosts/ips:\n"
		for _, entry := range profile.Include {
			value := entry.Address
			if value == "" {
				value = entry.Host
			}
			merged += "  " + value + "\n"
		}
		if warpcli.ValidateSettings(merged, team) != nil {
			continue
		}
		// Refuse any potentially shadowing profile, without trying to evaluate rules.
		shadowed := false
		for _, other := range profiles {
			if other.PolicyID != profile.PolicyID && other.Enabled && !other.Default && other.ProfileType != "browser_extension" && other.Precedence <= profile.Precedence {
				shadowed = true
			}
		}
		if !shadowed && profile.PolicyID != "" {
			credentials.ProfileID = profile.PolicyID
			break
		}
	}
	if credentials.ProfileID == "" {
		return nil, fmt.Errorf("no unshadowed safe Include profile matches identity.service_token_uuid for this token; no account changes were made")
	}
	for _, target := range []string{macMDMPath, "/Library/Application Support/Cloudflare/mdm.xml"} {
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			return nil, fmt.Errorf("existing or unreadable managed Cloudflare configuration; refusing to replace it")
		}
	}
	return func(ctx context.Context) error {
		// The privileged helper first enrolls in Posture only mode. It switches to
		// WARP only after verifying the actual team, token profile and Include routes.
		if err := local.Disconnect(ctx); err != nil {
			return err
		}
		dir, err := configMacMDMDir()
		if err != nil {
			return err
		}
		file, err := os.CreateTemp(dir, ".mdm-*")
		if err != nil {
			return err
		}
		name := file.Name()
		defer os.Remove(name)
		if err := json.NewEncoder(file).Encode(credentials); err != nil {
			file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		binary, err := os.Executable()
		if err != nil {
			return err
		}
		command := shellQuoteMac(binary) + " mac-mdm-install " + shellQuoteMac(name)
		script := "do shell script " + appleScriptQuote(command) + " with administrator privileges\n"
		cmd := exec.CommandContext(ctx, "/usr/bin/osascript")
		cmd.Env = config.ChildEnvironment()
		cmd.Stdin = strings.NewReader(script)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("administrator approval or managed enrollment did not finish; Cloudflare remains off or in Posture only mode; review docs/macos-enrollment.md")
		}
		return nil
	}, nil
}

func configMacMDMDir() (string, error) {
	path, err := macPendingPath()
	return filepath.Dir(path), err
}
func shellQuoteMac(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }
func appleScriptQuote(value string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + `"`
}

func mdmPlist(credentials macMDMCredentials, mode string) string {
	escape := func(value string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(value))
		return b.String()
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>organization</key><string>` + escape(credentials.Team) + `</string>
<key>auth_client_id</key><string>` + escape(credentials.ClientID) + `</string>
<key>auth_client_secret</key><string>` + escape(credentials.ClientSecret) + `</string>
<key>service_mode</key><string>` + escape(mode) + `</string>
<key>warp_tunnel_protocol</key><string>masque</string>
<key>auto_connect</key><integer>0</integer>
<key>switch_locked</key><false/>
<key>onboarding</key><false/>
</dict></plist>
`
}

func init() {
	register(&command{name: "mac-mdm-install", short: "internal administrator helper for up --no-login", run: runMacMDMInstall})
}

func runMacMDMInstall(parent context.Context, args []string) (err error) {
	if runtime.GOOS != "darwin" || os.Geteuid() != 0 || len(args) != 1 {
		return fmt.Errorf("this helper requires the macOS administrator flow from meshscale up --no-login")
	}
	// The unprivileged parent owns this mode-0600 input file. Do not read any
	// Cloudflare API credentials or meshscale configuration as root.
	info, err := os.Lstat(args[0])
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 16384 {
		return fmt.Errorf("invalid managed enrollment input")
	}
	file, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) {
		return fmt.Errorf("managed enrollment input changed")
	}
	var credentials macMDMCredentials
	if json.NewDecoder(file).Decode(&credentials) != nil || !validTeamName(credentials.Team) || credentials.ProfileID == "" || credentials.ClientID == "" || credentials.ClientSecret == "" {
		return fmt.Errorf("invalid managed enrollment input")
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	local := warpcli.New("")
	local.Organization = credentials.Team
	// Refuse to overwrite any existing registration, including a new one that
	// arrived since the unprivileged parent checked.
	if _, regErr := local.Registration(ctx); !warpcli.IsUnregistered(regErr) {
		return fmt.Errorf("managed enrollment requires an unregistered client")
	}
	if _, err := os.Lstat("/Library/Application Support/Cloudflare/mdm.xml"); !os.IsNotExist(err) {
		return fmt.Errorf("managed configuration already exists")
	}
	var managed os.FileInfo
	writeMode := func(mode string) error {
		next, err := writeMacMDM(macMDMPath, mdmPlist(credentials, mode), managed)
		if err != nil {
			return err
		}
		managed = next
		return local.MDMRefresh(ctx)
	}
	defer func() {
		if err != nil {
			stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = local.Disconnect(stop)
			// Retain credentials for review, but prevent a failed WARP stage from
			// reconnecting automatically after this helper exits.
			if managed != nil {
				if _, resetErr := writeMacMDM(macMDMPath, mdmPlist(credentials, "postureonly"), managed); resetErr == nil {
					_ = local.MDMRefresh(stop)
				}
			}
		}
	}()
	if err := writeMode("postureonly"); err != nil {
		return err
	}
	for {
		registration, regErr := local.Registration(ctx)
		settings, settingsErr := local.Settings(ctx)
		// Route validation is independent of service mode during this no-tunnel stage.
		stageSettings := strings.ReplaceAll(settings, "Mode: PostureOnly", "Mode: WarpWithDnsOverHttps")
		stageSettings = strings.ReplaceAll(stageSettings, "(mdm)\tMode:", "(network policy)\tMode:")
		if regErr == nil && settingsErr == nil && warpcli.ValidateSafety(registration, stageSettings, credentials.Team) == nil && strings.Contains(settings, "Profile ID: "+credentials.ProfileID+"\n") {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("safe service-token enrollment did not arrive; retained Posture only mode")
		case <-time.After(time.Second):
		}
	}
	if err := writeMode("warp"); err != nil {
		return err
	}
	if err := local.CheckSafety(ctx); err != nil {
		return err
	}
	// The ordinary parent state machine owns the explicit connect.
	return local.Disconnect(ctx)
}

// Replace atomically so Cloudflare never observes a partially written policy.
// Initial publication uses link's no-replace semantics; subsequent writes must
// still refer to the exact file created by this helper.
func writeMacMDM(path, contents string, expected os.FileInfo) (os.FileInfo, error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".meshscale-mdm-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	if _, err := file.WriteString(contents); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	if expected == nil {
		if err := os.Link(file.Name(), path); err != nil {
			return nil, err
		}
	} else {
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(current, expected) {
			return nil, fmt.Errorf("managed configuration changed; refusing replacement")
		}
		if err := os.Rename(file.Name(), path); err != nil {
			return nil, err
		}
	}
	return os.Lstat(path)
}
