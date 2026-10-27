package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/devicesync"
	"github.com/Whiteknight07/meshscale/internal/rules"
)

func init() {
	register(&command{name: "rules", short: "check, sync, list, or reset Gateway network access rules", run: runRules})
	devicesync.Default.Register("rules", func(ctx context.Context, snapshot devicesync.Snapshot) error {
		var out io.Writer = os.Stdout
		if snapshot.Quiet {
			out = io.Discard
		}
		return SyncRules(ctx, out, snapshot.Client, snapshot.Account, "", false)
	})
}

func defaultRulesPath() (string, error) {
	d, err := config.Dir()
	return filepath.Join(d, "rules.json"), err
}

func runRules(ctx context.Context, args []string) error {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if len(args) == 0 {
		return fmt.Errorf("usage: meshscale rules check <file> | sync [--dry-run] [--file path] | list | reset")
	}
	fs := flag.NewFlagSet("rules "+args[0], flag.ContinueOnError)
	path := ""
	dry := false
	switch args[0] {
	case "sync":
		fs.StringVar(&path, "file", "", "policy path (default: config dir/rules.json)")
		fs.BoolVar(&dry, "dry-run", false, "show planned changes without writes")
	case "check", "list", "reset":
	default:
		return fmt.Errorf("unknown rules command %q", args[0])
	}
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if args[0] == "check" {
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: meshscale rules check <file>")
		}
		path = fs.Arg(0)
		dry = true
	} else if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments to rules %s", args[0])
	}
	if args[0] == "sync" || args[0] == "check" {
		if path == "" {
			var err error
			path, err = defaultRulesPath()
			if err != nil {
				return err
			}
		}
		// Missing default policy is also a credential-free no-op after up.
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) && args[0] == "sync" && !hasFileFlag(fs) {
			fmt.Fprintln(os.Stdout, "No access policy file; no Gateway rules written. Use rules reset to remove a previously synced policy.")
			return nil
		}
	}
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	client := cfapi.New(tokens, version)
	switch args[0] {
	case "sync", "check":
		return SyncRules(ctx, os.Stdout, client, account, path, dry)
	case "list":
		existing, err := client.ListGatewayRules(ctx, account)
		if err != nil {
			return err
		}
		var owned []cfapi.GatewayRule
		for _, r := range existing {
			if rules.Owner(r) != "" {
				owned = append(owned, r)
			}
		}
		sort.Slice(owned, func(i, j int) bool { return owned[i].Precedence < owned[j].Precedence })
		if owned == nil {
			owned = []cfapi.GatewayRule{}
		}
		return writeRuleJSON(os.Stdout, owned)
	case "reset":
		return resetRules(ctx, os.Stdout, client, account)
	}
	return nil
}

func hasFileFlag(fs *flag.FlagSet) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "file" {
			found = true
		}
	})
	return found
}

// SyncRules is shared with up/daemon. An absent default file is a no-op, so a
// participant without the admin's policy cannot erase centrally synced rules.
// Call with path "" after connecting, using a bounded context; report errors
// non-fatally. Explicit paths must exist.
func SyncRules(ctx context.Context, out io.Writer, client *cfapi.Client, account, path string, dry bool) error {
	optional := path == ""
	if optional {
		var err error
		path, err = defaultRulesPath()
		if err != nil {
			return err
		}
	}
	data, err := os.ReadFile(path)
	if optional && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	policy, err := rules.Parse(data)
	if err != nil {
		return err
	}
	state, err := config.LoadMeshState()
	if err != nil {
		return err
	}
	devices, err := loadMeshDevices(ctx, client, account, nil, time.Now(), state)
	if err != nil {
		return err
	}
	participants := make([]rules.Participant, 0, len(devices))
	for _, d := range devices {
		participants = append(participants, rules.Participant{ID: d.Kind + "/" + d.ID, Name: d.Name, Email: d.OwnerEmail, IPv4: d.IPv4, IPv6: d.IPv6})
	}
	peers, err := loadSecurePeers(ctx, client, account)
	if err != nil {
		return err
	}
	var secureIPs []netip.Addr
	for _, p := range peers {
		secureIPs = append(secureIPs, p.MeshIP)
	}
	desired, err := rules.CompileSecure(policy, participants, secureIPs)
	if err != nil {
		return err
	}
	existing, err := client.ListGatewayRules(ctx, account)
	if err != nil {
		return err
	}
	changes, err := rules.Diff(desired, existing)
	if err != nil {
		return err
	}
	if changes == nil {
		changes = []rules.Change{}
	}
	if err := writeRuleJSON(out, changes); err != nil {
		return err
	}
	if dry {
		// Show the complete compiled policy, including unchanged rules.
		if err := writeRuleJSON(out, desiredWithPrecedence(desired, existing, changes)); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "Dry run: %d change(s); no Gateway rules written.\n", len(changes))
		return err
	}
	if err := rules.Apply(ctx, client, account, changes); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Access rules synced: %d change(s). Gateway propagation may take about 60 seconds.\n", len(changes))
	return err
}

func desiredWithPrecedence(desired, existing []cfapi.GatewayRule, changes []rules.Change) []cfapi.GatewayRule {
	byOwner := map[string]cfapi.GatewayRule{}
	for _, r := range existing {
		if id := rules.Owner(r); id != "" {
			byOwner[id] = r
		}
	}
	for _, c := range changes {
		if c.Action != "delete" {
			byOwner[rules.Owner(c.Rule)] = c.Rule
		}
	}
	result := make([]cfapi.GatewayRule, 0, len(desired))
	for _, r := range desired {
		result = append(result, byOwner[rules.Owner(r)])
	}
	return result
}

func writeRuleJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func resetRules(ctx context.Context, out io.Writer, client *cfapi.Client, account string) error {
	existing, err := client.ListGatewayRules(ctx, account)
	if err != nil {
		return err
	}
	changes, err := rules.Diff(nil, existing)
	if err != nil {
		return err
	}
	if err := rules.Apply(ctx, client, account, changes); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Removed %d meshscale network rule(s); Gateway's default allow behavior is restored subject to other account policies. Remove/rename rules.json to prevent a later sync from reinstalling it.\n", len(changes))
	return err
}
