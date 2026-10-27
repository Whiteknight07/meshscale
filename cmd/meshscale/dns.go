package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/devicesync"
	"github.com/Whiteknight07/meshscale/internal/names"
)

func init() {
	devicesync.Default.Register("dns", func(ctx context.Context, s devicesync.Snapshot) error {
		suffix, err := dnsSuffix()
		if err != nil {
			return err
		}
		var participants []names.Participant
		for _, d := range s.Devices {
			participants = append(participants, names.Participant{ID: d.ID, Name: d.Name, IPv4: d.IPv4, IPv6: d.IPv6})
		}
		records, err := names.Build(participants, suffix)
		if err != nil {
			return err
		}
		var out io.Writer = os.Stdout
		if s.Quiet {
			out = io.Discard
		}
		return syncDNSRecords(ctx, out, s.Client, s.Account, records, false)
	})
	register(&command{name: "dns", short: "sync or list Gateway DNS names (MESHSCALE_DNS_SUFFIX, default: mesh)", run: runDNS})
}

func dnsSuffix() (string, error) {
	suffix := os.Getenv("MESHSCALE_DNS_SUFFIX")
	if suffix == "" {
		suffix = names.DefaultSuffix
	}
	return names.Suffix(suffix)
}

func deviceDNSRecords(devices []meshDevice) ([]names.Record, error) {
	suffix, err := dnsSuffix()
	if err != nil {
		return nil, err
	}
	participants := make([]names.Participant, 0, len(devices))
	for _, d := range devices {
		participants = append(participants, names.Participant{ID: d.Kind + "/" + d.ID, Name: d.Name, IPv4: d.IPv4, IPv6: d.IPv6})
	}
	return names.Build(participants, suffix)
}

func assignDNSNames(devices []meshDevice) error {
	records, err := deviceDNSRecords(devices)
	if err != nil {
		return err
	}
	byID := map[string]string{}
	for _, r := range records {
		byID[r.ID] = r.Name
	}
	for i := range devices {
		devices[i].DNSName = byID[devices[i].Kind+"/"+devices[i].ID]
	}
	return nil
}

func runDNS(ctx context.Context, args []string) error {
	if len(args) == 1 && args[0] == "cleanup-hosts" {
		return cleanupHosts(ctx)
	}
	if len(args) == 0 || args[0] != "sync" && args[0] != "list" {
		return fmt.Errorf("usage: meshscale dns sync [--dry-run] | dns list (suffix: MESHSCALE_DNS_SUFFIX, default mesh)")
	}
	fs := flag.NewFlagSet("dns "+args[0], flag.ContinueOnError)
	var dryRun bool
	if args[0] == "sync" {
		fs.BoolVar(&dryRun, "dry-run", false, "show changes without writing Gateway rules")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments to dns %s", args[0])
	}
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	client := cfapi.New(tokens, version)
	if args[0] == "list" {
		rules, err := client.ListGatewayRules(ctx, account)
		if err != nil {
			return err
		}
		return writeDNSRules(os.Stdout, rules)
	}
	return syncDNS(ctx, os.Stdout, client, account, dryRun)
}

func syncDNS(ctx context.Context, out io.Writer, client *cfapi.Client, account string, dryRun bool) error {
	state, err := config.LoadMeshState()
	if err != nil {
		return fmt.Errorf("read Mesh node state: %w", err)
	}
	devices, err := loadMeshDevices(ctx, client, account, nil, time.Now(), state)
	if err != nil {
		return err
	}
	records, err := deviceDNSRecords(devices)
	if err != nil {
		return err
	}
	return syncDNSRecords(ctx, out, client, account, records, dryRun)
}

func syncDNSRecords(ctx context.Context, out io.Writer, client *cfapi.Client, account string, records []names.Record, dryRun bool) error {
	rules, err := client.ListGatewayRules(ctx, account)
	if err != nil {
		return err
	}
	changes, err := names.Diff(records, rules)
	if err != nil {
		return err
	}
	for _, c := range changes {
		if _, err := fmt.Fprintf(out, "%s\t%s\t%s\n", c.Action, tableField(strings.TrimPrefix(c.Rule.Name, names.RulePrefix)), tableField(strings.Join(c.Rule.RuleSettings.OverrideIPs, ", "))); err != nil {
			return err
		}
	}
	if dryRun {
		_, err = fmt.Fprintf(out, "Dry run: %d change(s); no Gateway rules written.\n", len(changes))
		return err
	}
	if err := names.Apply(ctx, client, account, changes); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "DNS synced: %d change(s). Gateway propagation may take about 60 seconds.\n", len(changes))
	return err
}

func writeDNSRules(out io.Writer, rules []cfapi.GatewayRule) error {
	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "DNS NAME\tMESH IP\tENABLED\tRULE ID"); err != nil {
		return err
	}
	for _, rule := range rules {
		if names.Owner(rule) == "" {
			continue
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\t%t\t%s\n", tableField(strings.TrimPrefix(rule.Name, names.RulePrefix)), tableField(strings.Join(rule.RuleSettings.OverrideIPs, ", ")), rule.Enabled, tableField(rule.ID)); err != nil {
			return err
		}
	}
	return w.Flush()
}
