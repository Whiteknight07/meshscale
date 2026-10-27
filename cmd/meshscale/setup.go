package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	"github.com/Whiteknight07/meshscale/internal/auth"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/mesh"
)

func init() {
	register(&command{name: "setup", short: "prepare the Cloudflare account for Mesh nodes", run: runSetup})
}

func runSetup(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	devices := fs.Bool("devices", false, "allow only the signed-in owner to enroll phones/laptops with a safe Mesh-only profile")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: meshscale setup")
	}
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	if *devices {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		_, oauth := tokens.(*auth.TokenSource)
		email, err := auth.NewClient().Email(ctx, tokens, oauth)
		if err != nil && !oauth {
			email, err = cfapi.New(tokens, version).SoleAccountOwnerEmail(ctx, account)
			if err == nil {
				fmt.Fprintln(os.Stdout, "API token cannot read /user; verified the sole accepted account owner through account membership.")
			}
		}
		if err != nil {
			return fmt.Errorf("read signed-in owner email (no enrollment changes made): %w", err)
		}
		return completeAccountSetup(ctx, os.Stdout, cfapi.New(tokens, version), account, email)
	}
	report, err := mesh.EnsureAccountReady(ctx, cfapi.New(tokens, version), account)
	writeSetupReport(os.Stdout, report)
	return err
}

func writeSetupReport(out io.Writer, r mesh.Report) {
	for _, s := range r.Changed {
		fmt.Fprintln(out, "Changed:", s)
	}
	for _, s := range r.AlreadyReady {
		fmt.Fprintln(out, "Already ready:", s)
	}
	for _, s := range r.Manual {
		fmt.Fprintln(out, "Dashboard step:", s)
	}
}

// Login passes its newly saved OAuth token source directly, so dev.env cannot
// accidentally provision a different account than the one just selected.
func completeAccountSetup(ctx context.Context, out io.Writer, client *cfapi.Client, account, email string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	report, err := mesh.EnsureSetup(ctx, client, account, email)
	writeSetupReport(out, report)
	if err != nil {
		return err
	}
	switch {
	case len(report.Manual) > 0:
		fmt.Fprintln(out, "Mesh setup needs the dashboard step above; then run `meshscale setup --devices`.")
	case len(report.Changed) == 0:
		fmt.Fprintln(out, "Mesh is already ready (no changes).")
	default:
		fmt.Fprintf(out, "Mesh is ready (%d changes).\n", len(report.Changed))
	}
	return nil
}

// Keep account detail in setup/login; up reports only progress and actionable
// manual steps. In particular the plan link appears exactly once.
func completeUpSetup(ctx context.Context, out io.Writer, client *cfapi.Client, account, email string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	_, err := mesh.EnsureSetup(ctx, client, account, email)
	if errors.Is(err, mesh.ErrPlanRequired) {
		fmt.Fprintf(out, "Activate Zero Trust Free at https://one.dash.cloudflare.com/%s/settings/billing, then run `meshscale up` to resume.\n", url.PathEscape(account))
		return fmt.Errorf("account setup incomplete; login saved, run meshscale up to resume")
	}
	if err != nil {
		return err
	}
	// Billing 403 is expected for OAuth; successful resource verification is
	// sufficient to proceed. No extra dashboard visit can grant a Billing scope.
	fmt.Fprintln(out, "Account ready.")
	return nil
}
