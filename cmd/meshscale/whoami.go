package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Whiteknight07/meshscale/internal/auth"
)

func init() {
	register(&command{name: "whoami", short: "show the current Cloudflare user and account", run: runWhoami})
}

func runWhoami(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("whoami", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print account identity as JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: meshscale whoami [--json]")
	}
	accountID, source, err := resolveCredentials()
	if err != nil {
		return err
	}
	_, oauth := source.(*auth.TokenSource)
	kind := "API token"
	if oauth {
		kind = "OAuth"
	}
	if !*asJSON {
		fmt.Printf("Credentials: %s\n", kind)
	}
	client := auth.NewClient()
	email, emailErr := client.Email(ctx, source, oauth)
	if !*asJSON && emailErr != nil {
		fmt.Printf("User: unavailable (%v)\n", emailErr)
	} else if !*asJSON {
		fmt.Printf("User: %s\n", tableField(email))
	}
	account, err := client.Account(ctx, source, accountID)
	if err != nil {
		if !*asJSON {
			fmt.Printf("Account ID: %s\n", tableField(accountID))
		}
		return err
	}
	if *asJSON {
		return writeIdentityJSON(os.Stdout, account.ID, account.Name, email, kind)
	}
	fmt.Printf("Account: %s (%s)\n", tableField(account.Name), tableField(account.ID))
	return nil
}

// Account identity contains no session or API credentials. Missing email is valid
// for scoped API tokens that can read devices but cannot read user details.
func writeIdentityJSON(out io.Writer, id, name, email, credentials string) error {
	return json.NewEncoder(out).Encode(struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Email       string `json:"email,omitempty"`
		Credentials string `json:"credentials"`
	}{id, name, email, credentials})
}
