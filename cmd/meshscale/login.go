package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Whiteknight07/meshscale/internal/auth"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
)

func init() {
	register(&command{name: "login", short: "sign in with Cloudflare", run: runLogin})
}

func runLogin(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("login", flag.ContinueOnError)
	noBrowser := flags.Bool("no-browser", false, "print the sign-in URL and accept a pasted callback URL or code")
	accountID := flags.String("account", "", "Cloudflare account ID (prompted when several are available)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: meshscale login [--no-browser] [--account id]")
	}
	return loginFlow(ctx, *noBrowser, *accountID, os.Stdout, true)
}

// up saves the login first and runs concise, resumable setup itself. The Mac
// app continues to use login with its existing full setup behavior.
func loginFlow(ctx context.Context, noBrowser bool, accountID string, out io.Writer, setup bool) error {
	store, err := auth.DefaultStore()
	if err != nil {
		return err
	}
	client := auth.NewClient()
	input := &loginInput{reader: bufio.NewReader(os.Stdin)}
	session, err := client.Login(ctx, auth.LoginOptions{Compact: !setup, NoBrowser: noBrowser, Output: out, ReadLine: input.readLine})
	if err != nil {
		return err
	}
	saved := false
	defer func() {
		if !saved {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			if err := client.Revoke(cleanupCtx, session); err != nil {
				fmt.Fprintf(os.Stderr, "Could not revoke the unsaved login: %v\n", err)
			}
		}
	}()
	source := cfapi.StaticToken(session.AccessToken)
	accounts, err := client.Accounts(ctx, source)
	if err != nil {
		return fmt.Errorf("list accounts after sign-in: %w", err)
	}
	account, err := chooseAccount(ctx, accounts, accountID, input.readLine, out)
	if err != nil {
		return err
	}
	session.Account = account
	email, emailErr := client.Email(ctx, source, true)
	if emailErr == nil {
		session.Email = email
	}
	if err := store.SaveLogin(ctx, session); err != nil {
		return err
	}
	saved = true
	if !setup {
		fmt.Fprintln(out, "Signed in.")
	} else {
		fmt.Fprintf(out, "Signed in with Cloudflare. Account: %s (%s)\n", tableField(account.Name), tableField(account.ID))
		if email != "" {
			fmt.Fprintf(out, "User: %s\n", tableField(email))
		}
	}
	if emailErr != nil {
		fmt.Fprintf(os.Stderr, "Could not read your email: %v\n", emailErr)
	}
	if env, err := config.LoadEnv(); err == nil && env["CLOUDFLARE_API_TOKEN"] != "" && env["CLOUDFLARE_ACCOUNT_ID"] != "" {
		fmt.Fprintln(out, "API token credentials in the environment or dev.env take priority. Remove those to use this OAuth login for other commands.")
	}
	if !setup {
		return nil
	}
	if emailErr != nil {
		return fmt.Errorf("signed in and login saved, but owner enrollment needs your email; run `meshscale setup --devices` after granting User Details Read: %w", emailErr)
	}
	if err := completeAccountSetup(ctx, out, cfapi.New(auth.NewTokenSource(client, store, session), version), account.ID, email); err != nil {
		return fmt.Errorf("signed in and login saved; account setup incomplete (retry `meshscale setup --devices`): %w", err)
	}

	return nil
}

func chooseAccount(ctx context.Context, accounts []auth.Account, id string, readLine func(context.Context) (string, error), output io.Writer) (auth.Account, error) {
	if id != "" {
		for _, account := range accounts {
			if account.ID == id {
				return account, nil
			}
		}
		return auth.Account{}, fmt.Errorf("account %q is not accessible to this login", id)
	}
	if len(accounts) == 0 {
		return auth.Account{}, errors.New("no Cloudflare accounts available; create or join an account at https://dash.cloudflare.com and retry login")
	}
	if len(accounts) == 1 {
		return accounts[0], nil
	}
	fmt.Fprintln(output, "Choose a Cloudflare account:")
	for i, account := range accounts {
		fmt.Fprintf(output, "  %d. %s (%s)\n", i+1, tableField(account.Name), tableField(account.ID))
	}
	fmt.Fprint(output, "Account number or ID: ")
	line, err := readLine(ctx)
	if err != nil && !errors.Is(err, io.EOF) {
		return auth.Account{}, err
	}
	choice := strings.TrimSpace(line)
	for _, account := range accounts {
		if account.ID == choice {
			return account, nil
		}
	}
	if n, err := strconv.Atoi(choice); err == nil && n >= 1 && n <= len(accounts) {
		return accounts[n-1], nil
	}
	return auth.Account{}, errors.New("choose an account number or rerun with --account <id>")
}

// Keep a pending stdin read across cancellation. If the browser callback wins,
// the same read supplies account selection instead of stealing its first line.
// Only one caller may use loginInput at a time.
type loginInput struct {
	reader  *bufio.Reader
	pending chan inputLine
}

type inputLine struct {
	text string
	err  error
}

func (in *loginInput) readLine(ctx context.Context) (string, error) {
	if in.pending == nil {
		in.pending = make(chan inputLine, 1)
		pending := in.pending
		go func() {
			line, err := in.reader.ReadString('\n')
			pending <- inputLine{line, err}
		}()
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case line := <-in.pending:
		in.pending = nil
		return line.text, line.err
	}
}
