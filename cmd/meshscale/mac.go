package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Whiteknight07/meshscale/internal/auth"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/warpcli"
)

func init() {
	register(&command{name: "local-status", short: "read this device's official client state and safety guard", run: runLocalStatus})
}

type macPending struct {
	Team    string
	Started time.Time
}

func macPendingPath() (string, error) {
	dir, err := config.Dir()
	return filepath.Join(dir, "mac-enrollment", "pending.json"), err
}

func runMacUp(parent context.Context, settings *config.BackendSettings, noLogin, replace, asJSON bool, tokenFile string) (err error) {
	notify := func(p warpcli.Progress) {
		if asJSON {
			_ = json.NewEncoder(os.Stdout).Encode(p)
		} else {
			fmt.Fprintln(os.Stdout, p.Message)
		}
	}
	defer func() {
		if err == nil {
			return
		}
		var public *warpcli.EnrollmentError
		if errors.As(err, &public) {
			notify(warpcli.Progress{State: public.State, Message: public.Message})
		} else {
			notify(warpcli.Progress{State: "error", Message: "Cloudflare enrollment could not finish. Run meshscale up in Terminal to review the error."})
		}
	}()
	if !warpcli.Installed() {
		return warpcli.EnrollmentFailure("not_installed")
	}
	if !noLogin && tokenFile != "" {
		return fmt.Errorf("--service-token-file requires --no-login")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	path, err := macPendingPath()
	if err != nil {
		return err
	}
	release, err := localstate.Lock(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("another enrollment is running: %w", err)
	}
	defer release()
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	client := cfapi.New(tokens, version)
	team, err := zeroTrustTeam(ctx, client, account)
	if err != nil {
		return err
	}
	var pending macPending
	if err := localstate.Read(path, &pending); err != nil && !os.IsNotExist(err) {
		return err
	}
	if pending.Team != "" && pending.Team != team && time.Since(pending.Started) < 10*time.Minute {
		return fmt.Errorf("a browser login for another team is pending; finish or cancel it in Cloudflare One first")
	}
	local := warpcli.New("")
	prepare := func(ctx context.Context) error {
		_, oauth := tokens.(*auth.TokenSource)
		email, err := auth.NewClient().Email(ctx, tokens, oauth)
		if err != nil && !oauth {
			email, err = client.SoleAccountOwnerEmail(ctx, account)
		}
		if err != nil {
			return err
		}
		return completeAccountSetup(ctx, io.Discard, client, account, email)
	}
	begin := func(ctx context.Context) error {
		if err := local.RegistrationNew(ctx, team); err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, "/usr/bin/open", "https://"+team+".cloudflareaccess.com/warp")
		cmd.Env = config.ChildEnvironment()
		return cmd.Run()
	}
	if noLogin {
		// Verification is read-only; no token or policy is ever created here.
		begin, err = prepareMacNoLogin(ctx, client, account, team, tokenFile, local)
		if err != nil {
			return err
		}
		prepare = nil
	}
	if err := settings.Save(); err != nil {
		return err
	}
	err = local.EnrollMac(ctx, warpcli.EnrollmentOptions{
		Team: team, ReplaceConsumer: replace, Pending: !noLogin && pending.Team == team && time.Since(pending.Started) < 10*time.Minute,
		Prepare: prepare, Begin: begin, Notify: notify,
		SetPending: func(active bool) error {
			if active {
				return localstate.Write(path, macPending{Team: team, Started: time.Now()})
			}
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		},
	})
	if err != nil {
		return err
	}
	if !asJSON {
		return writeLocalIP(ctx, os.Stdout, client, account, local, 4)
	}
	return nil
}

type localStatus struct {
	Installed  bool   `json:"installed"`
	State      string `json:"state"`
	Connected  bool   `json:"connected"`
	Safe       bool   `json:"safe"`
	Enrollment string `json:"enrollment"`
	Message    string `json:"message,omitempty"`
}

func runLocalStatus(ctx context.Context, args []string) error {
	if len(args) != 1 || args[0] != "--json" {
		return fmt.Errorf("usage: meshscale local-status --json")
	}
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("local-status currently supports the macOS official client")
	}
	s := localStatus{Installed: warpcli.Installed(), State: "disconnected", Enrollment: "unregistered"}
	if !s.Installed {
		s.Enrollment = "not_installed"
		s.Message = warpcli.EnrollmentFailure(s.Enrollment).Error()
		return json.NewEncoder(os.Stdout).Encode(s)
	}
	local := warpcli.New("")
	status, statusErr := local.Status(ctx)
	if statusErr != nil {
		s.Enrollment = "registration_error"
		s.Message = warpcli.EnrollmentFailure(s.Enrollment).Error()
		return json.NewEncoder(os.Stdout).Encode(s)
	}
	s.State = status.State
	info, err := local.Registration(ctx)
	if err != nil {
		if !warpcli.IsUnregistered(err) {
			return err
		}
		if path, pathErr := macPendingPath(); pathErr == nil {
			var pending macPending
			if localstate.Read(path, &pending) == nil && pending.Team != "" && time.Since(pending.Started) < 10*time.Minute {
				s.Enrollment = "registration_pending"
			}
		}
		return json.NewEncoder(os.Stdout).Encode(s)
	}
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	team, err := zeroTrustTeam(ctx, cfapi.New(tokens, version), account)
	if err != nil {
		return err
	}
	s.Enrollment = "registered"
	if info.AccountType != "Team" {
		s.Enrollment = "consumer"
	} else if info.Organization != team {
		s.Enrollment = "different_org"
	}
	if s.Enrollment != "registered" {
		s.Message = warpcli.EnrollmentFailure(s.Enrollment).Error()
		return json.NewEncoder(os.Stdout).Encode(s)
	}
	local.Organization = team
	s.Safe = local.CheckSafety(ctx) == nil
	s.Connected = status.Connected && s.Safe
	if !s.Safe {
		s.Enrollment = "safety_blocked"
		s.Message = warpcli.EnrollmentFailure(s.Enrollment).Error()
	}
	return json.NewEncoder(os.Stdout).Encode(s)
}
