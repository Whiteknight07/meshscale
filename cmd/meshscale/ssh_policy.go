package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/Whiteknight07/meshscale/internal/auth"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/config"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
	"github.com/Whiteknight07/meshscale/internal/sshserver"
)

func sshPolicyOwner(ctx context.Context) (string, error) {
	account, tokens, err := resolveCredentials()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return auth.ResolveOwnerEmail(ctx, cfapi.New(tokens, version), account)
}

type sshPolicyCommand struct {
	path             string
	out, diagnostics io.Writer
	owner            func(context.Context) (string, error)
	localUser        func(string) (string, uint32, error)
	uid              int
}

func runSSHPolicy(ctx context.Context, args []string) error {
	options, err := config.LoadService()
	if err != nil {
		return err
	}
	return (sshPolicyCommand{options.SSHPolicy, os.Stdout, os.Stderr, sshPolicyOwner, sshserver.LocalUser, os.Geteuid()}).run(ctx, args)
}

func (c sshPolicyCommand) run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshscale ssh policy init|show|test [--policy path]")
	}
	operation := args[0]
	fs := flag.NewFlagSet("ssh policy "+operation, flag.ContinueOnError)
	fs.SetOutput(c.diagnostics)
	path := fs.String("policy", c.path, "SSH policy file (defaults to the daemon's configured path)")
	var force, allowRoot *bool
	var from *string
	switch operation {
	case "init":
		force = fs.Bool("force", false, "replace an existing protected policy")
		allowRoot = fs.Bool("allow-root", false, "explicitly allow the account owner to log in as root")
	case "show":
	case "test":
		from = fs.String("from", "", "offline source: Mesh IP, admin-managed node name, or device:<id>")
	default:
		return fmt.Errorf("unknown SSH policy operation %q", operation)
	}
	// Go flags stop at the first positional; allow the documented test identity
	// local-user --from source form as well as flags before positional arguments.
	flags, positional := []string{}, []string{}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			key := strings.TrimLeft(arg, "-")
			if key == "from" || key == "policy" {
				if i+1 == len(args) {
					return fmt.Errorf("%s requires a value", arg)
				}
				i++
				flags = append(flags, args[i])
			}
		} else {
			positional = append(positional, arg)
		}
	}
	if err := fs.Parse(append(flags, positional...)); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if operation == "test" && fs.NArg() != 2 || operation != "test" && fs.NArg() != 0 {
		return fmt.Errorf("usage: meshscale ssh policy %s [--policy path]%s", operation, map[bool]string{true: " <identity> <local-user> [--from <mesh-ip|device>]"}[operation == "test"])
	}
	if operation == "init" {
		if c.uid != 0 && *allowRoot {
			return fmt.Errorf("rootless SSH cannot serve root; omit --allow-root")
		}
		owner, err := c.owner(ctx)
		if err != nil {
			return fmt.Errorf("verify account owner: %w", err)
		}
		_, err = sshserver.InitPolicy(*path, owner, *allowRoot, *force)
		if err != nil {
			return err
		}
		root := "root denied"
		if *allowRoot {
			root = "root explicitly allowed"
		}
		scope := "non-root local users"
		if c.uid != 0 {
			scope = "this server's non-root local user only"
		}
		_, err = fmt.Fprintf(c.out, "Created SSH policy %s: %s -> %s; %s.\n", *path, owner, scope, root)
		return err
	}
	p, err := sshserver.LoadPolicy(*path)
	if err != nil {
		return fmt.Errorf("read SSH policy: %w", err)
	}
	if operation == "show" {
		if p.Missing() {
			fmt.Fprintln(c.diagnostics, p.MissingMessage())
		}
		enc := json.NewEncoder(c.out)
		enc.SetIndent("", "  ")
		return enc.Encode(p)
	}
	id, note, err := offlineSSHIdentity(fs.Arg(0), *from)
	if err != nil {
		return err
	}
	reason := "no matching rule (default deny)"
	if p.Missing() {
		reason = p.MissingMessage()
	} else {
		name, uid, err := c.localUser(fs.Arg(1))
		if err != nil {
			reason = "local user unavailable: " + err.Error()
		} else if c.uid != 0 && uid != uint32(c.uid) {
			reason = "rootless SSH server can only serve its own local user"
		} else if index := p.MatchingRule(id, name, uid); index >= 0 {
			_, err := fmt.Fprintf(c.out, "ALLOW: %s -> %s: matched %s%s\n", fs.Arg(0), fs.Arg(1), p.RuleName(index), note)
			return err
		} else {
			reason = p.DenialReason(id, name, uid)
		}
	}
	fmt.Fprintf(c.out, "DENY: %s -> %s: %s%s\n", fs.Arg(0), fs.Arg(1), reason, note)
	return fmt.Errorf("SSH policy test denied")
}

func offlineSSHIdentity(identity, from string) (sshserver.Identity, string, error) {
	var id sshserver.Identity
	set := func(value string) error {
		switch {
		case value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n"):
			return fmt.Errorf("invalid offline identity or source")
		case strings.HasPrefix(value, "device:"):
			if value == "device:" {
				return fmt.Errorf("device selector needs a device ID")
			}
			id.DeviceID = strings.TrimPrefix(value, "device:")
		case strings.Contains(value, "@"):
			id.Owner = value
		default:
			id.Device, id.Node = value, true
		}
		return nil
	}
	if err := set(identity); err != nil {
		return id, "", err
	}
	note := " (offline identity assertions; enrollment and routing not verified)"
	if from != "" {
		if ip, err := netip.ParseAddr(from); err == nil {
			if !meshaddr.IsDevice(ip) {
				return id, "", fmt.Errorf("source is outside the Mesh device ranges")
			}
			id.IP = ip.Unmap()
			note = " (offline: source IP does not establish a device identity)"
		} else {
			if strings.Contains(from, "@") {
				return id, "", fmt.Errorf("--from requires a Mesh IP, node name or device:<id>")
			}
			if err := set(from); err != nil {
				return id, "", err
			}
		}
	}
	return id, note, nil
}

func sshPolicyState(path string) string {
	p, err := sshserver.LoadPolicy(path)
	switch {
	case err != nil:
		return "invalid (denying all)"
	case p.Missing():
		return "no policy (denying all)"
	case len(p.Rules) == 0:
		return "empty policy (denying all)"
	default:
		return "configured"
	}
}

func ensureOwnSSHPolicy(ctx context.Context, path string, initialize bool) error {
	return offerOwnSSHPolicy(ctx, path, initialize, term.IsTerminal(int(os.Stdin.Fd())), os.Stdin, os.Stderr, sshPolicyOwner)
}

func offerOwnSSHPolicy(ctx context.Context, path string, initialize, interactive bool, in io.Reader, out io.Writer, owner func(context.Context) (string, error)) error {
	p, err := sshserver.LoadPolicy(path)
	if err != nil {
		return fmt.Errorf("read SSH policy: %w", err)
	}
	if p.Missing() {
		if !initialize && interactive {
			fmt.Fprintf(out, "SSH has no policy and denies all logins. Create a starter policy for the signed-in account owner (non-root only)? [y/N] ")
			answer, err := bufio.NewReader(in).ReadString('\n')
			if err != nil && err != io.EOF {
				return err
			}
			initialize = strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes")
		}
		if !initialize {
			return fmt.Errorf("%s; or repeat this command with --init-policy", p.MissingMessage())
		}
		c := sshPolicyCommand{path, out, out, owner, sshserver.LocalUser, os.Geteuid()}
		if err := c.run(ctx, []string{"init"}); err != nil {
			return err
		}
		p, err = sshserver.LoadPolicy(path)
		if err != nil {
			return err
		}
	}
	if !policyHasLocalUsers(p, os.Geteuid()) {
		return fmt.Errorf("SSH policy %s denies every usable local user; edit it or run meshscale ssh policy init --policy %q --force", path, path)
	}
	return nil
}

// Readiness is local: an allow rule also needs a usable existing login account.
// Identity enrollment and remote routing still require a real connection test.
func policyHasLocalUsers(p sshserver.Policy, serverUID int) bool {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			continue
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil || serverUID != 0 && uint32(serverUID) != uint32(uid) {
			continue
		}
		name, localUID, err := sshserver.LocalUser(fields[0])
		if err != nil {
			continue
		}
		for _, rule := range p.Rules {
			for _, selector := range rule.From {
				id, _, err := offlineSSHIdentity(selector, "")
				if selector == "*" {
					id = sshserver.Identity{}
				}
				if err == nil && p.Allows(id, name, localUID) {
					return true
				}
			}
		}
	}
	return false
}

func warnMissingSSHPolicy(logger *log.Logger, path string) {
	if p, err := sshserver.LoadPolicy(path); err == nil && p.Missing() {
		logger.Printf("WARNING: %s; upgrade: the former account-wide non-root default has been removed", p.MissingMessage())
	}
}
