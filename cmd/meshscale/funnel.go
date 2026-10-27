package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/publication"
)

func init() {
	register(&command{name: "funnel", short: "publish a localhost HTTP(S) service through Cloudflare Tunnel", run: runFunnel})
}
func runFunnel(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshscale funnel <port> [--name device] [--funnel-suffix=-funnel] [--zone domain] [--https] [--access-owner-only] | funnel off | funnel status")
	}
	dir, err := publicationDir()
	if err != nil {
		return err
	}
	if args[0] == "off" || args[0] == "status" {
		if len(args) != 1 {
			return fmt.Errorf("usage: meshscale funnel %s", args[0])
		}
		method, path := "GET", "/status"
		var status publication.Status
		var out any = &status
		if args[0] == "off" {
			method, path, out = "DELETE", "/funnel", nil
		}
		err := publication.Request(ctx, dir, method, path, nil, out)
		if noServiceSocket(err) {
			release, err := localstate.Lock(dir)
			if err != nil {
				return fmt.Errorf("publication daemon is starting or stopping; retry: %w", err)
			}
			defer release()
			account, tokens, err := resolveCredentials()
			if err != nil {
				return err
			}
			manager, err := publicationManager(cfapi.New(tokens, version), account)
			if err != nil {
				return err
			}
			if method == "DELETE" {
				err = manager.Off(ctx)
			} else {
				status = manager.Status()
			}
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if method == "DELETE" {
			fmt.Println("Funnel removed (tunnel, owned DNS and Access application).")
			return nil
		}
		return json.NewEncoder(os.Stdout).Encode(status)
	}
	port, err := strconv.Atoi(args[0])
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	fs := flag.NewFlagSet("funnel", flag.ContinueOnError)
	name := fs.String("name", "", "device label (defaults to local Mesh name)")
	suffix := fs.String("funnel-suffix", "-funnel", "suffix appended within one DNS label; covered by Universal SSL")
	zone := fs.String("zone", "", "active Cloudflare zone; pinned after first publication")
	https := fs.Bool("https", false, "use TLS with full certificate verification to the localhost origin")
	originName := fs.String("origin-server-name", "", "TLS origin hostname (default: <name>.mesh.<zone>); verification is always enabled")
	owner := fs.Bool("access-owner-only", false, "require the signed-in account owner's email through Cloudflare Access")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected Funnel arguments")
	}
	if *name == "" {
		account, tokens, err := resolveCredentials()
		if err != nil {
			return err
		}
		identity, _, err := publicationIdentity(ctx, cfapi.New(tokens, version), account)
		if err != nil {
			return err
		}
		*name = identity
	}
	var funnel publication.Funnel
	err = publication.Request(ctx, dir, "PUT", "/funnel", publication.FunnelRequest{Name: *name, Suffix: *suffix, Port: port, HTTPS: *https, OriginServerName: *originName, OwnerOnly: *owner, Zone: *zone}, &funnel)
	if noServiceSocket(err) {
		return fmt.Errorf("funnel requires the upgraded meshscale daemon; start or restart meshscale.service: %w", err)
	}
	if err != nil {
		return err
	}
	fmt.Printf("https://%s -> %s (owner-only Access: %t)\nPublic HTTPS uses the zone's Universal SSL wildcard; see docs/funnel.md.\n", funnel.Host, funnel.Origin, funnel.OwnerOnly)
	return nil
}
