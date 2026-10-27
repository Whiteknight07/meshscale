package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/names"
	"github.com/Whiteknight07/meshscale/internal/publication"
)

func init() {
	register(&command{name: "cert", short: "issue or reuse an ACME DNS-01 certificate for this Mesh device", run: runCert})
}
func runCert(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "rm" {
		return runCertRemove(ctx, args[1:])
	}
	name := ""
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		name = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet("cert", flag.ContinueOnError)
	zone := fs.String("zone", "", "active Cloudflare zone; pinned after first publication")
	staging := fs.Bool("staging", false, "use Let's Encrypt staging (certificates are not publicly trusted)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() > 1 || name != "" && fs.NArg() > 0 {
		return fmt.Errorf("usage: meshscale cert [name] [--zone domain] [--staging] | meshscale cert rm <name>")
	}
	if fs.NArg() == 1 {
		name = fs.Arg(0)
	}
	account, tokens, err := resolveCredentials()
	if err != nil {
		return err
	}
	client := cfapi.New(tokens, version)
	localName, ip, err := publicationIdentity(ctx, client, account)
	if err != nil {
		return err
	}
	if name == "" {
		name = localName
	}
	request := publication.CertRequest{Name: name, IP: ip, Zone: *zone, Staging: *staging}
	dir, err := publicationDir()
	if err != nil {
		return err
	}
	var cert publication.Certificate
	err = publication.Request(ctx, dir, "POST", "/cert", request, &cert)
	if noServiceSocket(err) {
		release, err := localstate.Lock(dir)
		if err != nil {
			return fmt.Errorf("publication daemon is starting or stopping; retry: %w", err)
		}
		defer release()
		manager, err := publicationManager(client, account)
		if err != nil {
			return err
		}
		cert, err = manager.Cert(ctx, request)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(cert)
}
func publicationIdentity(ctx context.Context, client *cfapi.Client, account string) (name, ip string, err error) {
	local, _, err := selectedBackend()
	if err != nil {
		return "", "", err
	}
	ips, err := localSSHIPs(ctx, client, account, local)
	if err != nil {
		return "", "", fmt.Errorf("find local Mesh identity: %w", err)
	}
	for _, address := range ips {
		if address.Is4() {
			ip = address.String()
			break
		}
	}
	if ip == "" {
		return "", "", fmt.Errorf("local device has no IPv4 Mesh address")
	}
	snapshot, err := deviceSnapshot(ctx, client, account)
	if err != nil {
		return "", "", fmt.Errorf("resolve Mesh device name: %w", err)
	}
	for _, device := range snapshot.Devices {
		if device.IPv4 == ip {
			label, err := publicationName(device.Name)
			return label, ip, err
		}
	}
	return "", "", fmt.Errorf("local IPv4 Mesh address has no device in this account")
}

// Build reuses the Mesh DNS sanitizer without maintaining a second spelling.
func publicationName(raw string) (string, error) {
	records, err := names.Build([]names.Participant{{ID: "local", Name: raw}}, names.DefaultSuffix)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(records[0].Name, "."+names.DefaultSuffix), nil
}
func runCertRemove(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: meshscale cert rm <name>")
	}
	if _, err := publication.Label(args[0]); err != nil {
		return err
	}
	dir, err := publicationDir()
	if err != nil {
		return err
	}
	request := publication.CertRequest{Name: args[0]}
	err = publication.Request(ctx, dir, "DELETE", "/cert", request, nil)
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
		return manager.RemoveCert(ctx, args[0])
	}
	return err
}
