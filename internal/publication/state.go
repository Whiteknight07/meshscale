// Package publication owns public DNS, Funnel resources and ACME certificates.
// It never adopts DNS records or resources created by another process.
package publication

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/localstate"
)

const ManagedComment = "managed-by: meshscale"
const ProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory"
const StagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

type OwnedRecord struct {
	ZoneID string          `json:"zone_id"`
	Record cfapi.DNSRecord `json:"record"`
}
type Funnel struct {
	TunnelAttempted  bool   `json:"tunnel_attempted,omitempty"`
	Nonce            string `json:"creation_nonce,omitempty"`
	OwnerEmail       string `json:"owner_email,omitempty"`
	Host             string `json:"host"`
	Origin           string `json:"origin"`
	OriginServerName string `json:"origin_server_name,omitempty"`
	TunnelID         string `json:"tunnel_id,omitempty"`
	DNSID            string `json:"dns_id,omitempty"`
	AppID            string `json:"access_app_id,omitempty"`
	OwnerOnly        bool   `json:"owner_only"`
	Enabled          bool   `json:"enabled"`
}
type Certificate struct {
	Name      string    `json:"name"`
	IP        string    `json:"ip"`
	Directory string    `json:"directory"`
	CertFile  string    `json:"cert_file"`
	KeyFile   string    `json:"key_file"`
	NotAfter  time.Time `json:"not_after"`
	RenewAt   time.Time `json:"renew_at"`
}
type State struct {
	DesiredAddresses map[string]string `json:"desired_addresses,omitempty"`
	Account          string            `json:"account"`
	Zone             cfapi.Zone        `json:"zone"`
	Records          []OwnedRecord     `json:"records,omitempty"`
	Funnel           *Funnel           `json:"funnel,omitempty"`
	Certificates     []Certificate     `json:"certificates,omitempty"`
}
type Store struct{ Dir string }

func (s Store) Load() (State, error) {
	var state State
	err := localstate.Read(filepath.Join(s.Dir, "state.json"), &state)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	// Older manifests stored an address per CA. The owned A ledger is the
	// authoritative last requested DNS value, even when a CA entry is stale.
	if state.DesiredAddresses == nil {
		state.DesiredAddresses = make(map[string]string)
		for _, cert := range state.Certificates {
			if _, ok := state.DesiredAddresses[cert.Name]; !ok {
				state.DesiredAddresses[cert.Name] = cert.IP
			}
		}
		for _, owned := range state.Records {
			if owned.Record.Type == "A" {
				if _, ok := state.DesiredAddresses[owned.Record.Name]; ok {
					state.DesiredAddresses[owned.Record.Name] = owned.Record.Content
				}
			}
		}
	}
	return state, nil
}
func (s Store) Save(state State) error {
	return localstate.Write(filepath.Join(s.Dir, "state.json"), state)
}

var labelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func Label(name string) (string, error) {
	if !labelPattern.MatchString(name) {
		return "", fmt.Errorf("device name %q must be a single lowercase DNS label", name)
	}
	return name, nil
}

// validZone checks the account's zone name before it reaches DNS records,
// Access domains or certificate names.
func validZone(zone string) error {
	for _, label := range strings.Split(zone, ".") {
		if !labelPattern.MatchString(label) {
			return fmt.Errorf("invalid publication zone %q", zone)
		}
	}
	return nil
}

func Host(name, namespace, zone string) (string, error) {
	if _, err := Label(name); err != nil {
		return "", err
	}
	if err := validZone(zone); err != nil {
		return "", err
	}
	if namespace != "mesh" {
		return "", fmt.Errorf("invalid publication namespace")
	}
	host := name + "." + namespace + "." + zone
	if len(host) > 253 {
		return "", fmt.Errorf("publication hostname too long")
	}
	return host, nil
}

// FunnelHost stays one label below the zone so Universal SSL's wildcard covers
// it. Never silently turn a suffix into another DNS namespace.
func FunnelHost(name, suffix, zone string) (string, error) {
	if _, err := Label(name); err != nil {
		return "", err
	}
	if suffix == "" {
		suffix = "-funnel"
	}
	label, err := Label(name + suffix)
	if err != nil {
		return "", fmt.Errorf("Funnel name and suffix must form one DNS label: %w", err)
	}
	if err := validZone(zone); err != nil {
		return "", err
	}
	host := label + "." + zone
	if len(host) > 253 {
		return "", fmt.Errorf("Funnel hostname too long")
	}
	return host, nil
}

func creationNonce() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate creation nonce: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}
func creationMarker(nonce string) string { return " meshscale-create:" + nonce }
func accessApplication(f *Funnel) cfapi.PublicApplication {
	rule, _ := json.Marshal(map[string]string{"email": f.OwnerEmail})
	return cfapi.PublicApplication{Name: "meshscale Funnel: " + f.Host + creationMarker(f.Nonce), Type: "self_hosted", Domain: f.Host, SessionDuration: "24h", Policies: []cfapi.EnrollmentPolicy{{Name: "meshscale owner only", Decision: "allow", Precedence: 1, Include: []cfapi.AccessRule{{"email": rule}}, Exclude: []cfapi.AccessRule{}, Require: []cfapi.AccessRule{}}}}
}
func tunnelName(f *Funnel) string { return "meshscale-funnel-" + f.Nonce }
