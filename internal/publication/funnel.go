package publication

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

type Tunnels interface {
	FindPublicTunnel(context.Context, string, string) (cfapi.PublicTunnel, error)
	FindPublicApplication(context.Context, string, cfapi.PublicApplication) (cfapi.PublicApplication, error)
	PublicTunnel(context.Context, string, string) (cfapi.PublicTunnel, error)
	PublicApplication(context.Context, string, string) (cfapi.PublicApplication, error)
	CreatePublicTunnel(context.Context, string, string) (cfapi.PublicTunnel, error)
	ConfigurePublicTunnel(context.Context, string, string, string, string, *cfapi.TunnelOrigin) error
	Organization(context.Context, string) (cfapi.Organization, error)
	PublicTunnelToken(context.Context, string, string) (string, error)
	DeletePublicTunnel(context.Context, string, string) error
	CreatePublicApplication(context.Context, string, cfapi.PublicApplication) (cfapi.PublicApplication, error)
	DeletePublicApplication(context.Context, string, string) error
}
type Manager struct {
	DNS              DNS
	Tunnels          Tunnels
	Process          Process
	ACME             Issuer
	Store            Store
	Owner            func(context.Context) (string, error)
	mu               sync.Mutex
	issueMu          sync.Mutex // Serializes ACME issuance and certificate removal.
	statusMu         sync.RWMutex
	snapshot         Status
	state            State
	parent           context.Context
	wake             chan struct{}
	lastRenewalError string
	retryRenew       map[string]time.Time
}

func New(store Store, account string, dns DNS, tunnels Tunnels, process Process, issuer Issuer) (*Manager, error) {
	state, err := store.Load()
	if err != nil {
		return nil, fmt.Errorf("load publication state: %w", err)
	}
	if state.Account != "" && state.Account != account {
		return nil, fmt.Errorf("publication state belongs to another Cloudflare account")
	}
	state.Account = account
	m := &Manager{Store: store, DNS: dns, Tunnels: tunnels, Process: process, ACME: issuer, state: state, wake: make(chan struct{}, 1), retryRenew: make(map[string]time.Time)}
	m.updateStatus()
	return m, nil
}
func (m *Manager) save() error {
	defer m.updateStatus()
	if err := m.Store.Save(m.state); err != nil {
		return fmt.Errorf("save publication state: %w", err)
	}
	return nil
}
func (m *Manager) zone(ctx context.Context, preferred string) error {
	if m.state.Zone.ID != "" {
		if preferred != "" && preferred != m.state.Zone.Name {
			return fmt.Errorf("publication zone is pinned to %s", m.state.Zone.Name)
		}
		return nil
	}
	z, err := SelectZone(ctx, m.DNS, m.state.Account, preferred)
	if err != nil {
		return err
	}
	m.state.Zone = z
	return m.save()
}

type FunnelRequest struct {
	Name             string `json:"name"`
	Suffix           string `json:"funnel_suffix,omitempty"`
	Port             int    `json:"port"`
	HTTPS            bool   `json:"https"`
	OriginServerName string `json:"origin_server_name,omitempty"`
	OwnerOnly        bool   `json:"owner_only"`
	Zone             string `json:"zone,omitempty"`
}

func (m *Manager) Enable(ctx context.Context, r FunnelRequest) (result *Funnel, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.Port < 1 || r.Port > 65535 {
		return nil, fmt.Errorf("port must be between 1 and 65535")
	}
	if _, err := FunnelHost(r.Name, r.Suffix, "example.invalid"); err != nil {
		return nil, err
	}
	if m.parent == nil {
		return nil, fmt.Errorf("Funnel requires a running meshscale daemon")
	}
	if err := m.Process.Check(); err != nil {
		return nil, err
	}
	if err := m.zone(ctx, r.Zone); err != nil {
		return nil, err
	}
	host, err := FunnelHost(r.Name, r.Suffix, m.state.Zone.Name)
	if err != nil {
		return nil, err
	}
	scheme := "http"
	if r.HTTPS {
		scheme = "https"
	}
	origin := fmt.Sprintf("%s://127.0.0.1:%d", scheme, r.Port)
	serverName := r.OriginServerName
	if r.HTTPS && serverName == "" {
		serverName, err = Host(r.Name, "mesh", m.state.Zone.Name)
		if err != nil {
			return nil, err
		}
	}
	if serverName != "" {
		if !r.HTTPS {
			return nil, fmt.Errorf("origin server name requires --https")
		}
		if len(serverName) > 253 {
			return nil, fmt.Errorf("origin server name is too long")
		}
		for _, label := range strings.Split(serverName, ".") {
			if _, err := Label(label); err != nil {
				return nil, fmt.Errorf("invalid origin server name: %w", err)
			}
		}
	}
	if f := m.state.Funnel; f != nil {
		if f.Enabled && f.Host == host && f.Origin == origin && f.OwnerOnly == r.OwnerOnly && f.OriginServerName == serverName {
			result := *f
			return &result, nil
		}
		return nil, fmt.Errorf("a Funnel is already configured; run meshscale funnel off first")
	}
	// Journal every ID before progressing. Incomplete resources remain available
	// to off after interruption, instead of broad discovery or name-based deletes.
	nonce, err := creationNonce()
	if err != nil {
		return nil, err
	}
	f := &Funnel{Nonce: nonce, Host: host, Origin: origin, OriginServerName: serverName, OwnerOnly: r.OwnerOnly}
	m.state.Funnel = f
	if err := m.save(); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			defer cancel()
			if cleanupErr := m.off(cleanupCtx); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("rollback incomplete; retry funnel off: %w", cleanupErr))
			}
		}
	}()
	options := &cfapi.TunnelOrigin{OriginServerName: serverName}
	if r.OwnerOnly {
		if m.Owner == nil {
			return nil, fmt.Errorf("cannot identify the account owner")
		}
		email, err := m.Owner(ctx)
		if err != nil {
			return nil, fmt.Errorf("resolve Access owner: %w", err)
		}
		address, err := mail.ParseAddress(email)
		if err != nil || address.Address != email {
			return nil, fmt.Errorf("invalid account owner email")
		}
		f.OwnerEmail = email
		if err := m.save(); err != nil {
			return nil, err
		}
		intended := accessApplication(f)
		app, err := m.Tunnels.CreatePublicApplication(ctx, m.state.Account, intended)
		if err != nil {
			return nil, fmt.Errorf("create owner-only Access application: %w", err)
		}
		if err := cfapi.VerifyPublicApplication(app, intended); err != nil {
			return nil, err
		}
		if app.ID == "" {
			return nil, fmt.Errorf("created Access application has no ID")
		}

		f.AppID = app.ID
		if err = m.save(); err != nil {
			return nil, err
		}
		org, err := m.Tunnels.Organization(ctx, m.state.Account)
		if err != nil {
			return nil, fmt.Errorf("get Access organization: %w", err)
		}
		team := strings.TrimSuffix(org.AuthDomain, ".cloudflareaccess.com")
		if app.AUD == "" || team == "" || team == org.AuthDomain || strings.ContainsAny(team, "./ @\t\n") {
			return nil, fmt.Errorf("the Access application has no valid audience/team")
		}
		options.Access = &cfapi.TunnelAccess{TeamName: team, AudTag: []string{app.AUD}, Required: true}
	}
	f.TunnelAttempted = true
	if err := m.save(); err != nil {
		return nil, err
	}
	tunnel, err := m.Tunnels.CreatePublicTunnel(ctx, m.state.Account, tunnelName(f))
	if err != nil {
		return nil, fmt.Errorf("create Funnel tunnel: %w", err)
	}
	if tunnel.ID == "" || tunnel.Name != tunnelName(f) {
		return nil, fmt.Errorf("created tunnel ownership marker mismatch")
	}
	f.TunnelID = tunnel.ID
	if err = m.save(); err != nil {
		return nil, err
	}
	if err = m.Tunnels.ConfigurePublicTunnel(ctx, m.state.Account, f.TunnelID, host, origin, options); err != nil {
		return nil, fmt.Errorf("configure Funnel ingress: %w", err)
	}
	token, err := m.Tunnels.PublicTunnelToken(ctx, m.state.Account, f.TunnelID)
	if err != nil {
		return nil, fmt.Errorf("get Funnel token: %w", err)
	}
	// Start the connector before publishing DNS. Access, if selected, is already
	// configured before this hostname can reach an origin.
	if err = m.Process.Start(m.parent, token); err != nil {
		return nil, fmt.Errorf("start Funnel connector: %w", err)
	}
	f.DNSID, err = m.createRecord(ctx, cfapi.DNSRecord{Type: "CNAME", Name: host, Content: tunnel.ID + ".cfargotunnel.com", Proxied: true})
	if err != nil {
		return nil, err
	}
	f.Enabled = true
	if err = m.save(); err != nil {
		return nil, err
	}
	resultCopy := *f
	return &resultCopy, nil
}
func (m *Manager) Off(ctx context.Context) error { m.mu.Lock(); defer m.mu.Unlock(); return m.off(ctx) }
func (m *Manager) off(ctx context.Context) error {
	f := m.state.Funnel
	if f == nil {
		return nil
	}
	f.Enabled = false
	// Persist disabled before stopping, so restart cannot reopen a partial off.
	if err := m.save(); err != nil {
		return err
	}
	if m.Process != nil {
		m.Process.Stop()
	}
	// Recover any POST that committed before its returned ID could be saved.
	if err := m.recoverPendingRecords(ctx); err != nil {
		return err
	}
	if f.DNSID == "" {
		for _, owned := range m.state.Records {
			if owned.Record.Name == f.Host && owned.Record.Type == "CNAME" {
				f.DNSID = owned.Record.ID
			}
		}
	}
	if f.TunnelID == "" && f.TunnelAttempted {
		tunnel, err := m.Tunnels.FindPublicTunnel(ctx, m.state.Account, tunnelName(f))
		if err != nil {
			return fmt.Errorf("recover Funnel tunnel: %w", err)
		}
		f.TunnelID = tunnel.ID
		if err := m.save(); err != nil {
			return err
		}
	}
	if f.AppID == "" && f.OwnerEmail != "" {
		app, err := m.Tunnels.FindPublicApplication(ctx, m.state.Account, accessApplication(f))
		if err != nil {
			return fmt.Errorf("recover Funnel Access application: %w", err)
		}
		f.AppID = app.ID
		if err := m.save(); err != nil {
			return err
		}
	}
	// DNS must be gone before deleting Access; a failure leaves protection intact.
	if f.DNSID != "" {
		if err := m.deleteFunnelRecord(ctx, f.DNSID); err != nil {
			return err
		}
		f.DNSID = ""
		if err := m.save(); err != nil {
			return err
		}
	}
	if f.TunnelID != "" {
		if f.Nonce == "" {
			return fmt.Errorf("Funnel tunnel has no creation nonce; refusing deletion")
		}
		current, err := m.Tunnels.PublicTunnel(ctx, m.state.Account, f.TunnelID)
		if err != nil && !cfapi.IsMissing(err) {
			return fmt.Errorf("verify Funnel tunnel: %w", err)
		}
		if err == nil && (current.ID != f.TunnelID || current.Name != tunnelName(f)) {
			return fmt.Errorf("Funnel tunnel ownership marker mismatch; refusing deletion")
		}
		if err == nil {
			if err := m.Tunnels.DeletePublicTunnel(ctx, m.state.Account, f.TunnelID); err != nil && !cfapi.IsMissing(err) {
				return fmt.Errorf("delete Funnel tunnel: %w", err)
			}
		}
		f.TunnelID = ""
		f.TunnelAttempted = false
		if err := m.save(); err != nil {
			return err
		}
	}
	if f.AppID != "" {
		if f.Nonce == "" {
			return fmt.Errorf("Funnel Access application has no creation nonce; refusing deletion")
		}
		current, err := m.Tunnels.PublicApplication(ctx, m.state.Account, f.AppID)
		if err != nil && !cfapi.IsMissing(err) {
			return fmt.Errorf("verify Funnel Access application: %w", err)
		}
		if err == nil {
			if current.ID != f.AppID {
				return fmt.Errorf("access application ID mismatch; refusing deletion")
			}
			if verifyErr := cfapi.VerifyPublicApplication(current, accessApplication(f)); verifyErr != nil {
				return verifyErr
			}
			if err := m.Tunnels.DeletePublicApplication(ctx, m.state.Account, f.AppID); err != nil && !cfapi.IsMissing(err) {
				return fmt.Errorf("delete Funnel Access application: %w", err)
			}
		}
		f.AppID = ""
		f.OwnerEmail = ""
		if err := m.save(); err != nil {
			return err
		}
	}
	m.state.Funnel = nil
	return m.save()
}

type Status struct {
	Zone         string        `json:"zone"`
	Funnel       *Funnel       `json:"funnel"`
	Running      bool          `json:"running"`
	ProcessError string        `json:"process_error,omitempty"`
	Certificates []Certificate `json:"certificates"`
	RenewalError string        `json:"renewal_error,omitempty"`
}

// updateStatus is called with mu held, or before the manager is published.
func (m *Manager) updateStatus() {
	s := Status{Zone: m.state.Zone.Name, Certificates: append([]Certificate(nil), m.state.Certificates...), RenewalError: m.lastRenewalError}
	if m.state.Funnel != nil {
		f := *m.state.Funnel
		s.Funnel = &f
	}
	m.statusMu.Lock()
	m.snapshot = s
	m.statusMu.Unlock()
}
func (m *Manager) Status() Status {
	m.statusMu.RLock()
	s := m.snapshot
	s.Certificates = append([]Certificate(nil), s.Certificates...)
	if s.Funnel != nil {
		f := *s.Funnel
		s.Funnel = &f
	}
	m.statusMu.RUnlock()
	if m.Process != nil {
		s.Running, s.ProcessError = m.Process.Status()
	}
	return s
}
func ValidateOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("parse origin: %w", err)
	}
	if u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Scheme != "http" && u.Scheme != "https" || u.User != nil || strings.Trim(u.Path, "/") != "" {
		return fmt.Errorf("origin must be localhost HTTP(S) with a port")
	}
	return nil
}

// Deletion can have committed its ledger update before a crash cleared DNSID.
// In that case there is nothing left that this process is authorized to delete.
func (m *Manager) deleteFunnelRecord(ctx context.Context, id string) error {
	for _, owned := range m.state.Records {
		if owned.Record.ID == id {
			return m.deleteRecord(ctx, id)
		}
	}
	return nil
}

// restoreFunnel rechecks remote ownership and owner-only policy before a saved
// connector can resume. Reassert ingress, including connector-side JWT checks,
// so an externally edited tunnel configuration cannot silently remove Access.
func (m *Manager) restoreFunnel(ctx context.Context, f *Funnel) error {
	if cfapi.CreationNonce(tunnelName(f)) == "" || f.TunnelID == "" {
		return fmt.Errorf("Funnel tunnel has no creation nonce or ID; refusing restart")
	}
	current, err := m.Tunnels.PublicTunnel(ctx, m.state.Account, f.TunnelID)
	if err != nil {
		return fmt.Errorf("verify Funnel before restart: %w", err)
	}
	if current.ID != f.TunnelID || current.Name != tunnelName(f) {
		return fmt.Errorf("Funnel tunnel ownership mismatch; refusing restart")
	}
	options := &cfapi.TunnelOrigin{OriginServerName: f.OriginServerName}
	if f.OwnerOnly {
		if f.AppID == "" || f.OwnerEmail == "" {
			return fmt.Errorf("owner-only Funnel has no Access identity; refusing restart")
		}
		app, err := m.Tunnels.PublicApplication(ctx, m.state.Account, f.AppID)
		if err != nil {
			return fmt.Errorf("verify Funnel Access before restart: %w", err)
		}
		if app.ID != f.AppID {
			return fmt.Errorf("Funnel Access ID mismatch; refusing restart")
		}
		if err := cfapi.VerifyPublicApplication(app, accessApplication(f)); err != nil {
			return err
		}
		org, err := m.Tunnels.Organization(ctx, m.state.Account)
		if err != nil {
			return fmt.Errorf("get Access organization: %w", err)
		}
		team := strings.TrimSuffix(org.AuthDomain, ".cloudflareaccess.com")
		if app.AUD == "" || team == "" || team == org.AuthDomain || strings.ContainsAny(team, "./ @\t\n") {
			return fmt.Errorf("the Access application has no valid audience/team")
		}
		options.Access = &cfapi.TunnelAccess{TeamName: team, AudTag: []string{app.AUD}, Required: true}
	}
	if err := m.Tunnels.ConfigurePublicTunnel(ctx, m.state.Account, f.TunnelID, f.Host, f.Origin, options); err != nil {
		return fmt.Errorf("restore Funnel ingress: %w", err)
	}
	return nil
}
