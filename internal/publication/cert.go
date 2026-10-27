package publication

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

type CertRequest struct {
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Zone    string `json:"zone,omitempty"`
	Staging bool   `json:"staging"`
}

func (m *Manager) Cert(ctx context.Context, r CertRequest) (Certificate, error) {
	if _, err := Label(r.Name); err != nil {
		return Certificate{}, err
	}
	ip, err := netip.ParseAddr(r.IP)
	if err != nil || !meshaddr.IsIPv4(ip) {
		return Certificate{}, fmt.Errorf("certificate DNS requires this device's IPv4 Mesh address in 100.96.0.0/12")
	}
	m.issueMu.Lock()
	defer m.issueMu.Unlock()
	directory := ProductionDirectory
	if r.Staging {
		directory = StagingDirectory
	}
	m.mu.Lock()
	if err := m.zone(ctx, r.Zone); err != nil {
		m.mu.Unlock()
		return Certificate{}, err
	}
	name, err := Host(r.Name, "mesh", m.state.Zone.Name)
	if err != nil {
		m.mu.Unlock()
		return Certificate{}, err
	}
	if m.state.DesiredAddresses == nil {
		m.state.DesiredAddresses = make(map[string]string)
	}
	// This is hostname state, independent of the production/staging certificate.
	if m.state.DesiredAddresses[name] != r.IP {
		m.state.DesiredAddresses[name] = r.IP
		if err := m.save(); err != nil {
			m.mu.Unlock()
			return Certificate{}, err
		}
	}
	for _, cert := range m.state.Certificates {
		if cert.Name == name && cert.Directory == directory && cert.IP == r.IP && time.Now().Before(cert.RenewAt) {
			m.mu.Unlock()
			if err := validSavedCertificate(cert); err != nil {
				return Certificate{}, err
			}
			return cert, nil
		}
	}
	m.mu.Unlock()
	return m.issue(ctx, name, r.IP, directory)
}
func (m *Manager) Present(ctx context.Context, name, value string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.createRecord(ctx, cfapi.DNSRecord{Type: "TXT", Name: name, Content: value})
}
func (m *Manager) Cleanup(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deleteRecord(ctx, id)
}
func (m *Manager) issue(ctx context.Context, name, ip, directory string) (Certificate, error) {
	var cert Certificate
	m.mu.Lock()
	_, err := m.createRecord(ctx, cfapi.DNSRecord{Type: "A", Name: name, Content: ip})
	m.mu.Unlock()
	if err != nil {
		return cert, err
	}
	bundle, err := m.ACME.Issue(ctx, name, directory, m)
	if err != nil {
		return cert, fmt.Errorf("issue certificate for %s: %w", name, err)
	}
	if err := validateBundle(name, bundle); err != nil {
		return cert, err
	}
	// Commit a complete generation before publishing its paths in the manifest.
	// Readers can never observe a new certificate paired with an old private key.
	dir, err := os.MkdirTemp(m.Store.Dir, "cert-")
	if err != nil {
		return cert, fmt.Errorf("create certificate generation: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(dir)
		}
	}()
	cert = Certificate{Name: name, IP: ip, Directory: directory, CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem"), NotAfter: bundle.NotAfter, RenewAt: RenewalTime(bundle.NotBefore, bundle.NotAfter)}
	for path, data := range map[string][]byte{cert.CertFile: bundle.Chain, cert.KeyFile: bundle.Key} {
		if err := writePEM(path, data); err != nil {
			return Certificate{}, err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	i := slices.IndexFunc(m.state.Certificates, func(c Certificate) bool { return c.Name == name && c.Directory == directory })
	previous := append([]Certificate(nil), m.state.Certificates...)
	if i < 0 {
		m.state.Certificates = append(m.state.Certificates, cert)
	} else {
		m.state.Certificates[i] = cert
	}
	if err := m.save(); err != nil {
		m.state.Certificates = previous
		m.updateStatus()
		return Certificate{}, err
	}
	committed = true
	if i >= 0 {
		if err := m.removeGeneration(previous[i]); err != nil {
			return cert, err
		}
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return cert, nil
}
func writePEM(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create certificate material: %w", err)
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return fmt.Errorf("write certificate material: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close certificate material: %w", closeErr)
	}
	return nil
}
func validSavedCertificate(cert Certificate) error {
	for _, path := range []string{cert.CertFile, cert.KeyFile} {
		if err := localstate.Dir(filepath.Dir(path)); err != nil {
			return fmt.Errorf("validate certificate directory: %w", err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("read saved certificate material: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return fmt.Errorf("certificate material must be a regular mode 0600 file")
		}
	}
	chain, err := os.ReadFile(cert.CertFile)
	if err != nil {
		return fmt.Errorf("read certificate: %w", err)
	}
	key, err := os.ReadFile(cert.KeyFile)
	if err != nil {
		return fmt.Errorf("read certificate key: %w", err)
	}
	// The issued bounds are read from the leaf to validate the stored pair.
	return validateSavedPair(cert, chain, key)
}

// RenewalTime schedules one wake-up at two thirds of the issued lifetime,
// supporting short-lived ACME certificates without a fixed daily API poll.
func RenewalTime(notBefore, notAfter time.Time) time.Time {
	return notBefore.Add(notAfter.Sub(notBefore) * 2 / 3)
}
func (m *Manager) renew(ctx context.Context, now time.Time) time.Time {
	m.issueMu.Lock()
	defer m.issueMu.Unlock()
	m.mu.Lock()
	pending := append([]Certificate(nil), m.state.Certificates...)
	m.mu.Unlock()
	next := time.Time{}
	for _, cert := range pending {
		due := cert.RenewAt
		retryKey := cert.Name + "\x00" + cert.Directory
		m.mu.Lock()
		if retry := m.retryRenew[retryKey]; retry.After(due) {
			due = retry
		}
		m.mu.Unlock()
		if !now.Before(due) {
			attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			m.mu.Lock()
			ip := m.state.DesiredAddresses[cert.Name]
			m.mu.Unlock()
			if ip == "" {
				ip = cert.IP
			}
			replacement, err := m.issue(attemptCtx, cert.Name, ip, cert.Directory)
			cancel()
			m.mu.Lock()
			if err != nil {
				m.lastRenewalError = err.Error()
				due = now.Add(time.Hour)
				m.retryRenew[retryKey] = due
			} else {
				m.lastRenewalError = ""
				due = replacement.RenewAt
				delete(m.retryRenew, retryKey)
			}
			m.updateStatus()
			m.mu.Unlock()
		}
		if next.IsZero() || due.Before(next) {
			next = due
		}
	}
	return next
}

// removeGeneration accepts only a direct cert-* child of the private store.
// Lstat prevents following a substituted directory symlink.
func (m *Manager) removeGeneration(cert Certificate) error {
	dir, err := filepath.Abs(filepath.Dir(cert.CertFile))
	if err != nil {
		return err
	}
	root, err := filepath.Abs(m.Store.Dir)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil || filepath.Dir(rel) != "." || !strings.HasPrefix(rel, "cert-") || filepath.Dir(cert.KeyFile) != filepath.Dir(cert.CertFile) {
		return fmt.Errorf("refusing certificate generation outside publication store")
	}
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("certificate generation is not a directory")
	}
	return os.RemoveAll(dir)
}

// RemoveCert removes only ledger-owned A records and saved generations for name.
func (m *Manager) RemoveCert(ctx context.Context, name string) error {
	if _, err := Label(name); err != nil {
		return err
	}
	m.issueMu.Lock()
	defer m.issueMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.Zone.ID == "" {
		return nil
	}
	host, err := Host(name, "mesh", m.state.Zone.Name)
	if err != nil {
		return err
	}
	if err := m.recoverPendingRecords(ctx); err != nil {
		return err
	}
	for _, owned := range append([]OwnedRecord(nil), m.state.Records...) {
		if owned.Record.Name == host && owned.Record.Type == "A" {
			if err := m.deleteRecord(ctx, owned.Record.ID); err != nil {
				return err
			}
		}
	}
	previous := append([]Certificate(nil), m.state.Certificates...)
	previousAddress := m.state.DesiredAddresses[host]
	delete(m.state.DesiredAddresses, host)
	m.state.Certificates = slices.DeleteFunc(m.state.Certificates, func(c Certificate) bool { return c.Name == host })
	if err := m.save(); err != nil {
		m.state.Certificates = previous
		if previousAddress != "" {
			m.state.DesiredAddresses[host] = previousAddress
		}
		m.updateStatus()
		return err
	}
	for _, cert := range previous {
		if cert.Name == host {
			delete(m.retryRenew, cert.Name+"\x00"+cert.Directory)
			if err := m.removeGeneration(cert); err != nil {
				return err
			}
		}
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return nil
}

func validateSavedPair(cert Certificate, chain, key []byte) error {
	pair, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return fmt.Errorf("load saved certificate/key: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse saved certificate: %w", err)
	}
	return validateBundle(cert.Name, Bundle{Chain: chain, Key: key, NotBefore: leaf.NotBefore, NotAfter: cert.NotAfter})
}
