package publication

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/Whiteknight07/meshscale/internal/localstate"
	"golang.org/x/crypto/acme"
)

type TXT interface {
	Present(context.Context, string, string) (string, error)
	Cleanup(context.Context, string) error
}
type Bundle struct {
	Chain               []byte
	Key                 []byte
	NotBefore, NotAfter time.Time
}
type Issuer interface {
	Issue(context.Context, string, string, TXT) (Bundle, error)
}
type Propagation interface {
	Wait(context.Context, string, string) error
}

// DNSPropagation waits until public resolvers see the exact challenge value.
// A bounded timeout tolerates caches without issuing prematurely to the CA.
type DNSPropagation struct {
	Resolvers []*net.Resolver
	Interval  time.Duration
}

func (p DNSPropagation) Wait(ctx context.Context, name, value string) error {
	interval := p.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	resolvers := p.Resolvers
	if len(resolvers) == 0 {
		for _, server := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
			resolvers = append(resolvers, &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, server)
			}})
		}
	}
	for {
		visible := true
		for _, resolver := range resolvers {
			entries, err := resolver.LookupTXT(ctx, name)
			if err != nil || !slices.Contains(entries, value) {
				visible = false
				break
			}
		}
		if visible {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("wait for public DNS TXT %s: %w", name, ctx.Err())
		case <-timer.C:
		}
	}
}

type ACME struct {
	Dir         string
	Propagation Propagation
}

func (a *ACME) Issue(ctx context.Context, name, directory string, txt TXT) (bundle Bundle, err error) {
	if directory != ProductionDirectory && directory != StagingDirectory {
		return bundle, fmt.Errorf("unsupported ACME directory")
	}
	key, err := a.accountKey(directory)
	if err != nil {
		return bundle, err
	}
	client := &acme.Client{Key: key, DirectoryURL: directory, UserAgent: "meshscale"}
	// The account key persists, so every issuance after the first finds the
	// account already registered.
	if _, err = client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return bundle, fmt.Errorf("register ACME account: %w", err)
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(name))
	if err != nil {
		return bundle, fmt.Errorf("create ACME order: %w", err)
	}
	for _, authURL := range order.AuthzURLs {
		auth, err := client.GetAuthorization(ctx, authURL)
		if err != nil {
			return bundle, fmt.Errorf("get ACME authorization: %w", err)
		}
		if auth.Status == acme.StatusValid {
			continue
		}
		var challenge *acme.Challenge
		for _, c := range auth.Challenges {
			if c.Type == "dns-01" {
				challenge = c
				break
			}
		}
		if challenge == nil {
			return bundle, fmt.Errorf("ACME did not offer DNS-01")
		}
		value, err := client.DNS01ChallengeRecord(challenge.Token)
		if err != nil {
			return bundle, fmt.Errorf("build ACME DNS-01 value: %w", err)
		}
		id, err := txt.Present(ctx, "_acme-challenge."+name, value)
		if err != nil {
			return bundle, fmt.Errorf("present ACME TXT: %w", err)
		}
		// Also runs on propagation/validation failure, using an uncancelled deadline.
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if cleanupErr := txt.Cleanup(cleanupCtx, id); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("cleanup ACME TXT %s: %w", id, cleanupErr))
			}
		}()
		propagation := a.Propagation
		if propagation == nil {
			propagation = DNSPropagation{}
		}
		waitCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		err = propagation.Wait(waitCtx, "_acme-challenge."+name, value)
		cancel()
		if err != nil {
			return bundle, err
		}
		if _, err = client.Accept(ctx, challenge); err != nil {
			return bundle, fmt.Errorf("accept ACME DNS-01: %w", err)
		}
		if _, err = client.WaitAuthorization(ctx, authURL); err != nil {
			return bundle, fmt.Errorf("validate ACME DNS-01: %w", err)
		}
	}
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return bundle, fmt.Errorf("wait for ACME order: %w", err)
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return bundle, fmt.Errorf("generate certificate key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{}, DNSNames: []string{name}}, certKey)
	if err != nil {
		return bundle, fmt.Errorf("create certificate request: %w", err)
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return bundle, fmt.Errorf("finalize ACME certificate: %w", err)
	}
	if len(chain) == 0 {
		return bundle, fmt.Errorf("ACME returned no certificate")
	}
	for _, der := range chain {
		bundle.Chain = append(bundle.Chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	rawKey, err := x509.MarshalPKCS8PrivateKey(certKey)
	if err != nil {
		return bundle, fmt.Errorf("encode certificate key: %w", err)
	}
	bundle.Key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rawKey})
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return bundle, fmt.Errorf("parse issued certificate: %w", err)
	}
	bundle.NotBefore, bundle.NotAfter = leaf.NotBefore, leaf.NotAfter
	return bundle, nil
}
func (a *ACME) accountKey(directory string) (crypto.Signer, error) {
	sum := sha256.Sum256([]byte(directory))
	path := filepath.Join(a.Dir, "account-"+hex.EncodeToString(sum[:8])+".key")
	var saved struct {
		Key []byte `json:"key"`
	}
	err := localstate.Read(path, &saved)
	if err == nil {
		key, err := x509.ParsePKCS8PrivateKey(saved.Key)
		if err != nil {
			return nil, fmt.Errorf("parse ACME account key: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("ACME account key is not a signer")
		}
		return signer, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("load ACME account key: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ACME account key: %w", err)
	}
	saved.Key, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal ACME account key: %w", err)
	}
	if err = localstate.Write(path, saved); err != nil {
		return nil, fmt.Errorf("save ACME account key: %w", err)
	}
	return key, nil
}
func validateBundle(name string, b Bundle) error {
	pair, err := tls.X509KeyPair(b.Chain, b.Key)
	if err != nil {
		return fmt.Errorf("validate certificate/key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse leaf certificate: %w", err)
	}
	if err := leaf.VerifyHostname(name); err != nil {
		return fmt.Errorf("validate certificate hostname: %w", err)
	}
	if !leaf.NotAfter.Equal(b.NotAfter) || !leaf.NotBefore.Equal(b.NotBefore) || !b.NotAfter.After(time.Now()) || !b.NotAfter.After(b.NotBefore) || b.NotBefore.After(time.Now().Add(5*time.Minute)) {
		return fmt.Errorf("invalid issued certificate validity")
	}
	return nil
}
