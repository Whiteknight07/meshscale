package publication

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

type DNS interface {
	PublicationZones(context.Context, string) ([]cfapi.Zone, error)
	PublicationRecordsByName(context.Context, string, string) ([]cfapi.DNSRecord, error)
	PublicationRecordCount(context.Context, string) (int, error)
	CreatePublicationRecord(context.Context, string, cfapi.DNSRecord) (cfapi.DNSRecord, error)
	UpdatePublicationRecord(context.Context, string, string, cfapi.DNSRecord) (cfapi.DNSRecord, error)
	PublicationRecord(context.Context, string, string) (cfapi.DNSRecord, error)
	DeletePublicationRecord(context.Context, string, string) error
}

// SelectZone requires an explicit choice when multiple active zones qualify.
// A saved choice is pinned thereafter.
func SelectZone(ctx context.Context, dns DNS, account, preferred string) (cfapi.Zone, error) {
	zones, err := dns.PublicationZones(ctx, account)
	if err != nil {
		return cfapi.Zone{}, fmt.Errorf("list zones: %w", err)
	}
	var eligible []cfapi.Zone
	for _, z := range zones {
		if z.Status != "active" || preferred != "" && z.Name != preferred {
			continue
		}
		if _, err := dns.PublicationRecordCount(ctx, z.ID); err != nil {
			return cfapi.Zone{}, fmt.Errorf("count records for %s: %w", z.Name, err)
		}
		eligible = append(eligible, z)
	}
	if len(eligible) == 0 {
		return cfapi.Zone{}, fmt.Errorf("no active Cloudflare zone in this account matching %q", preferred)
	}
	if len(eligible) > 1 {
		return cfapi.Zone{}, fmt.Errorf("multiple active Cloudflare zones qualify; choose one with --zone")
	}
	return eligible[0], nil
}
func (d *Manager) createRecord(ctx context.Context, r cfapi.DNSRecord) (string, error) {
	if !d.inNamespace(r.Name) {
		return "", fmt.Errorf("refusing DNS name outside the device namespace or configured Funnel hostname")
	}
	if err := d.recoverPendingRecords(ctx); err != nil {
		return "", err
	}
	for i, owned := range d.state.Records {
		if owned.ZoneID == d.state.Zone.ID && owned.Record.Type == r.Type && owned.Record.Name == r.Name && (r.Type != "TXT" || owned.Record.Content == r.Content) {
			current, err := d.DNS.PublicationRecord(ctx, owned.ZoneID, owned.Record.ID)
			if err == nil && sameRecord(current, owned.Record) {
				if current.Content == r.Content {
					return current.ID, nil
				}
				if cfapi.CreationNonce(owned.Record.Comment) == "" {
					return "", fmt.Errorf("DNS record %s has no creation nonce; refusing update", current.ID)
				}
				r.ID, r.Comment, r.TTL = current.ID, current.Comment, 60
				updated, err := d.DNS.UpdatePublicationRecord(ctx, owned.ZoneID, current.ID, r)
				if err != nil {
					return "", fmt.Errorf("update owned DNS: %w", err)
				}
				if !sameRecord(updated, r) {
					return "", fmt.Errorf("updated DNS ownership marker or payload mismatch")
				}
				d.state.Records[i].Record = updated
				return updated.ID, d.save()
			}
			if err != nil && !cfapi.IsMissing(err) {
				return "", fmt.Errorf("verify owned DNS: %w", err)
			}
			return "", fmt.Errorf("owned DNS record %s changed or disappeared; refusing to adopt a replacement", owned.Record.ID)
		}
	}
	records, err := d.DNS.PublicationRecordsByName(ctx, d.state.Zone.ID, r.Name)
	if err != nil {
		return "", fmt.Errorf("list DNS records: %w", err)
	}
	for _, other := range records {
		if other.Name == r.Name && r.Type != "TXT" {
			return "", fmt.Errorf("DNS name %s already exists; refusing to change or adopt it", r.Name)
		}
	}
	nonce, err := creationNonce()
	if err != nil {
		return "", err
	}
	r.Comment = ManagedComment + creationMarker(nonce)
	r.TTL = 60
	// Persist the exact attempted payload/nonce before a POST can commit remotely.
	index := len(d.state.Records)
	d.state.Records = append(d.state.Records, OwnedRecord{d.state.Zone.ID, r})
	if err := d.save(); err != nil {
		d.state.Records = d.state.Records[:index]
		return "", err
	}
	created, err := d.DNS.CreatePublicationRecord(ctx, d.state.Zone.ID, r)
	if err != nil {
		return "", fmt.Errorf("create DNS %s: %w", r.Name, err)
	}
	if created.ID == "" || !sameRecord(created, cfapi.DNSRecord{ID: created.ID, Type: r.Type, Name: r.Name, Content: r.Content, Proxied: r.Proxied, Comment: r.Comment}) {
		return "", fmt.Errorf("created DNS ownership marker or payload mismatch")
	}
	d.state.Records[index].Record = created
	if err := d.save(); err != nil {
		return created.ID, fmt.Errorf("persist created DNS %s (ID %s): %w", r.Name, created.ID, err)
	}
	return created.ID, nil
}
func (d *Manager) inNamespace(name string) bool {
	name = strings.TrimPrefix(name, "_acme-challenge.")
	meshSuffix := ".mesh." + d.state.Zone.Name
	if strings.HasSuffix(name, meshSuffix) {
		_, err := Label(strings.TrimSuffix(name, meshSuffix))
		return err == nil
	}
	if d.state.Funnel != nil && name == d.state.Funnel.Host {
		zoneSuffix := "." + d.state.Zone.Name
		if !strings.HasSuffix(name, zoneSuffix) {
			return false
		}
		_, err := Label(strings.TrimSuffix(name, zoneSuffix))
		return err == nil
	}
	return false
}
func sameRecord(a, b cfapi.DNSRecord) bool {
	return a.ID == b.ID && a.Name == b.Name && a.Type == b.Type && a.Content == b.Content && a.Proxied == b.Proxied && (cfapi.CreationNonce(b.Comment) != "" || b.Comment == ManagedComment) && a.Comment == b.Comment
}
func (d *Manager) deleteRecord(ctx context.Context, id string) error {
	i := slices.IndexFunc(d.state.Records, func(r OwnedRecord) bool { return r.Record.ID == id })
	if i < 0 {
		return fmt.Errorf("DNS ID %s is not in the local ownership ledger", id)
	}
	owned := d.state.Records[i]
	if cfapi.CreationNonce(owned.Record.Comment) == "" {
		return fmt.Errorf("DNS record %s has no creation nonce; refusing deletion", id)
	}
	current, err := d.DNS.PublicationRecord(ctx, owned.ZoneID, id)
	if err != nil && !cfapi.IsMissing(err) {
		return fmt.Errorf("read DNS before deletion: %w", err)
	}
	if err == nil {
		if !sameRecord(current, owned.Record) {
			return fmt.Errorf("DNS record %s changed externally; refusing deletion", id)
		}
		if err = d.DNS.DeletePublicationRecord(ctx, owned.ZoneID, id); err != nil && !cfapi.IsMissing(err) {
			return fmt.Errorf("delete owned DNS: %w", err)
		}
	}
	d.state.Records = slices.Delete(d.state.Records, i, i+1)
	return d.save()
}

// A blank ID is a durable pre-POST journal entry, never deletion authority.
func (d *Manager) recoverPendingRecords(ctx context.Context) error {
	for i := 0; i < len(d.state.Records); {
		owned := d.state.Records[i]
		if owned.Record.ID != "" {
			i++
			continue
		}
		if cfapi.CreationNonce(owned.Record.Comment) == "" {
			return fmt.Errorf("pending DNS creation nonce missing")
		}
		records, err := d.DNS.PublicationRecordsByName(ctx, owned.ZoneID, owned.Record.Name)
		if err != nil {
			return fmt.Errorf("recover pending DNS: %w", err)
		}
		var match cfapi.DNSRecord
		for _, candidate := range records {
			expected := owned.Record
			expected.ID = candidate.ID
			if candidate.ID != "" && sameRecord(candidate, expected) {
				if match.ID != "" {
					return fmt.Errorf("ambiguous pending DNS creation nonce")
				}
				match = candidate
			}
		}
		if match.ID == "" {
			d.state.Records = slices.Delete(d.state.Records, i, i+1)
		} else {
			d.state.Records[i].Record = match
			i++
		}
		if err := d.save(); err != nil {
			return err
		}
	}
	return nil
}
