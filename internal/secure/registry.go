package secure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/cfapi"
	"github.com/Whiteknight07/meshscale/internal/meshaddr"
	"github.com/Whiteknight07/meshscale/internal/names"
)

const listPrefix = "meshscale-secure-v1-"
const recordPrefix = "meshscale secure v1: "

type Record struct {
	ExitVersion    int        `json:"exit_version,omitempty"`
	OffersExit     bool       `json:"offers_exit_node,omitempty"`
	IPv4           netip.Addr `json:"ipv4,omitempty"`
	RegistrationID string     `json:"registration_id"`
	PublicKey      string     `json:"public_key"`
	Enabled        bool       `json:"enabled"`
}
type Directory interface {
	ListGatewayLists(context.Context, string) ([]cfapi.GatewayList, error)
	CreateGatewayList(context.Context, string, cfapi.GatewayList) (cfapi.GatewayList, error)
	UpdateGatewayList(context.Context, string, string, cfapi.GatewayList) (cfapi.GatewayList, error)
}

// Publish touches only this registration's record. Different devices never
// read-modify-write a common document. Key replacement requires explicit local
// key replacement and account credentials (the account owner is the trust root).
func Publish(ctx context.Context, api Directory, account string, record Record, meshIP netip.Addr) error {
	if record.RegistrationID == "" || strings.ContainsAny(record.RegistrationID, "/\r\n") {
		return fmt.Errorf("registration ID required")
	}
	if _, err := Address(account, record.PublicKey); err != nil {
		return err
	}
	if !meshaddr.IsIPv4(meshIP) {
		return fmt.Errorf("a Mesh IPv4 endpoint is required")
	}
	data, _ := json.Marshal(record)
	want := cfapi.GatewayList{
		Name:        listPrefix + record.RegistrationID,
		Type:        "IP",
		Description: recordPrefix + string(data),
		Items:       []cfapi.GatewayListItem{{Value: meshIP.String()}},
	}
	lists, err := api.ListGatewayLists(ctx, account)
	if err != nil {
		return fmt.Errorf("list secure key directory: %w", err)
	}
	var old *cfapi.GatewayList
	for i := range lists {
		if lists[i].Name != want.Name {
			continue
		}
		if old != nil || lists[i].ID == "" || lists[i].Type != "IP" ||
			!strings.HasPrefix(lists[i].Description, recordPrefix) {
			return fmt.Errorf("conflicting secure key record for registration")
		}
		old = &lists[i]
	}
	if old == nil {
		_, err = api.CreateGatewayList(ctx, account, want)
		if err != nil {
			return fmt.Errorf("publish secure key record: %w", err)
		}
		return nil
	}
	// Items in list summaries may be omitted. Endpoint identity always comes
	// from live registrations, so stale illustrative list items are harmless.
	if old.Description == want.Description {
		return nil
	}
	_, err = api.UpdateGatewayList(ctx, account, old.ID, want)
	if err != nil {
		return fmt.Errorf("update secure key record: %w", err)
	}
	return nil
}

// Records isolates invalid directory entries. Every duplicate name is excluded,
// including an otherwise valid entry, so list order never selects an identity.
func Records(ctx context.Context, api Directory, account string) ([]Record, []string, error) {
	lists, err := api.ListGatewayLists(ctx, account)
	if err != nil {
		return nil, nil, fmt.Errorf("list secure key directory: %w", err)
	}
	counts := map[string]int{}
	for _, l := range lists {
		if strings.HasPrefix(l.Name, listPrefix) {
			counts[l.Name]++
		}
	}
	var result []Record
	var warnings []string
	for _, l := range lists {
		if !strings.HasPrefix(l.Name, listPrefix) {
			continue
		}
		var r Record
		reason := ""
		switch {
		case counts[l.Name] > 1:
			reason = "duplicate name"
		case l.ID == "" || l.Type != "IP":
			reason = "missing ID or wrong list type"
		case !strings.HasPrefix(l.Description, recordPrefix):
			reason = "missing record marker"
		case json.Unmarshal([]byte(strings.TrimPrefix(l.Description, recordPrefix)), &r) != nil:
			reason = "malformed record JSON"
		case r.RegistrationID == "" || l.Name != listPrefix+r.RegistrationID:
			reason = "registration/name mismatch"
		default:
			if _, err := Address(account, r.PublicKey); err != nil {
				reason = "invalid public key"
			}
		}
		if reason != "" {
			warnings = append(warnings, fmt.Sprintf("secure directory list %q (%s): %s", l.Name, l.ID, reason))
			continue
		}
		if r.Enabled {
			result = append(result, r)
		}
	}
	return result, warnings, nil
}

type Peer struct {
	ExitVersion    int            `json:"exit_version,omitempty"`
	OffersExit     bool           `json:"offers_exit_node,omitempty"`
	IPv4           netip.Addr     `json:"ipv4,omitempty"`
	RegistrationID string         `json:"registration_id"`
	DeviceID       string         `json:"device_id"`
	Name           string         `json:"name"`
	Node           bool           `json:"node,omitempty"` // Name is an admin-set Mesh node name
	Owner          string         `json:"owner,omitempty"`
	PublicKey      string         `json:"public_key"`
	IP             netip.Addr     `json:"ip"`
	MeshIP         netip.Addr     `json:"mesh_ip"`
	Endpoint       netip.AddrPort `json:"endpoint"`
	AllowedIPs     []netip.Prefix `json:"allowed_ips"`
	DNSName        string         `json:"dns_name"`
}

// BuildPeers joins account-owned keys with active registrations. List items
// cannot override IPs, names, ownership, or device identity from that API.
//
// Anything ambiguous or invalid is excluded with a warning rather than failing
// the whole directory: every party to a duplicate registration, Mesh IP,
// public key, overlay address or IPv4 binding is dropped, since none of them
// can be trusted. If that drops this device, the supervisor's self check fails
// closed.
func BuildPeers(account string, records []Record, registrations []cfapi.Registration) ([]Peer, []string, error) {
	var warnings []string
	warn := func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) }

	active := map[string]cfapi.Registration{}
	claims := map[string]int{}
	byIP := map[netip.Addr][]string{}
	for _, r := range registrations {
		if r.DeletedAt != nil || r.RevokedAt != nil || (r.RegistrationType != "" && r.RegistrationType != "warp") {
			continue
		}
		claims[r.ID]++
		active[r.ID] = r
		if ip, err := netip.ParseAddr(r.VirtualIPv4); err == nil {
			byIP[ip] = append(byIP[ip], r.ID)
		}
	}
	for id, n := range claims {
		if n > 1 {
			delete(active, id)
			warn("registration %s is listed %d times; excluded", id, n)
		}
	}
	for ip, ids := range byIP {
		if len(ids) > 1 {
			for _, id := range ids {
				delete(active, id)
			}
			warn("Mesh IP %s is claimed by %d registrations; excluded", ip, len(ids))
		}
	}

	enabled := map[string]int{}
	for _, record := range records {
		if record.Enabled {
			enabled[record.RegistrationID]++
		}
	}
	for id, n := range enabled {
		if _, ok := active[id]; ok && n > 1 {
			delete(active, id)
			warn("registration %s has %d secure keys; excluded", id, n)
		}
	}
	var candidates []Peer
	for _, record := range records {
		r, ok := active[record.RegistrationID]
		if !record.Enabled || !ok {
			continue
		}
		peer, err := buildPeer(account, record, r)
		if err != nil {
			warn("secure key for %s excluded: %v", r.ID, err)
			continue
		}
		candidates = append(candidates, peer)
	}

	// Drop every party to a key, overlay address or IPv4 collision.
	uses := map[string]int{}
	for _, p := range candidates {
		uses["key "+p.PublicKey]++
		uses["address "+p.IP.String()]++
		if p.IPv4.IsValid() {
			uses["IPv4 "+p.IPv4.String()]++
		}
	}
	var peers []Peer
	var participants []names.Participant
	for _, p := range candidates {
		if uses["key "+p.PublicKey] > 1 || uses["address "+p.IP.String()] > 1 || p.IPv4.IsValid() && uses["IPv4 "+p.IPv4.String()] > 1 {
			warn("secure key for %s collides with another device; excluded", p.RegistrationID)
			continue
		}
		peers = append(peers, p)
		participants = append(participants, names.Participant{ID: p.RegistrationID, Name: p.Name, IPv6: p.IP.String()})
	}

	dns, err := names.Build(participants, "secure")
	if err != nil {
		return nil, warnings, err
	}
	byID := map[string]string{}
	for _, r := range dns {
		byID[r.ID] = r.Name
	}
	for i := range peers {
		peers[i].DNSName = byID[peers[i].RegistrationID]
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].RegistrationID < peers[j].RegistrationID })
	sort.Strings(warnings)
	return peers, warnings, nil
}

// buildPeer validates one enabled record against its active registration.
func buildPeer(account string, record Record, r cfapi.Registration) (Peer, error) {
	ip, err := netip.ParseAddr(r.VirtualIPv4)
	if err != nil || !meshaddr.IsIPv4(ip) || r.Device.ID == "" || r.ID == "" {
		return Peer{}, fmt.Errorf("incomplete secure registration")
	}
	overlayIP, err := Address(account, record.PublicKey)
	if err != nil {
		return Peer{}, err
	}
	var v4 netip.Addr
	if record.ExitVersion != 0 {
		if record.ExitVersion != 2 {
			return Peer{}, fmt.Errorf("unsupported exit record version")
		}
		if v4, err = IPv4Address(account, record.PublicKey); err != nil {
			return Peer{}, err
		}
		if record.IPv4 != v4 {
			return Peer{}, fmt.Errorf("invalid secure IPv4 binding")
		}
	} else if record.OffersExit || record.IPv4.IsValid() {
		return Peer{}, fmt.Errorf("exit record requires v2 binding")
	}
	return Peer{
		ExitVersion: record.ExitVersion, OffersExit: record.OffersExit, IPv4: v4,
		RegistrationID: r.ID, DeviceID: r.Device.ID,
		Name: r.Device.Name, Owner: r.User.Email,
		PublicKey: record.PublicKey, IP: overlayIP, MeshIP: ip,
		Endpoint:   netip.AddrPortFrom(ip, Port),
		AllowedIPs: []netip.Prefix{netip.PrefixFrom(overlayIP, 128)},
	}, nil
}
