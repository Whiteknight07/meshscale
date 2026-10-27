package secure

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/Whiteknight07/meshscale/internal/backend"
	"github.com/Whiteknight07/meshscale/internal/cfapi"
)

type Registrations interface {
	ListRegistrations(context.Context, string) ([]cfapi.Registration, error)
	ListMeshNodes(context.Context, string) ([]cfapi.MeshNode, error)
	ListMeshConnectors(context.Context, string, string) ([]cfapi.MeshConnector, error)
}

// LoadPeers joins the directory to authoritative device and node identities.
func LoadPeers(ctx context.Context, directory Directory, source Registrations, account string) ([]Peer, []string, error) {
	records, warnings, err := Records(ctx, directory, account)
	if err != nil {
		return nil, warnings, fmt.Errorf("load secure key records: %w", err)
	}
	registrations, err := source.ListRegistrations(ctx, account)
	if err != nil {
		return nil, warnings, err
	}
	// Match the node names used by the ordinary account device/SSH loader.
	nodes, err := source.ListMeshNodes(ctx, account)
	if err != nil {
		return nil, warnings, err
	}
	byID := map[string]string{}
	for _, n := range nodes {
		if n.DeletedAt != nil {
			continue
		}
		connectors, err := source.ListMeshConnectors(ctx, account, n.ID)
		if err != nil {
			return nil, warnings, err
		}
		for _, c := range connectors {
			if _, ok := byID[c.ID]; ok {
				return nil, warnings, fmt.Errorf("ambiguous secure node registration")
			}
			byID[c.ID] = n.Name
		}
	}
	for i := range registrations {
		if n := byID[registrations[i].ID]; n != "" {
			registrations[i].Device.Name = n
		}
	}
	peers, excluded, err := BuildPeers(account, records, registrations)
	for i := range peers {
		peers[i].Node = byID[peers[i].RegistrationID] != ""
	}
	return peers, append(warnings, excluded...), err
}

// Advertisement is what this device publishes about itself.
type Advertisement struct {
	Enabled bool // the secure key is active
	Exit    bool // publish the v2 IPv4 binding that exit traffic needs
	Offers  bool // offer Internet egress; needs Enabled and Exit
}

// PublishLocal resolves the backend's enrollment to exactly one active account
// registration. Editable directory data never selects the local identity.
func PublishLocal(ctx context.Context, directory Directory, source Registrations, account string, local backend.Backend, key Key, ad Advertisement) (Peer, error) {
	info, err := local.Registration(ctx)
	if err != nil {
		return Peer{}, err
	}
	regs, err := source.ListRegistrations(ctx, account)
	if err != nil {
		return Peer{}, err
	}
	// Some client versions label an enrollment UUID "Device ID". Prefer that
	// exact registration before matching a physical device with several enrollments.
	if info.RegistrationID == "" && info.DeviceID != "" {
		for _, reg := range regs {
			if reg.ID == info.DeviceID {
				info.RegistrationID = info.DeviceID
				break
			}
		}
	}
	var self *cfapi.Registration
	for i := range regs {
		reg := &regs[i]
		if reg.DeletedAt != nil || reg.RevokedAt != nil || (reg.RegistrationType != "" && reg.RegistrationType != "warp") {
			continue
		}
		match := false
		switch {
		case info.RegistrationID != "":
			match = reg.ID == info.RegistrationID
		case info.DeviceID != "":
			match = reg.Device.ID == info.DeviceID
		case info.ID != "":
			match = reg.ID == info.ID || reg.Device.ID == info.ID
		}
		if !match {
			continue
		}
		if self != nil {
			return Peer{}, fmt.Errorf("ambiguous local secure registration")
		}
		self = reg
	}
	if self == nil {
		return Peer{}, fmt.Errorf("no active local registration for secure mode")
	}
	ip, err := netip.ParseAddr(self.VirtualIPv4)
	if err != nil {
		return Peer{}, err
	}
	public, err := key.Public()
	if err != nil {
		return Peer{}, err
	}
	record := Record{RegistrationID: self.ID, PublicKey: public, Enabled: ad.Enabled}
	if ad.Exit {
		record.ExitVersion = 2
		record.IPv4, err = IPv4Address(account, public)
		if err != nil {
			return Peer{}, err
		}
		record.OffersExit = ad.Enabled && ad.Offers
	}
	if err := Publish(ctx, directory, account, record, ip); err != nil {
		return Peer{}, err
	}
	addr, err := Address(account, public)
	if err != nil {
		return Peer{}, err
	}
	return Peer{RegistrationID: self.ID, PublicKey: public, IP: addr, MeshIP: ip, Owner: self.User.Email, ExitVersion: record.ExitVersion, IPv4: record.IPv4, OffersExit: record.OffersExit}, nil
}
