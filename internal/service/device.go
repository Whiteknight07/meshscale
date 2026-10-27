package service

import (
	"time"

	"github.com/Whiteknight07/meshscale/internal/secure"
)

// Device is one registration, unenrolled physical device, or Mesh node.
type Device struct {
	SSHPolicy       string             `json:"ssh_policy,omitempty"`
	SSHMode         string             `json:"ssh_mode,omitempty"`
	SecureTCP       string             `json:"tcp_congestion_control,omitempty"`
	OffersExit      bool               `json:"offers_exit_node"`
	ExitNode        string             `json:"exit_node,omitempty"`
	ExitState       string             `json:"exit_state,omitempty"`
	ExitAllowLAN    bool               `json:"exit_node_allow_lan_access"`
	Secure          *secure.PeerStatus `json:"secure,omitempty"`
	ID              string             `json:"id"`
	RegistrationID  string             `json:"registration_id,omitempty"`
	DeviceID        string             `json:"device_id,omitempty"`
	Kind            string             `json:"kind"`
	Name            string             `json:"name"`
	DNSName         string             `json:"dns_name,omitempty"`
	User            string             `json:"user,omitempty"`
	OwnerEmail      string             `json:"owner_email,omitempty"`
	Routes          []string           `json:"routes,omitempty"`
	IPv4            string             `json:"ipv4,omitempty"`
	IPv6            string             `json:"ipv6,omitempty"`
	OS              string             `json:"os,omitempty"`
	OnlineSource    string             `json:"online_source"`
	Online          bool               `json:"online"`
	LastSeenAt      *time.Time         `json:"last_seen_at,omitempty"`
	ThisMachine     bool               `json:"this_machine"`
	Backend         string             `json:"backend,omitempty"`
	ConnectionState string             `json:"connection_state,omitempty"`
}
