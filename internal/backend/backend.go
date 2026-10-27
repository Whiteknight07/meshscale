// Package backend defines the local connection control shared by transports.
package backend

import "context"

type Status struct {
	State     string `json:"state"`
	Connected bool   `json:"connected"`
	Reason    string `json:"reason,omitempty"`
}

type Registration struct {
	AccountType    string `json:"account_type,omitempty"`
	Organization   string `json:"organization,omitempty"`
	ID             string `json:"id,omitempty"`
	RegistrationID string `json:"registration_id,omitempty"`
	DeviceID       string `json:"device_id,omitempty"`
	ConnectorID    string `json:"connector_id,omitempty"`
}

// Backend controls a local connection. Native Connect requires its foreground
// daemon; the official backend delegates lifecycle to warp-svc.
type Backend interface {
	Status(context.Context) (Status, error)
	Registration(context.Context) (Registration, error)
	Connect(context.Context) error
	Disconnect(context.Context) error
}

// StatusWatcher exposes connection state changes without short-lived polling
// commands. Implementations may return when their local status stream closes.
type StatusWatcher interface {
	WatchStatus(context.Context, chan<- Status) error
}

// NetworkReconciler is an optional backend capability for maintaining local
// network integration while connected (for example Linux firewall coexistence).
type NetworkReconciler interface {
	ReconcileNetwork(context.Context) error
}
