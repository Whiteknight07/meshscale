package cfapi

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

func (c *Client) Account(ctx context.Context, accountID string) (Account, error) {
	return get[Account](ctx, c, accountPath(accountID, ""))
}

func (c *Client) ListAccounts(ctx context.Context) ([]Account, error) {
	return list[Account](ctx, c, "/accounts", pages)
}

type User struct {
	ID    string `json:"id,omitempty"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
}

func (c *Client) User(ctx context.Context) (User, error) {
	return get[User](ctx, c, "/user")
}

type RegistrationDevice struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ClientVersion string `json:"client_version,omitempty"`
}

type Registration struct {
	ID               string             `json:"id"`
	Device           RegistrationDevice `json:"device"`
	User             User               `json:"user"`
	VirtualIPv4      string             `json:"virtual_ipv4"`
	VirtualIPv6      string             `json:"virtual_ipv6"`
	RegistrationType string             `json:"registration_type,omitempty"`
	LastSeenAt       *time.Time         `json:"last_seen_at"`
	DeletedAt        *time.Time         `json:"deleted_at,omitempty"`
	RevokedAt        *time.Time         `json:"revoked_at,omitempty"`
}

type PhysicalDevice struct {
	ID                   string        `json:"id"`
	Name                 string        `json:"name"`
	DeviceType           string        `json:"device_type"`
	OSVersion            string        `json:"os_version,omitempty"`
	LastSeenAt           *time.Time    `json:"last_seen_at"`
	LastSeenUser         User          `json:"last_seen_user"`
	LastSeenRegistration *Registration `json:"last_seen_registration,omitempty"`
	DeletedAt            *time.Time    `json:"deleted_at,omitempty"`
}

func (c *Client) ListRegistrations(ctx context.Context, accountID string) ([]Registration, error) {
	return list[Registration](ctx, c, accountPath(accountID, "/devices/registrations"), cursors)
}

func (c *Client) ListPhysicalDevices(ctx context.Context, accountID string) ([]PhysicalDevice, error) {
	return list[PhysicalDevice](ctx, c, accountPath(accountID, "/devices/physical-devices"), cursors)
}

// Mesh IPs come from registrations joined through the dedicated connections
// endpoint. Connection origin_ip is a public IP, never a Mesh address.
type MeshNode struct {
	Connectors      []MeshConnector `json:"-"`
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Status          string          `json:"status"`
	TunnelType      string          `json:"tun_type,omitempty"`
	ConnsActiveAt   *time.Time      `json:"conns_active_at,omitempty"`
	ConnsInactiveAt *time.Time      `json:"conns_inactive_at,omitempty"`
	DeletedAt       *time.Time      `json:"deleted_at,omitempty"`
}

type CreateMeshNodeParams struct {
	Name string `json:"name"`
	HA   bool   `json:"ha,omitempty"`
}

func (c *Client) ListMeshNodes(ctx context.Context, accountID string) ([]MeshNode, error) {
	return list[MeshNode](ctx, c, accountPath(accountID, "/warp_connector"), pages)
}

func (c *Client) CreateMeshNode(ctx context.Context, accountID string, params CreateMeshNodeParams) (MeshNode, error) {
	return send[MeshNode](ctx, c, http.MethodPost, accountPath(accountID, "/warp_connector"), params)
}

func (c *Client) DeleteMeshNode(ctx context.Context, accountID, nodeID string) error {
	_, err := c.request(ctx, http.MethodDelete, accountPath(accountID, "/warp_connector/"+url.PathEscape(nodeID)), nil, nil, nil)
	return err
}

func (c *Client) MeshNodeToken(ctx context.Context, accountID, nodeID string) (string, error) {
	return get[string](ctx, c, accountPath(accountID, "/warp_connector/"+url.PathEscape(nodeID)+"/token"))
}

type Route struct {
	ID               string     `json:"id"`
	Network          string     `json:"network"`
	TunnelID         string     `json:"tunnel_id"`
	TunnelName       string     `json:"tunnel_name,omitempty"`
	Comment          string     `json:"comment"`
	VirtualNetworkID string     `json:"virtual_network_id,omitempty"`
	DeletedAt        *time.Time `json:"deleted_at,omitempty"`
}

type CreateRouteParams struct {
	Network          string `json:"network"`
	TunnelID         string `json:"tunnel_id"`
	Comment          string `json:"comment,omitempty"`
	VirtualNetworkID string `json:"virtual_network_id,omitempty"`
}

func (c *Client) ListRoutes(ctx context.Context, accountID string) ([]Route, error) {
	return list[Route](ctx, c, accountPath(accountID, "/teamnet/routes"), pages)
}

func (c *Client) CreateRoute(ctx context.Context, accountID string, params CreateRouteParams) (Route, error) {
	return send[Route](ctx, c, http.MethodPost, accountPath(accountID, "/teamnet/routes"), params)
}

func (c *Client) DeleteRoute(ctx context.Context, accountID, routeID string) error {
	_, err := c.request(ctx, http.MethodDelete, accountPath(accountID, "/teamnet/routes/"+url.PathEscape(routeID)), nil, nil, nil)
	return err
}

type DeviceSettings struct {
	UseZTVirtualIP         bool `json:"use_zt_virtual_ip"`
	GatewayProxyEnabled    bool `json:"gateway_proxy_enabled"`
	GatewayUDPProxyEnabled bool `json:"gateway_udp_proxy_enabled"`
}

// Pointers distinguish an omitted setting from explicitly disabling it.
type DeviceSettingsPatch struct {
	UseZTVirtualIP         *bool `json:"use_zt_virtual_ip,omitempty"`
	GatewayProxyEnabled    *bool `json:"gateway_proxy_enabled,omitempty"`
	GatewayUDPProxyEnabled *bool `json:"gateway_udp_proxy_enabled,omitempty"`
}

func (c *Client) DeviceSettings(ctx context.Context, accountID string) (DeviceSettings, error) {
	return get[DeviceSettings](ctx, c, accountPath(accountID, "/devices/settings"))
}

func (c *Client) UpdateDeviceSettings(ctx context.Context, accountID string, patch DeviceSettingsPatch) (DeviceSettings, error) {
	return send[DeviceSettings](ctx, c, http.MethodPatch, accountPath(accountID, "/devices/settings"), patch)
}

type SplitTunnelEntry struct {
	Address     string `json:"address,omitempty"`
	Host        string `json:"host,omitempty"`
	Description string `json:"description,omitempty"`
}

type ServiceMode struct {
	Mode string `json:"mode"`
	Port int    `json:"port,omitempty"`
}

type DeviceProfile struct {
	PolicyID       string             `json:"policy_id"`
	Name           string             `json:"name,omitempty"`
	Description    string             `json:"description,omitempty"`
	Default        bool               `json:"default"`
	Enabled        bool               `json:"enabled"`
	Match          string             `json:"match,omitempty"`
	Precedence     float64            `json:"precedence,omitempty"`
	ProfileType    string             `json:"profile_type,omitempty"`
	TunnelProtocol string             `json:"tunnel_protocol,omitempty"`
	ServiceModeV2  ServiceMode        `json:"service_mode_v2"`
	Include        []SplitTunnelEntry `json:"include,omitempty"`
	Exclude        []SplitTunnelEntry `json:"exclude,omitempty"`
}

type CreateDeviceProfileParams struct {
	Name           string              `json:"name"`
	Description    string              `json:"description,omitempty"`
	Match          string              `json:"match,omitempty"`
	Precedence     *float64            `json:"precedence,omitempty"`
	Enabled        *bool               `json:"enabled,omitempty"`
	ProfileType    string              `json:"profile_type,omitempty"`
	TunnelProtocol string              `json:"tunnel_protocol,omitempty"`
	ServiceModeV2  *ServiceMode        `json:"service_mode_v2,omitempty"`
	Include        *[]SplitTunnelEntry `json:"include,omitempty"`
	Exclude        *[]SplitTunnelEntry `json:"exclude,omitempty"`
}

func (c *Client) ListDeviceProfiles(ctx context.Context, accountID string) ([]DeviceProfile, error) {
	return list[DeviceProfile](ctx, c, accountPath(accountID, "/devices/policies"), unpaginated)
}

func (c *Client) CreateDeviceProfile(ctx context.Context, accountID string, params CreateDeviceProfileParams) (DeviceProfile, error) {
	return send[DeviceProfile](ctx, c, http.MethodPost, accountPath(accountID, "/devices/policy"), params)
}

type Organization struct {
	Name       string `json:"name"`
	AuthDomain string `json:"auth_domain"`
}

func (c *Client) Organization(ctx context.Context, accountID string) (Organization, error) {
	return get[Organization](ctx, c, accountPath(accountID, "/access/organizations"))
}

type ServiceToken struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	ClientID     string     `json:"client_id"`
	ClientSecret string     `json:"client_secret,omitempty"` // Returned only at creation.
	Duration     string     `json:"duration,omitempty"`
	Enabled      *bool      `json:"enabled,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

func (c *Client) ListServiceTokens(ctx context.Context, accountID string) ([]ServiceToken, error) {
	return list[ServiceToken](ctx, c, accountPath(accountID, "/access/service_tokens"), pages)
}

// MeshConnector.ID matches the device/registration ID of a Linux Mesh node.
type MeshConnector struct {
	ID          string           `json:"id"`
	HAStatus    string           `json:"ha_status"`
	Connections []MeshConnection `json:"conns"`
}

type MeshConnection struct {
	ClientID string     `json:"client_id"`
	OpenedAt *time.Time `json:"opened_at"`
}

func (c *Client) ListMeshConnectors(ctx context.Context, accountID, nodeID string) ([]MeshConnector, error) {
	return list[MeshConnector](ctx, c, accountPath(accountID, "/warp_connector/"+url.PathEscape(nodeID)+"/connections"), pages)
}
