// Package native implements the experimental, undocumented Mesh WireGuard backend.
package native

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

const MTU = 1280

// tunnelRoutes are the prefixes routed into the userspace tunnel.
var tunnelRoutes = []string{meshaddr.IPv4Range.String(), meshaddr.IPv6Block.String()}

type Addresses struct {
	V4 string `json:"v4"`
	V6 string `json:"v6"`
}
type Endpoint struct {
	V4    string `json:"v4"`
	V6    string `json:"v6"`
	Ports []int  `json:"ports"`
}
type Peer struct {
	PublicKey string   `json:"public_key"`
	Endpoint  Endpoint `json:"endpoint"`
}
type TunnelConfig struct {
	Interface struct {
		Addresses Addresses `json:"addresses"`
	} `json:"interface"`
	Peers []Peer `json:"peers"`
}
type Registration struct {
	ID     string       `json:"id"`
	Token  string       `json:"token"`
	Key    string       `json:"key"`
	Config TunnelConfig `json:"config"`
	Policy struct {
		Protocol string `json:"tunnel_protocol"`
		ID       string `json:"policy_id"`
	} `json:"policy"`
}

func (r Registration) IPs() ([]netip.Addr, error) {
	var ips []netip.Addr
	for i, raw := range []string{r.Config.Interface.Addresses.V4, r.Config.Interface.Addresses.V6} {
		if raw == "" {
			continue
		}
		ip, err := netip.ParseAddr(raw)
		if err != nil || ![]netip.Prefix{meshaddr.IPv4Range, meshaddr.IPv6Block}[i].Contains(ip) || ip.Zone() != "" {
			return nil, fmt.Errorf("registration has an invalid Mesh address")
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("registration has no Mesh addresses")
	}
	return ips, nil
}

func keyBytes(key string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("invalid WireGuard key (contents withheld)")
	}
	return b, nil
}

func (r Registration) Validate() error {
	if !strings.HasPrefix(r.ID, "t.") || len(r.ID) < 3 || strings.ContainsAny(r.ID, "/?#\r\n") {
		return fmt.Errorf("invalid device registration ID")
	}
	if _, err := keyBytes(r.Key); err != nil {
		return err
	}
	if _, err := r.IPs(); err != nil {
		return err
	}
	if len(r.Config.Peers) != 1 {
		return fmt.Errorf("expected one WireGuard peer")
	}
	if _, err := keyBytes(r.Config.Peers[0].PublicKey); err != nil {
		return err
	}
	_, err := r.Config.Peers[0].Endpoint.Address()
	return err
}

func (e Endpoint) Address() (string, error) {
	for _, raw := range []string{e.V4, e.V6} {
		addr, err := netip.ParseAddrPort(raw)
		if err != nil {
			continue
		}
		ip := addr.Addr()
		if ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || meshaddr.IPv4Range.Contains(ip.Unmap()) || meshaddr.IPv6Block.Contains(ip) {
			continue
		}
		port := addr.Port()
		if port == 0 && len(e.Ports) > 0 && e.Ports[0] > 0 && e.Ports[0] <= 65535 {
			port = uint16(e.Ports[0])
		}
		if port != 0 {
			return netip.AddrPortFrom(ip, port).String(), nil
		}
	}
	return "", fmt.Errorf("registration has no usable WireGuard endpoint")
}

type API struct {
	BaseURL string
	HTTP    *http.Client
}

func NewAPI() *API {
	return &API{BaseURL: "https://api.devices.cloudflare.com", HTTP: &http.Client{Timeout: 30 * time.Second}}
}

type HTTPError struct{ Status int }

func (e *HTTPError) Error() string {
	return "native device API: HTTP " + strconv.Itoa(e.Status) + " (body withheld)"
}

// request never includes response bodies or credentials in errors.
func (a *API) request(ctx context.Context, method, path, token string, body, out any) error {
	var data io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		data = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.BaseURL+path, data)
	if err != nil {
		return fmt.Errorf("invalid device API URL")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := a.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("native device API request failed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return &HTTPError{Status: res.StatusCode}
	}
	if out == nil {
		return nil
	}
	var envelope struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&envelope) != nil || !envelope.Success || json.Unmarshal(envelope.Result, out) != nil {
		return fmt.Errorf("invalid device API response (body withheld)")
	}
	return nil
}

func accountPath(account string) string { return "/v1/accounts/" + url.PathEscape(account) }
func regPath(account, id string) string { return accountPath(account) + "/reg/" + url.PathEscape(id) }

func ValidateNodeToken(token, account, node string) error {
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return fmt.Errorf("invalid node token encoding")
	}
	var fields struct {
		Account string `json:"a"`
		Node    string `json:"t"`
		Secret  string `json:"s"`
	}
	if json.Unmarshal(data, &fields) != nil || fields.Account != account || fields.Node != node || fields.Secret == "" {
		return fmt.Errorf("node token account/node mismatch or missing secret")
	}
	return nil
}

func GenerateKey() (private, public string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func (a *API) Register(ctx context.Context, account, node, name, token, public string) (Registration, error) {
	var r Registration
	if err := ValidateNodeToken(token, account, node); err != nil {
		return r, err
	}
	body := struct {
		Type  string `json:"type"`
		Name  string `json:"name"`
		Key   string `json:"key"`
		Token string `json:"warp_connector_token"`
	}{"linux", name, public, token}
	if err := a.request(ctx, http.MethodPost, accountPath(account)+"/warp_connector", "", body, &r); err != nil {
		return r, err
	}
	if r.Token == "" || r.Key != public {
		return r, fmt.Errorf("registration credential missing or public key mismatch")
	}
	return r, r.Validate()
}

func (a *API) Refresh(ctx context.Context, account string, old Registration) (Registration, error) {
	var r Registration
	if err := a.request(ctx, http.MethodGet, regPath(account, old.ID), old.Token, nil, &r); err != nil {
		return r, err
	}
	// GET omits the bearer credential. Never replace it with an empty token.
	r.Token = old.Token
	if r.Key == "" {
		r.Key = old.Key
	}
	if r.ID != old.ID || r.Key != old.Key {
		return r, fmt.Errorf("registration identity/key changed; refusing to continue")
	}
	return r, r.Validate()
}

func (a *API) Deregister(ctx context.Context, account string, r Registration) error {
	return a.request(ctx, http.MethodDelete, regPath(account, r.ID), r.Token, nil, nil)
}
