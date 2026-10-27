// Probe MASQUE configuration only. The temporary registration is always deleted.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

var client = &http.Client{Timeout: 25 * time.Second}

func call(method, url, token string, body any) (int, map[string]any, error) {
	var b io.Reader
	if body != nil {
		v, e := json.Marshal(body)
		if e != nil {
			return 0, nil, e
		}
		b = bytes.NewReader(v)
	}
	req, e := http.NewRequest(method, url, b)
	if e != nil {
		return 0, nil, e
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	r, e := client.Do(req)
	if e != nil {
		return 0, nil, e
	}
	defer r.Body.Close()
	var v map[string]any
	if r.StatusCode != 204 {
		if e = json.NewDecoder(r.Body).Decode(&v); e != nil {
			return r.StatusCode, nil, fmt.Errorf("response decoding failed")
		}
	}
	return r.StatusCode, v, nil
}
func run() error {
	var s struct {
		NodeID string `json:"node_id"`
	}
	b, e := os.ReadFile("/state/registration.secret.json")
	if e != nil {
		return e
	}
	if e = json.Unmarshal(b, &s); e != nil {
		return e
	}
	account := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	status, v, e := call("GET", "https://api.cloudflare.com/client/v4/accounts/"+account+"/warp_connector/"+s.NodeID+"/token", os.Getenv("CLOUDFLARE_API_TOKEN"), nil)
	if e != nil {
		return e
	}
	if status != 200 {
		return fmt.Errorf("node token GET status %d", status)
	}
	token, ok := v["result"].(string)
	if !ok {
		return fmt.Errorf("missing node token")
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	pub, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		return e
	}
	body := map[string]any{"type": "linux", "name": "meshscale-native-test", "key": base64.StdEncoding.EncodeToString(pub), "warp_connector_token": token, "key_type": "secp256r1", "tunnel_type": "masque"}
	status, v, e = call("POST", "https://api.devices.cloudflare.com/v1/accounts/"+account+"/warp_connector", "", body)
	if e != nil {
		return e
	}
	fmt.Println("MASQUE registration HTTP", status)
	if status != 200 {
		return fmt.Errorf("registration rejected (body withheld)")
	}
	result, ok := v["result"].(map[string]any)
	if !ok {
		return fmt.Errorf("missing result")
	}
	id, _ := result["id"].(string)
	apiToken, _ := result["token"].(string)
	if id == "" || apiToken == "" {
		return fmt.Errorf("missing registration credentials")
	}
	url := "https://api.devices.cloudflare.com/v1/accounts/" + account + "/reg/" + id
	defer func() {
		status, _, e := call("DELETE", url, apiToken, nil)
		fmt.Printf("Temporary MASQUE registration DELETE status=%d error=%v\n", status, e)
		status, _, e = call("GET", url, apiToken, nil)
		fmt.Printf("GET after deletion status=%d error=%v (401 expected)\n", status, e)
	}()
	fmt.Printf("Temporary MASQUE registration id=%s key_type=%v tunnel_type=%v public_key_der_bytes=%d\n", id, result["key_type"], result["tunnel_type"], len(pub))
	config, _ := result["config"].(map[string]any)
	iface, _ := config["interface"].(map[string]any)
	fmt.Println("MASQUE interface:", iface)
	peers, _ := config["peers"].([]any)
	for _, p := range peers {
		m, _ := p.(map[string]any)
		peerKey, _ := m["public_key"].(string)
		fmt.Printf("MASQUE endpoint=%v peer_key_bytes=%d peer_key_is_pem=%v\n", m["endpoint"], len(peerKey), len(peerKey) > 26 && peerKey[:26] == "-----BEGIN PUBLIC KEY-----")
	}
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
