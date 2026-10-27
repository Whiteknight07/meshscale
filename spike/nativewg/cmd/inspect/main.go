// Print schema and public metadata only; never dump a complete registration response.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"
)

func main() {
	var s struct {
		Registration struct {
			ID, Token string `json:",omitempty"`
		}
	}
	b, e := os.ReadFile("/state/registration.secret.json")
	if e != nil {
		panic(e)
	}
	if e = json.Unmarshal(b, &s); e != nil {
		panic(e)
	}
	url := "https://api.devices.cloudflare.com/v1/accounts/" + os.Getenv("CLOUDFLARE_ACCOUNT_ID") + "/reg/" + s.Registration.ID
	req, e := http.NewRequest("GET", url, nil)
	if e != nil {
		panic(e)
	}
	req.Header.Set("Authorization", "Bearer "+s.Registration.Token)
	client := &http.Client{Timeout: 20 * time.Second}
	r, e := client.Do(req)
	if e != nil {
		panic(e)
	}
	defer r.Body.Close()
	fmt.Println("GET status", r.StatusCode)
	if r.StatusCode != 200 {
		os.Exit(1)
	}
	var v struct {
		Result map[string]any `json:"result"`
	}
	if e = json.NewDecoder(r.Body).Decode(&v); e != nil {
		panic(e)
	}
	keys := func(m map[string]any) []string {
		a := []string{}
		for k := range m {
			a = append(a, k)
		}
		sort.Strings(a)
		return a
	}
	fmt.Println("result field names:", keys(v.Result))
	for _, k := range []string{"id", "type", "key_type", "tunnel_type", "valid_until", "expires_at", "created", "updated"} {
		if x, ok := v.Result[k]; ok {
			fmt.Printf("%s=%v\n", k, x)
		}
	}
	for _, k := range []string{"policy", "config", "connector"} {
		if m, ok := v.Result[k].(map[string]any); ok {
			fmt.Printf("%s field names: %v\n", k, keys(m))
			if k == "policy" {
				for _, n := range []string{"id", "policy_id", "tunnel_protocol", "dns", "gateway_id"} {
					if x, ok := m[n]; ok {
						fmt.Printf("policy.%s=%v\n", n, x)
					}
				}
			}
		}
	}
}
