package service

import (
	"encoding/json"
	"net/http"
	"net/netip"

	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

// MaxReachabilityAddresses bounds one request. A batch has under a second to
// probe, so callers lose nothing by sending only the first addresses.
const MaxReachabilityAddresses = 4096

func (c *Control) checkReachability(w http.ResponseWriter, r *http.Request) {
	if c.Reachability == nil {
		http.Error(w, "reachability unavailable", http.StatusServiceUnavailable)
		return
	}
	var addresses []string
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
	if err := dec.Decode(&addresses); err != nil || len(addresses) > MaxReachabilityAddresses {
		http.Error(w, "invalid address list", http.StatusBadRequest)
		return
	}
	ips := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		ip, err := netip.ParseAddr(address)
		if err != nil || !meshaddr.IsDevice(ip) {
			http.Error(w, "invalid Mesh IP", http.StatusBadRequest)
			return
		}
		ips = append(ips, ip)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(c.Reachability.Check(r.Context(), ips))
}
