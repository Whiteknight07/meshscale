package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Whiteknight07/meshscale/internal/localstate"
)

type DNSSettings struct {
	Hosts string `json:"hosts"`
}

func LoadDNS() (*DNSSettings, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	s := &DNSSettings{Hosts: "auto"}
	if err := localstate.Read(filepath.Join(dir, "dns.json"), s); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if s.Hosts != "auto" && s.Hosts != "on" && s.Hosts != "off" {
		return nil, fmt.Errorf("dns-hosts must be auto, on or off")
	}
	return s, nil
}

func (s *DNSSettings) Save() error {
	if s.Hosts != "auto" && s.Hosts != "on" && s.Hosts != "off" {
		return fmt.Errorf("dns-hosts must be auto, on or off")
	}
	dir, err := Dir()
	if err != nil {
		return err
	}
	return localstate.Write(filepath.Join(dir, "dns.json"), s)
}
