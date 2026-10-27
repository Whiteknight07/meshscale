package secure

import (
	"os"
	"path/filepath"

	"github.com/Whiteknight07/meshscale/internal/localstate"
)

type Config struct {
	IPv6          string `json:"exit_source_ipv6,omitempty"`
	IPv4          string `json:"exit_source_ipv4,omitempty"`
	AdvertiseExit bool   `json:"advertise_exit_node,omitempty"`
	ExitID        string `json:"exit_node_id,omitempty"`
	ExitKey       string `json:"exit_node_key,omitempty"`
	ExitName      string `json:"exit_node,omitempty"`
	ExitMeshIP    string `json:"exit_mesh_ip,omitempty"`
	AllowLAN      bool   `json:"exit_node_allow_lan_access"`
	Engine        string `json:"engine,omitempty"`
	Enabled       bool   `json:"enabled"`
	Userspace     bool   `json:"userspace"`
}

func LoadConfig(dir string) (Config, error) {
	var c Config
	err := localstate.Read(filepath.Join(dir, "config.json"), &c)
	if os.IsNotExist(err) {
		err = nil
	}
	return c, err
}
func (c Config) Save(dir string) error { return localstate.Write(filepath.Join(dir, "config.json"), c) }
