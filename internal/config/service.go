package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Whiteknight07/meshscale/internal/localstate"
	"github.com/Whiteknight07/meshscale/internal/service"
)

type ServiceSettings struct {
	SSH          bool              `json:"ssh,omitempty"`
	SSHPort      int               `json:"ssh_port,omitempty"`
	SSHPolicy    string            `json:"ssh_policy,omitempty"`
	PollInterval time.Duration     `json:"poll_interval,omitempty"`
	Forwards     []service.Forward `json:"forwards,omitempty"`
}

func ServiceDir() (string, error) { dir, err := Dir(); return filepath.Join(dir, "service"), err }
func servicePath() (string, error) {
	dir, err := ServiceDir()
	return filepath.Join(dir, "config.json"), err
}
func LoadService() (*ServiceSettings, error) {
	path, err := servicePath()
	if err != nil {
		return nil, err
	}
	policy, err := DefaultSSHPolicyPath()
	if err != nil {
		return nil, err
	}
	s := &ServiceSettings{SSHPort: 22, SSHPolicy: policy, PollInterval: time.Minute}
	if err := localstate.Read(path, s); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if s.SSHPort < 1 || s.SSHPort > 65535 || s.PollInterval < time.Second || s.PollInterval > 15*time.Minute {
		return nil, fmt.Errorf("invalid service port or poll interval")
	}
	seen := map[int]bool{}
	for _, f := range s.Forwards {
		if err := f.Validate(); err != nil {
			return nil, err
		}
		if seen[f.MeshPort] {
			return nil, fmt.Errorf("duplicate saved mesh port")
		}
		seen[f.MeshPort] = true
	}
	return s, nil
}
func (s *ServiceSettings) Save() error {
	path, err := servicePath()
	if err != nil {
		return err
	}
	return localstate.Write(path, s)
}

// DefaultSSHPolicyPath keeps rootless SSH policy in the invoking configuration.
func DefaultSSHPolicyPath() (string, error) {
	if os.Geteuid() == 0 {
		return "/etc/meshscale/ssh.json", nil
	}
	dir, err := Dir()
	return filepath.Join(dir, "ssh.json"), err
}
