//go:build !linux

package sshserver

import (
	"context"
	"fmt"
	"golang.org/x/crypto/ssh"
)

func lookupLocalUser(string) (*localUser, error) { return nil, fmt.Errorf("SSH server requires Linux") }
func (s *Server) session(context.Context, *ssh.ServerConn, *localUser, ssh.Channel, <-chan *ssh.Request) {
}
