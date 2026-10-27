//go:build linux

package sshserver

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

func lookupLocalUser(name string) (*localUser, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	target := &localUser{Name: u.Username, Home: u.HomeDir, UID: uint32(uid), GID: uint32(gid)}
	for _, group := range ids {
		n, err := strconv.ParseUint(group, 10, 32)
		if err != nil {
			return nil, err
		}
		target.Groups = append(target.Groups, uint32(n))
	}
	// os/user does not expose the shell. Use the local passwd entry, never an
	// environment variable or the server's own shell.
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) != 7 || fields[0] != name || fields[2] != u.Uid || fields[3] != u.Gid {
			continue
		}
		target.Shell = fields[6]
		break
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if target.Shell == "" || !filepath.IsAbs(target.Shell) || !filepath.IsAbs(target.Home) {
		return nil, fmt.Errorf("user requires an absolute home and login shell in /etc/passwd")
	}
	switch filepath.Base(target.Shell) {
	case "nologin", "false":
		return nil, fmt.Errorf("user has a disabled login shell")
	}
	return target, nil
}
