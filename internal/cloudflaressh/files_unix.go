//go:build linux || darwin

package cloudflaressh

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func checkDropInDir(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e != nil {
			return e
		}
		st, ok := i.Sys().(*syscall.Stat_t)
		if !ok || !i.IsDir() || st.Uid != uint32(os.Geteuid()) && st.Uid != 0 || i.Mode().Perm()&0022 != 0 && i.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("insecure SSH directory %s", p)
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}
