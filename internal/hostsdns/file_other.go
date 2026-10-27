//go:build !linux && !darwin

package hostsdns

import (
	"context"
	"fmt"
	"os"
)

func lock(context.Context, string) (func(), error) {
	return nil, fmt.Errorf("hosts DNS requires Linux or macOS")
}
func metadata(*os.File, os.FileInfo, string) error {
	return fmt.Errorf("hosts DNS requires Linux or macOS")
}

func isMountPoint(error) bool { return false }
