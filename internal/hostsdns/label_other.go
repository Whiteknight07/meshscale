//go:build !linux

package hostsdns

import "os"

func copyLabel(*os.File, string) error { return nil }
