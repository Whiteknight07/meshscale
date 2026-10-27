//go:build !linux && !darwin

package cloudflaressh

import "fmt"

func checkDropInDir(string) error { return fmt.Errorf("OpenSSH provisioning requires Linux") }
