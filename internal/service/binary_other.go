//go:build !linux && !darwin

package service

import "fmt"

func ValidateSystemBinary(string) error {
	return fmt.Errorf("system service installation is unsupported on this OS")
}
