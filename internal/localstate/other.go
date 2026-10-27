//go:build !linux && !darwin

package localstate

import (
	"fmt"
	"os"
	"time"
)

func openFile(string, int) (*os.File, error) {
	return nil, fmt.Errorf("private state is unsupported on this OS")
}

func currentOwner(os.FileInfo) bool { return false }
func owned(os.FileInfo) bool        { return false }
func Lock(string) (func(), error) {
	return nil, fmt.Errorf("private native state is unsupported on this OS")
}
func WaitLock(string, time.Duration) (func(), error) {
	return nil, fmt.Errorf("private native state is unsupported on this OS")
}
