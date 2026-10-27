//go:build !linux

package secure

import (
	"context"
	"fmt"
)

func clampMSS(context.Context, int) (func(), error) {
	return nil, fmt.Errorf("secure interface requires Linux")
}
