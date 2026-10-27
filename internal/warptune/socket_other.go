//go:build !linux

package warptune

import (
	"context"
	"fmt"
)

type System struct{}

func (System) Discover(context.Context, int) ([]Socket, error) {
	return nil, fmt.Errorf("WARP buffer tuning requires Linux")
}
func (System) Set(context.Context, Socket, int) error {
	return fmt.Errorf("WARP buffer tuning requires Linux")
}
