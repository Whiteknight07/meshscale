//go:build !linux

package exitnode

import "context"

func WatchNetwork(context.Context) (<-chan struct{}, error)       { return nil, nil }
func (m *Manager) Watch(context.Context) (<-chan struct{}, error) { return nil, nil }
