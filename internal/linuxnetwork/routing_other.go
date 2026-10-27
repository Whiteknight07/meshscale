//go:build !linux

package linuxnetwork

func newRoutingRunner() routingRunner { return nil }
