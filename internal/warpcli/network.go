package warpcli

import "context"

// ReconcileNetwork is called at enrollment and on every daemon connection check.
func (c *Client) ReconcileNetwork(ctx context.Context) error {
	if c.Network == nil {
		return nil
	}
	return c.Network.Reconcile(ctx)
}

func (c *Client) CleanupNetwork(ctx context.Context) error {
	if c.Network == nil {
		return nil
	}
	return c.Network.Cleanup(ctx)
}
