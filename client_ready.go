package syntra

import "context"

// WaitReady waits for the validated ServerReady exchange, session termination,
// or ctx cancellation. Run must be started separately. A terminated session
// returns FailedPrecondition, including when it was previously ready; this
// method does not retain or expose the handshake's potentially sensitive error.
// Cancellation returns ctx.Err(). Readiness is a snapshot, not a lease on the
// connection: a later Call can still observe a disconnect.
func (c *Client) WaitReady(ctx context.Context) error {
	if c == nil {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: invalid client")
	}
	for {
		c.mu.Lock()
		if c.closed || c.activated == nil || c.done == nil {
			c.mu.Unlock()
			return NewRpcError(ErrorCodeFailedPrecondition, "syntra: client closed or invalid")
		}
		// Check terminal state before readiness under the same lock used by
		// handshake and Close. Selecting between two closed channels alone
		// would randomly report success for an already closed session.
		select {
		case <-c.done:
			c.mu.Unlock()
			return NewRpcError(ErrorCodeUnavailable, "syntra: client stopped")
		default:
		}
		if err := ctx.Err(); err != nil {
			c.mu.Unlock()
			return err
		}
		select {
		case <-c.activated:
			c.mu.Unlock()
			return nil
		default:
		}
		activated, done := c.activated, c.done
		c.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-done:
		case <-activated:
		}
	}
}
