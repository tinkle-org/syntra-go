package syntra

import "context"

// ChannelIdentity is the authenticated channel binding supplied by a transport.
// Principal is evidence for ChannelPolicy to verify, not an automatic RPC identity.
type ChannelIdentity struct {
	Mode      string
	Carrier   string
	Scope     string
	Handle    [8]byte
	Epoch     uint64
	Principal string
}

// ChannelIdentityProvider supplies channel authentication after receiving a
// client record. The bool is true only when the responder has authenticated at
// least one client record, providing fresh confirmation of the channel binding.
type ChannelIdentityProvider interface {
	ChannelIdentity() (ChannelIdentity, bool)
}

// ChannelPolicy verifies a freshly confirmed channel identity and the explicit
// hello credential, returning the nonempty principal to bind to the session.
// An empty credential does not implicitly select the channel's Principal.
type ChannelPolicy func(context.Context, ChannelIdentity, []byte) (string, error)
