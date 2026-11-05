// Package network owns bounded reconnecting clients and network services.
//
// Connectors build fresh channel keys, credentials and policy inputs on every
// invocation and carry the supplied budget through every establishment layer.
// They must honor cancellation and must not start detached work. A callback that
// ignores cancellation stays charged to its owner until it actually returns.
//
// Calls never wait for a future connection and are never replayed. Results and
// notifications carry a generation; controls synchronously invalidate that
// generation. Applications must fence their own deferred completion work too.
// Core readiness and recovery negotiation do not imply restored subscriptions or
// durable catch-up. Each generation has independent transport and profile state.
package network
