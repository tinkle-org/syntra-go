package securechannel

import (
	"bytes"
	"context"
	"testing"
)

func TestHTTPCandidatePolicyIsScoped(t *testing.T) {
	for _, carrier := range []Carrier{HTTP, HTTPS} {
		for _, mode := range []Mode{Bootstrap, Returning} {
			t.Run(carrier.String()+"/"+mode.String(), func(t *testing.T) {
				f := newChannelFixture(t, mode)
				f.client.Context.Carrier, f.server.Carrier = carrier, carrier
				c := f.client.Context
				if c.Validate() != ErrConfig || c.ValidateWithHTTPCandidate(false) != ErrConfig {
					t.Fatal("candidate accepted by default")
				}
				if _, err := AppendContext(nil, c); err != ErrConfig {
					t.Fatal("default encoder admitted candidate", err)
				}
				encoded, err := AppendContextWithHTTPCandidate(nil, c, true)
				if err != nil || !bytes.Equal(encoded, canonicalTestContext(c)) || encoded[len(domain)+1] != byte(carrier) {
					t.Fatal("candidate code changed", err)
				}
				if _, err := ParseContext(encoded); err != ErrAuth {
					t.Fatal("default parser admitted candidate", err)
				}
				if got, err := ParseContextWithHTTPCandidate(encoded, true); err != nil || got != c {
					t.Fatal("explicit parser rejected candidate", err)
				}
				if _, _, err := Begin(f.client); err != ErrConfig || f.server.Validate() != ErrConfig {
					t.Fatal("default handshake admitted candidate", err)
				}
				f.client.AllowHTTPCandidate = true
				i, first, err := Begin(f.client)
				if err != nil {
					t.Fatal(err)
				}
				defer i.Close()
				if _, _, err := ParseFirst(first); err != ErrAuth {
					t.Fatal("default first-message parser admitted candidate", err)
				}
				if _, _, err := Respond(context.Background(), f.server, first); err != ErrConfig {
					t.Fatal("server opt-in bypassed", err)
				}
				f.server.AllowHTTPCandidate = true
				s, reply, err := Respond(context.Background(), f.server, first)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				client, err := i.Finish(reply)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				record, err := client.Encrypt(nil, []byte("confirmation"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.Decrypt(nil, record); err != nil {
					t.Fatal(err)
				}
				peer, ok := s.Peer()
				if !ok || f.server.Check(context.Background(), peer) != nil {
					t.Fatal("explicit identity check rejected candidate")
				}
				f.server.AllowHTTPCandidate = false
				if f.server.Check(context.Background(), peer) != ErrAuth || c.Validate() != ErrConfig {
					t.Fatal("candidate policy leaked across configurations")
				}
			})
		}
	}
	if HTTP != 4 || HTTPS != 5 {
		t.Fatal("candidate wire codes changed")
	}
}
