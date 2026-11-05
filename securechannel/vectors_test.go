package securechannel

import (
	"bytes"
	"context"
	"testing"
)

// Fixed test-only keys and ephemerals exercise both complete handshake patterns,
// the handshake hash and nonce-zero records in both directions.
func TestDeterministicHandshakeVectors(t *testing.T) {
	for _, v := range []struct {
		mode                                            Mode
		first, second, hash, clientRecord, serverRecord string
	}{
		{Bootstrap,
			"73796e7472612e312e30010301020304000000000000000000000000000000000007766563746f7273ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59dc28c46364d95dcd2c9a1b26a8871681",
			"5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22797a187d9a945dc2a09641b50ccd9a81",
			"59408ecfb5c4d92d52317df6a8bcf581ed96a5c388a9c46f5e0dc8d98591a0d5",
			"4d7817d328498b6871d89c17942f7bf51f9402765b93ee6908", "3d45fe35b7dbd0387ffb35404563ace178758eb8811407f1fd"},
		{Returning,
			"73796e7472612e312e30020301020304000000000000000101020304050607080007766563746f7273ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d598d4a7e884bfa8a7af72d4ba240f6269c",
			"5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef226d38ff226aad6b317ad34cbefa1dde9f",
			"28cb409708948814ac4cce03757cddd748a8086ffab9bfc7372abde782787ae7",
			"7bc1579ea8950dfeba94799bb21bc6bd822a3d7278a7c15fd1", "baf294c6ef5b4c1b1753279764ffd00f9b491a63c1b895976a"},
	} {
		t.Run(v.mode.String(), func(t *testing.T) {
			var private, authorization Key
			copy(private[:], bytes.Repeat([]byte{1}, 32))
			copy(authorization[:], bytes.Repeat([]byte{4}, 32))
			static, err := NewStaticKey(private)
			if err != nil {
				t.Fatal(err)
			}
			public := static.Public()
			if !bytes.Equal(public[:], decodeHex(t, "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209")) {
				t.Fatal("static public vector")
			}
			cfg := ClientConfig{Context: Context{Mode: v.mode, Carrier: WSS, ServerKeyID: 0x01020304, Scope: "vectors"}, ServerPublicKey: public}
			if v.mode == Returning {
				cfg.Context.Epoch = 1
				cfg.Context.Handle = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
				cfg.AuthorizationKey = authorization
			}
			i, first, err := begin(cfg, bytes.NewReader(bytes.Repeat([]byte{2}, 32)))
			if err != nil {
				t.Fatal(err)
			}
			defer i.Close()
			if !bytes.Equal(first, decodeHex(t, v.first)) {
				t.Fatalf("M1 = %x", first)
			}
			s, second, err := respond(context.Background(), ServerConfig{StaticKey: static, ServerKeyID: cfg.Context.ServerKeyID, Scope: cfg.Context.Scope, Carrier: WSS, AllowBootstrap: v.mode == Bootstrap, LookupKey: func(context.Context, Context) (Key, error) { return authorization, nil }}, first, bytes.NewReader(bytes.Repeat([]byte{3}, 32)))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if !bytes.Equal(second, decodeHex(t, v.second)) {
				t.Fatalf("M2 = %x", second)
			}
			c, err := i.Finish(second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if !bytes.Equal(c.peer.HandshakeHash[:], decodeHex(t, v.hash)) || c.peer.HandshakeHash != s.peer.HandshakeHash {
				t.Fatal("handshake hash vector")
			}
			request, _ := FramePlaintext([]byte("hello"))
			response, _ := FramePlaintext([]byte("ready"))
			wire, err := c.Encrypt(nil, request)
			if err != nil || !bytes.Equal(wire, decodeHex(t, v.clientRecord)) {
				t.Fatalf("client record = %x: %v", wire, err)
			}
			if plain, err := s.Decrypt(nil, wire); err != nil || !bytes.Equal(plain, request) {
				t.Fatal("client vector decryption")
			}
			wire, err = s.Encrypt(nil, response)
			if err != nil || !bytes.Equal(wire, decodeHex(t, v.serverRecord)) {
				t.Fatalf("server record = %x: %v", wire, err)
			}
			if plain, err := c.Decrypt(nil, wire); err != nil || !bytes.Equal(plain, response) {
				t.Fatal("server vector decryption")
			}
		})
	}
}

func TestNoncontributoryDHRejected(t *testing.T) {
	for _, mode := range []Mode{Bootstrap, Returning} {
		f := newChannelFixture(t, mode)
		f.client.ServerPublicKey = [32]byte{1}
		i, first, err := Begin(f.client)
		if err != ErrAuth || i != nil || first != nil {
			t.Fatal("noncontributory static accepted")
		}
		f = newChannelFixture(t, mode)
		i, first, err = Begin(f.client)
		if err != nil {
			t.Fatal(err)
		}
		i.Close()
		clear(first[len(first)-48 : len(first)-16])
		s, second, err := Respond(context.Background(), f.server, first)
		requireAuthDenied(t, s, second, err)
	}
}
