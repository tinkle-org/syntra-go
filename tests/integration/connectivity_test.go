package integration_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/tests/integration/internal/fixture"
)

func TestSC1(t *testing.T) {
	s := newSuite(t)
	for _, protocol := range []string{"tcp", "ws", "wss"} {
		t.Run(protocol, func(t *testing.T) {
			for _, mode := range []string{"returning", "bootstrap"} {
				t.Run(mode, func(t *testing.T) {
					p := s.startPeer(t, fixture.Provision(protocol, mode, "initial"), protocol+"-"+mode)
					t.Run("echo", p.testEcho)
					t.Run("concurrent16", p.testConcurrent)
					t.Run("cancel", func(t *testing.T) { p.testCancellation(t, false) })
					t.Run("deadline", func(t *testing.T) { p.testCancellation(t, true) })
					t.Run("authorize", p.testAuthorize)
					t.Run("bad_static", func(t *testing.T) {
						cfg, err := p.config.Client()
						if err != nil {
							t.Fatal(err)
						}
						other, err := securechannel.NewStaticKey(fixture.Provision(protocol, mode, "other").Static)
						if err != nil {
							t.Fatal(err)
						}
						cfg.ServerPublicKey = other.Public()
						p.reject(t, cfg, p.tls)
					})
					if mode == "returning" {
						t.Run("bad_authorization_key", func(t *testing.T) {
							cfg, err := p.config.Client()
							if err != nil {
								t.Fatal(err)
							}
							cfg.AuthorizationKey[0] ^= 1
							p.reject(t, cfg, p.tls)
						})
						t.Run("toxiproxy", func(t *testing.T) { s.testProxy(t, p) })
					} else {
						t.Run("bootstrap_requires_credential", func(t *testing.T) {
							for _, cred := range [][]byte{nil, []byte("unaccepted-test-credential")} {
								session := p.connectCredential(t, cred)
								ctx, cancel := context.WithTimeout(context.Background(), operationBound)
								_, err := session.client.Call(ctx, fixture.EchoMethod, nil, 5000)
								cancel()
								if err == nil {
									t.Fatal("bootstrap accepted missing/wrong credential")
								}
								var rpc *syntra.RpcError
								if !errors.As(err, &rpc) || rpc.Code == syntra.ErrorCodeDeadlineExceeded {
									t.Fatalf("bootstrap did not promptly reject: %v", err)
								}
								select {
								case <-session.done:
									// Pre-ACTIVE policy rejection closes the connection;
									// the schema has no typed authentication error carrier.
									wantCode(t, session.runErr, syntra.ErrorCodeUnavailable)
								case <-time.After(operationBound):
									t.Fatal("bootstrap rejection did not terminate handshake")
								}
								p.waitLog(t, fmt.Sprintf(`"msg":"channel_policy_rejected","credential_present":%t}`, len(cred) != 0))
								session.close(t)
							}
						})
					}
					if protocol == "wss" {
						t.Run("tls_verification", p.testTLS)
					}
					t.Run("shutdown_pending", p.testShutdown)
					t.Run("restart_fresh_keys", func(t *testing.T) { s.testRestart(t, p) })
				})
			}
		})
	}
}

func (p *peer) testEcho(t *testing.T) {
	s := p.connect(t)
	for _, size := range []int{0, 64 << 10, syntra.MaxFrameBytes - 128} {
		t.Run(fmt.Sprint(size), func(t *testing.T) { echo(t, s.client, bytes.Repeat([]byte{0x61}, size)) })
	}
}

func (p *peer) testConcurrent(t *testing.T) {
	s := p.connect(t)
	echo(t, s.client, nil)
	start, done := make(chan struct{}), make(chan error, 16)
	ctx, cancel := context.WithTimeout(context.Background(), operationBound)
	defer cancel()
	for i := range 16 {
		go func() {
			<-start
			want := bytes.Repeat([]byte{byte(i)}, 64<<10)
			got, err := s.client.Call(ctx, fixture.EchoMethod, want, 5000)
			if err == nil && !bytes.Equal(got, want) {
				err = errors.New("concurrent echo differs")
			}
			done <- err
		}()
	}
	close(start)
	for range 16 {
		if err := awaitError(t, done); err != nil {
			t.Error(err)
		}
	}
}

func waitCall(ctx context.Context, c *syntra.Client, token uint64) <-chan error {
	done := make(chan error, 1)
	var payload [8]byte
	binary.BigEndian.PutUint64(payload[:], token)
	go func() { _, err := c.Call(ctx, fixture.WaitMethod, payload[:], 20000); done <- err }()
	return done
}

func (p *peer) testCancellation(t *testing.T, deadline bool) {
	s := p.connect(t)
	echo(t, s.client, nil)
	token, want, budget := uint64(1), syntra.ErrorCodeCancelled, operationBound
	if deadline {
		token, want, budget = 2, syntra.ErrorCodeDeadlineExceeded, time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	done := waitCall(ctx, s.client, token)
	p.waitEvent(t, "wait_started", token)
	if !deadline {
		cancel()
	}
	wantCode(t, awaitError(t, done), want)
	p.waitEvent(t, "wait_finished", token)
	// Cancellation is advisory but must leave this session usable.
	echo(t, s.client, []byte("after cancellation"))
}

func (p *peer) testAuthorize(t *testing.T) {
	s := p.connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), operationBound)
	defer cancel()
	_, err := s.client.Call(ctx, fixture.DeniedMethod, nil, 5000)
	wantCode(t, err, syntra.ErrorCodePermissionDenied)
	echo(t, s.client, nil)
}

func (p *peer) reject(t *testing.T, cfg securechannel.ClientConfig, tlsConfig *tls.Config) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), operationBound)
	defer cancel()
	tr, err := p.dial(ctx, cfg, tlsConfig)
	if tr != nil {
		_ = tr.Close()
	}
	if err == nil {
		t.Fatal("invalid peer configuration was accepted")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("rejection timed out instead of failing authentication: %v", err)
	}
}

func (p *peer) testTLS(t *testing.T) {
	cfg, err := p.config.Client()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("wrong_hostname", func(t *testing.T) {
		bad := p.tls.Clone()
		bad.ServerName = "wrong.integration.test"
		p.reject(t, cfg, bad)
	})
	t.Run("untrusted_ca", func(t *testing.T) {
		bad := p.tls.Clone()
		bad.RootCAs = x509.NewCertPool()
		p.reject(t, cfg, bad)
	})
	// Same listener and SC1 credentials with the right CA/name must work.
	s := p.connect(t)
	echo(t, s.client, []byte("verified TLS 1.3"))
}

func (p *peer) testShutdown(t *testing.T) {
	s := p.connect(t)
	echo(t, s.client, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make([]<-chan error, 16)
	for i := range done {
		done[i] = waitCall(ctx, s.client, uint64(100+i))
	}
	for i := range done {
		p.waitEvent(t, "wait_started", uint64(100+i))
	}
	s.close(t)
	for i := range done {
		wantCode(t, awaitError(t, done[i]), syntra.ErrorCodeUnavailable)
		p.waitEvent(t, "wait_finished", uint64(100+i))
	}
}

func (s *suite) testRestart(t *testing.T, p *peer) {
	old := p.connect(t)
	echo(t, old.client, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := waitCall(ctx, old.client, 4)
	p.waitEvent(t, "wait_started", 4)
	stopBound := 3 * time.Second
	if err := p.container.Stop(ctx, &stopBound); err != nil {
		t.Fatal(err)
	}
	p.waitEvent(t, "wait_finished", 4)
	state, err := p.container.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.ExitCode != 0 {
		t.Fatalf("fixture did not shut down gracefully: exit %d", state.ExitCode)
	}
	wantCode(t, awaitError(t, done), syntra.ErrorCodeUnavailable)
	old.close(t)
	rotated := s.startPeer(t, fixture.Provision(p.config.Protocol, p.config.Mode, "rotated"), p.alias+"-rotated")
	stale, err := p.config.Client()
	if err != nil {
		t.Fatal(err)
	}
	rotated.reject(t, stale, rotated.tls)
	if p.config.Mode == "returning" {
		// Also isolate enrollment rotation: correct new static, stale AK.
		fresh, err := rotated.config.Client()
		if err != nil {
			t.Fatal(err)
		}
		fresh.AuthorizationKey = stale.AuthorizationKey
		rotated.reject(t, fresh, rotated.tls)
	}
	fresh := rotated.connect(t)
	echo(t, fresh.client, []byte("fresh session after restart"))
}
