package syntrahttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func startHookServer(t *testing.T, cfg ServerConfig, ctx context.Context) *Server {
	t.Helper()
	cfg.Address, cfg.Authority = "127.0.0.1:0", testAuthority(t)
	s, err := Bind(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Serve(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
		st := s.Status()
		if st.Associations != 0 || st.Sockets != 0 || st.ReservedBytes != 0 || !st.Stopped {
			t.Errorf("retained hook resources: %+v", st)
		}
	})
	return s
}

func TestAssociationHookRejectsBeforeBodyAndLookup(t *testing.T) {
	for _, withRelease := range []bool{false, true} {
		t.Run(map[bool]string{false: "nil lease", true: "error with lease"}[withRelease], func(t *testing.T) {
			_, sc := securityConfigs(t, securechannel.Returning, securechannel.HTTP)
			var lookups, calls, releases atomic.Int32
			lookup := sc.Lookup
			sc.Lookup = func(ctx context.Context, c securechannel.Context) (securechannel.Enrollment, error) {
				lookups.Add(1)
				return lookup(ctx, c)
			}
			var server *Server
			cfg := ServerConfig{Security: sc, Host: hostConfig(), AdmitAssociation: func(ctx context.Context, b *ordered.EstablishmentBudget) (func(), error) {
				calls.Add(1)
				// Calling Status here also proves the server mutex is not held.
				if st := server.Status(); st.Associations != 1 || st.ReservedBytes < server.reservation {
					t.Error("native reservation must precede hook")
				}
				if err := b.Check(); err != nil || ctx.Err() != nil {
					t.Error("hook lost original attempt")
				}
				if withRelease {
					return func() { releases.Add(1) }, errors.New("private admission diagnostic")
				}
				return nil, nil
			}}
			var err error
			cfg.Address, cfg.Authority = "127.0.0.1:0", testAuthority(t)
			server, err = Bind(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err = server.Serve(context.Background()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			head, _ := requestHeader(Open, testAuthority(t), Route{}, 0, 83)
			// No body is supplied. Rejection must complete without trying to read it.
			got, err := nativeRequest(t, server, head, nil)
			if err != nil || !bytes.HasPrefix(got, []byte("HTTP/1.1 503 ")) || bytes.Contains(got, []byte("private")) {
				t.Fatalf("hook rejection: %q %v", got, err)
			}
			awaitCondition(t, func() bool { return server.Status().Sockets == 0 })
			want := int32(0)
			if withRelease {
				want = 1
			}
			if calls.Load() != 1 || releases.Load() != want || lookups.Load() != 0 {
				t.Fatalf("hook calls/releases/lookups: %d/%d/%d", calls.Load(), releases.Load(), lookups.Load())
			}
		})
	}
}

func TestAssociationHookReleasesMalformedM1AndUnattachedDownload(t *testing.T) {
	for _, missingDownload := range []bool{false, true} {
		t.Run(map[bool]string{false: "malformed M1", true: "no download"}[missingDownload], func(t *testing.T) {
			cc, sc := securityConfigs(t, securechannel.Returning, securechannel.HTTP)
			var calls, releases atomic.Int32
			s := startHookServer(t, ServerConfig{Security: sc, Host: hostConfig(), Options: ordered.Options{HandshakeTimeout: 100 * time.Millisecond}, AdmitAssociation: func(context.Context, *ordered.EstablishmentBudget) (func(), error) {
				calls.Add(1)
				return func() { releases.Add(1) }, nil
			}}, context.Background())
			body := bytes.Repeat([]byte{1}, 83)
			if missingDownload {
				initiator, m1, err := securechannel.Begin(cc)
				if err != nil {
					t.Fatal(err)
				}
				defer initiator.Close()
				body = m1
			}
			c, err := net.Dial("tcp", s.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(time.Second))
			head, _ := requestHeader(Open, testAuthority(t), Route{}, 0, len(body))
			if err = writeUnit(c, head, body); err != nil {
				t.Fatal(err)
			}
			got, err := readHeader(c)
			if missingDownload {
				if err != nil {
					t.Fatal(err)
				}
				h, err := ParseResponse(got, Open)
				if err != nil || h.BodyLen != 48 {
					t.Fatalf("open: %+v %v", h, err)
				}
				if _, err = io.CopyN(io.Discard, c, 48); err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatalf("malformed M1 got response %q", got)
			}
			awaitCondition(t, func() bool { return s.Status().Associations == 0 && s.Status().Sockets == 0 })
			if calls.Load() != 1 || releases.Load() != 1 {
				t.Fatalf("lease calls/releases: %d/%d", calls.Load(), releases.Load())
			}
		})
	}
}

func TestAssociationHookIgnoresIdleAndDownloadStreams(t *testing.T) {
	for _, carrier := range []securechannel.Carrier{securechannel.HTTP, securechannel.HTTPS} {
		t.Run(carrier.String(), func(t *testing.T) {
			cc, sc := securityConfigs(t, securechannel.Returning, carrier)
			var calls, used, releases atomic.Int32
			cfg := ServerConfig{Security: sc, Host: hostConfig(), Limits: ServerLimits{Associations: 1, Handshakes: 1, UnboundStreams: 4, Sockets: 6}, AdmitAssociation: func(ctx context.Context, b *ordered.EstablishmentBudget) (func(), error) {
				calls.Add(1)
				if used.Add(1) != 1 {
					t.Error("download acquired another lease")
				}
				if err := b.Check(); err != nil || ctx.Err() != nil {
					t.Error("expired admission")
				}
				return func() { used.Add(-1); releases.Add(1) }, nil
			}}
			if carrier == securechannel.HTTPS {
				cfg.TLS = testProvider(t)
			}
			s := startHookServer(t, cfg, context.Background())
			idle, err := net.Dial("tcp", s.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer idle.Close()
			awaitCondition(t, func() bool { return s.Status().UnboundStreams == 1 })
			if calls.Load() != 0 || used.Load() != 0 {
				t.Fatal("idle socket hoarded association admission")
			}
			_ = idle.Close()
			awaitCondition(t, func() bool { return s.Status().Sockets == 0 })
			client := connectTo(t, s, cc, cfg.TLS)
			callEcho(t, client, []byte("two streams, one lease"))
			if calls.Load() != 1 || used.Load() != 1 || s.Status().Sockets != 2 {
				t.Fatalf("association leases: %d/%d status=%+v", calls.Load(), used.Load(), s.Status())
			}
			_ = client.Close()
			awaitCondition(t, func() bool { return releases.Load() == 1 })
			if used.Load() != 0 || calls.Load() != 1 {
				t.Fatal("lease was reused or leaked")
			}
		})
	}
}

func TestAssociationHookPauseCancelsWithoutDroppingOwner(t *testing.T) {
	_, sc := securityConfigs(t, securechannel.Returning, securechannel.HTTP)
	entered, canceled, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(returned) })
	var releases, lookups atomic.Int32
	lookup := sc.Lookup
	sc.Lookup = func(ctx context.Context, c securechannel.Context) (securechannel.Enrollment, error) {
		lookups.Add(1)
		return lookup(ctx, c)
	}
	s := startHookServer(t, ServerConfig{Security: sc, Host: hostConfig(), AdmitAssociation: func(ctx context.Context, _ *ordered.EstablishmentBudget) (func(), error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-returned
		return func() { releases.Add(1) }, nil
	}}, context.Background())
	c, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	head, _ := requestHeader(Open, testAuthority(t), Route{}, 0, 83)
	if _, err = c.Write(head); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("hook did not start")
	}
	s.Pause()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("pause did not cancel hook context")
	}
	st := s.Status()
	if releases.Load() != 0 || lookups.Load() != 0 || st.Associations != 1 || st.Sockets != 1 || st.ReservedBytes < s.reservation {
		t.Fatalf("premature admission cleanup: %+v", st)
	}
	s.Resume()
	once.Do(func() { close(returned) })
	awaitCondition(t, func() bool { return releases.Load() == 1 && s.Status().Associations == 0 && s.Status().Sockets == 0 })
	if lookups.Load() != 0 {
		t.Fatal("canceled hook processed M1 after resume")
	}
}

func TestAssociationHookUsesOriginalAttemptExpiry(t *testing.T) {
	_, sc := securityConfigs(t, securechannel.Returning, securechannel.HTTP)
	var calls, releases, lookups atomic.Int32
	lookup := sc.Lookup
	sc.Lookup = func(ctx context.Context, c securechannel.Context) (securechannel.Enrollment, error) {
		lookups.Add(1)
		return lookup(ctx, c)
	}
	s := startHookServer(t, ServerConfig{Security: sc, Host: hostConfig(), Options: ordered.Options{AttemptTimeout: 100 * time.Millisecond}, AdmitAssociation: func(ctx context.Context, budget *ordered.EstablishmentBudget) (func(), error) {
		calls.Add(1)
		if _, ok := ctx.Deadline(); !ok {
			t.Error("admission lost absolute attempt deadline")
		}
		<-ctx.Done()
		if err := budget.Check(); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("admission and original budget diverged: %v", err)
		}
		return func() { releases.Add(1) }, ctx.Err()
	}}, context.Background())
	head, _ := requestHeader(Open, testAuthority(t), Route{}, 0, 83)
	if got, err := nativeRequest(t, s, head, nil); err == nil {
		t.Fatalf("expired admission emitted response %q", got)
	}
	awaitCondition(t, func() bool { return releases.Load() == 1 })
	if calls.Load() != 1 || lookups.Load() != 0 || s.Status().Sockets != 0 || s.Status().ReservedBytes != 0 {
		t.Fatal("expired admission processed body or lost cleanup ownership")
	}
}
