package ordered

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
)

func hookBudget(t *testing.T) (*EstablishmentBudget, *atomic.Int64) {
	t.Helper()
	age := new(atomic.Int64)
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(age.Load()), true }))
	b, err := NewEstablishmentBudget(clock, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return b, age
}

func TestBudgetCapRetainsSharedIdentityAndOriginalStart(t *testing.T) {
	b, age := hookBudget(t)
	alias := b
	age.Store(int64(time.Second))
	if err := b.Cap(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := b.Cap(9 * time.Second); err != nil {
		t.Fatal(err)
	}
	opts, _, until, _, err := setup(context.Background(), Options{Budget: b})
	if err != nil || opts.Budget != alias || until != 3*time.Second {
		t.Fatal("setup replaced or extended budget", err)
	}
	age.Store(int64(3 * time.Second))
	if err := alias.Check(); err != context.DeadlineExceeded {
		t.Fatal("cap renewed at current age", err)
	}
	alias.Release()
	if alias.Check() != context.DeadlineExceeded {
		t.Fatal("expired release opened raw I/O")
	}
}

func TestDeferredBudgetCompletionAndContinuity(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "expired"}[expire], func(t *testing.T) {
			b, age := hookBudget(t)
			finish, err := b.DeferCompletion()
			if err != nil {
				t.Fatal(err)
			}
			if finish() != ErrOptions {
				t.Fatal("completion preceded protected Ready")
			}
			b.Release()
			if _, active := b.cutoff(); !active {
				t.Fatal("core readiness released deferred gate")
			}
			if expire {
				age.Store(int64(10 * time.Second))
				if finish() != context.DeadlineExceeded || b.Check() != context.DeadlineExceeded {
					t.Fatal("expired recovery released budget")
				}
				return
			}
			if err := finish(); err != nil {
				t.Fatal(err)
			}
			age.Store(int64(11 * time.Second))
			if b.Check() != nil || finish() != nil {
				t.Fatal("released setup cutoff limited active I/O")
			}
			ctx, cancel := b.Context(context.Background())
			defer cancel()
			if ctx.Err() != context.DeadlineExceeded {
				t.Fatal("setup context lost original cutoff")
			}
			age.Store(int64(time.Second))
			if b.Check() != context.DeadlineExceeded {
				t.Fatal("release bypassed clock regression")
			}
		})
	}
}

func TestDeferredBudgetStillGatesOrderedIdleAfterReady(t *testing.T) {
	b, age := hookBudget(t)
	if _, err := b.DeferCompletion(); err != nil {
		t.Fatal(err)
	}
	c, s := driverPair(t, securechannel.Bootstrap, Options{Budget: b}, Options{})
	if err := c.Send(context.Background(), []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Recv(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), []byte("ready")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Recv(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.Release()
	age.Store(int64(10 * time.Second))
	select {
	case <-c.Stopped():
	case <-time.After(time.Second):
		t.Fatal("deferred idle cutoff was retired at Ready")
	}
	if c.TerminalError() != context.DeadlineExceeded {
		t.Fatal("idle cutoff lost terminal cause", c.TerminalError())
	}
}
