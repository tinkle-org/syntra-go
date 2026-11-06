// File terminal_config_regression_test.go checks complete-frame configuration
// budgets and ownership before any terminal authority or session work starts.
package syntra

import (
	"bytes"
	"context"
	"math"
	"sync/atomic"
	"testing"
	"time"
)

// terminalConfigMethod is a valid application method used only for config checks.
const terminalConfigMethod = "/test.Authority/Retire"

// terminalConfigAuthority records any accidental constructor-time authority I/O.
type terminalConfigAuthority struct{ calls atomic.Int32 }

func (a *terminalConfigAuthority) Commit(context.Context, TerminalTransition) error {
	a.calls.Add(1)
	return nil
}

func (a *terminalConfigAuthority) Observe(context.Context, TerminalTransition) (TerminalObservation, error) {
	a.calls.Add(1)
	return TerminalObservation{}, nil
}

// TestTerminalConfigCompleteFrameBudget checks both sides of the 1024-byte
// ceiling with maximum-width version and correlation varints, not payload alone.
func TestTerminalConfigCompleteFrameBudget(t *testing.T) {
	for _, tc := range []struct {
		name      string
		payload   int
		frameSize int
		valid     bool
	}{
		{name: "empty", payload: 0, frameSize: 21, valid: true},
		{name: "exact-budget", payload: 1001, frameSize: 1024, valid: true},
		{name: "one-byte-over", payload: 1002, frameSize: 1025},
		{name: "payload-only-budget", payload: 1024, frameSize: 1047},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{'x'}, tc.payload)
			frame, err := MarshalFrame(NewResultFrame(math.MaxUint32, math.MaxUint64, NewSuccessResult(payload)))
			if err != nil || len(frame) != tc.frameSize {
				t.Fatalf("boundary frame = %d bytes, %v; want %d bytes", len(frame), err, tc.frameSize)
			}
			if len(payload) > 1024 {
				t.Fatal("test does not isolate frame overhead from the payload limit")
			}
			authority := &terminalConfigAuthority{}
			var callbacks atomic.Int32
			budget, err := NewExecutionBudget(16)
			if err != nil {
				t.Fatal(err)
			}
			cfg := HostConfig{
				MaxVersion: math.MaxUint32,
				TerminalMethods: map[string]TerminalMethodPolicy{terminalConfigMethod: {
					SuccessPayload: payload, Authority: authority, ObservationTimeout: time.Millisecond,
				}},
				ExecutionBudget: budget,
				Policy: func(context.Context, []byte) (string, error) {
					callbacks.Add(1)
					return "principal", nil
				},
				Authorize: func(context.Context, string, string) error { callbacks.Add(1); return nil },
				Handler: func(context.Context, *RpcRequest) (*RpcResult, error) {
					callbacks.Add(1)
					return NewSuccessResult(nil), nil
				},
			}
			host, err := OpenHost(cfg)
			if host != nil {
				t.Cleanup(func() { _ = host.Close() })
			}
			if tc.valid && (err != nil || host == nil) {
				t.Fatalf("valid complete frame rejected: %v", err)
			}
			if !tc.valid && (err == nil || host != nil) {
				t.Errorf("oversize complete frame accepted: host present=%t, error=%v", host != nil, err)
			}
			if authority.calls.Load() != 0 || callbacks.Load() != 0 || budget.Live() != 0 {
				t.Fatal("configuration performed authority, callback, or execution-admission work")
			}
		})
	}
}

// TestTerminalConfigOwnsPolicyCopies ensures neither the caller's map and bytes
// nor a second host share the fixed payload snapshot owned by a constructed host.
func TestTerminalConfigOwnsPolicyCopies(t *testing.T) {
	payload := bytes.Repeat([]byte{'x'}, 1001)
	want := append([]byte(nil), payload...)
	authority := &terminalConfigAuthority{}
	cfg := HostConfig{TerminalMethods: map[string]TerminalMethodPolicy{terminalConfigMethod: {
		SuccessPayload: payload, Authority: authority, ObservationTimeout: time.Millisecond,
	}}}
	first, err := OpenHost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := OpenHost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	payload[0] = 'y'
	delete(cfg.TerminalMethods, terminalConfigMethod)
	for _, host := range []*Host{first, second} {
		policy, ok := host.cfg.terminalMethods[terminalConfigMethod]
		if !ok || !bytes.Equal(policy.SuccessPayload, want) || policy.Authority != authority || policy.ObservationTimeout != time.Millisecond {
			t.Fatal("caller mutation changed the configured policy snapshot")
		}
	}
	first.cfg.terminalMethods[terminalConfigMethod].SuccessPayload[0] = 'z'
	if !bytes.Equal(second.cfg.terminalMethods[terminalConfigMethod].SuccessPayload, want) {
		t.Fatal("separately constructed hosts share fixed payload storage")
	}
	if authority.calls.Load() != 0 {
		t.Fatal("copying configuration invoked authority callbacks")
	}
}
