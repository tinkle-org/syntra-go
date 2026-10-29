// Wire-fixture tests: golden vectors from
// conformance/test-vectors/protobuf/vectors.yaml plus negative wire
// cases (duplicate bodies, reserved fields, truncation, enum
// normalization). Fixture identities are neutral (/example.Echo/Echo,
// /example.KV/Get); no messenger semantics appear here.
package syntra

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	syntrav1 "github.com/tinkle-org/syntra-go/gen/syntra/v1"
	"google.golang.org/protobuf/proto"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestGoldenVectors decodes every valid golden fixture and asserts the
// logical message. Byte equality is never asserted across encoders
// (SNTR-SER-002); logical equality is.
func TestGoldenVectors(t *testing.T) {
	t.Run("hello", func(t *testing.T) {
		f, err := UnmarshalFrame(mustHex(t, "0801521e080110011a186f70617175652d746573742d63726564656e7469616c2d41"))
		if err != nil {
			t.Fatal(err)
		}
		if f.GetVersion() != 1 || f.GetRequestId() != 0 {
			t.Fatalf("envelope = v%d id%d", f.GetVersion(), f.GetRequestId())
		}
		h := f.GetHello()
		if h == nil || h.GetMinVersion() != 1 || h.GetMaxVersion() != 1 {
			t.Fatalf("hello = %+v", h)
		}
		if string(h.GetCredential()) != "opaque-test-credential-A" {
			t.Fatalf("credential = %q", h.GetCredential())
		}
	})
	t.Run("ready", func(t *testing.T) {
		f, err := UnmarshalFrame(mustHex(t, "08015a110a0f666978747572652d636f6e6e2d3031"))
		if err != nil {
			t.Fatal(err)
		}
		if f.GetVersion() != 1 || f.GetRequestId() != 0 {
			t.Fatalf("envelope = v%d id%d", f.GetVersion(), f.GetRequestId())
		}
		if f.GetReady().GetConnectionId() != "fixture-conn-01" {
			t.Fatalf("connection_id = %q", f.GetReady().GetConnectionId())
		}
	})
	t.Run("request", func(t *testing.T) {
		f, err := UnmarshalFrame(mustHex(t, "08011007621e0a122f6578616d706c652e4563686f2f4563686f120568656c6c6f18f403"))
		if err != nil {
			t.Fatal(err)
		}
		if f.GetRequestId() != 7 {
			t.Fatalf("request_id = %d", f.GetRequestId())
		}
		req := f.GetRequest()
		if req.GetMethod() != "/example.Echo/Echo" || string(req.GetPayload()) != "hello" || req.GetTimeoutMs() != 500 {
			t.Fatalf("request = %+v", req)
		}
	})
	t.Run("request-empty-payload", func(t *testing.T) {
		f, err := UnmarshalFrame(mustHex(t, "0801100d62190a122f6578616d706c652e4563686f2f4563686f120018f403"))
		if err != nil {
			t.Fatal(err)
		}
		req := f.GetRequest()
		// RpcRequest.payload is a plain bytes field (not a oneof), so
		// the generated codec cannot distinguish selected-empty from
		// absent — and per SNTR-WIRE-007 it does not need to: both mean
		// "invoke with empty input". Only the length is asserted.
		if req == nil || len(req.GetPayload()) != 0 {
			t.Fatalf("payload = %+v", req)
		}
	})
	t.Run("result-ok", func(t *testing.T) {
		f, err := UnmarshalFrame(mustHex(t, "080110076a070a0568656c6c6f"))
		if err != nil {
			t.Fatal(err)
		}
		if string(f.GetResult().GetPayload()) != "hello" {
			t.Fatalf("payload = %q", f.GetResult().GetPayload())
		}
	})
	t.Run("result-empty-success", func(t *testing.T) {
		f, err := UnmarshalFrame(mustHex(t, "0801100d6a020a00"))
		if err != nil {
			t.Fatal(err)
		}
		res := f.GetResult()
		if res.GetPayload() == nil {
			t.Fatal("empty success outcome not selected")
		}
	})
	t.Run("result-error", func(t *testing.T) {
		f, err := UnmarshalFrame(mustHex(t, "080110076a141212080c120e756e6b6e6f776e206d6574686f64"))
		if err != nil {
			t.Fatal(err)
		}
		werr := f.GetResult().GetError()
		if werr.GetCode() != ErrorCodeUnimplemented || werr.GetMessage() != "unknown method" {
			t.Fatalf("error = %+v", werr)
		}
	})
	t.Run("notification", func(t *testing.T) {
		f, err := UnmarshalFrame(mustHex(t, "08017a090a076576656e742d31"))
		if err != nil {
			t.Fatal(err)
		}
		if f.GetRequestId() != 0 || string(f.GetNotification().GetPayload()) != "event-1" {
			t.Fatalf("notification = %+v", f)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		f, err := UnmarshalFrame(mustHex(t, "0801100c7200"))
		if err != nil {
			t.Fatal(err)
		}
		if f.GetRequestId() != 12 || f.GetCancel() == nil {
			t.Fatalf("cancel = %+v", f)
		}
	})
	t.Run("unknown-field-tolerated", func(t *testing.T) {
		withUnknown := mustHex(t, "08011007621e0a122f6578616d706c652e4563686f2f4563686f120568656c6c6f18f403d2050178")
		f, err := UnmarshalFrame(withUnknown)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := UnmarshalFrame(mustHex(t, "08011007621e0a122f6578616d706c652e4563686f2f4563686f120568656c6c6f18f403"))
		if err != nil {
			t.Fatal(err)
		}
		// Logical equality despite the unknown field (SNTR-SER-003).
		// proto.Equal is false when unknown bytes are retained, so
		// compare the interpreted fields instead.
		if f.GetRequest().GetMethod() != plain.GetRequest().GetMethod() ||
			string(f.GetRequest().GetPayload()) != string(plain.GetRequest().GetPayload()) {
			t.Fatal("unknown field changed the logical message")
		}
	})
	t.Run("empty-frame-rejected", func(t *testing.T) {
		_, err := UnmarshalFrame(mustHex(t, "0801"))
		rerr, ok := err.(*RpcError)
		if !ok || !IsInvalidArgument(rerr.Code) {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestGoldenRoundTrip re-encodes every decoded golden fixture and
// requires logical (not byte-identical) round-trip stability.
func TestGoldenRoundTrip(t *testing.T) {
	hexes := []string{
		"0801521e080110011a186f70617175652d746573742d63726564656e7469616c2d41",
		"08015a110a0f666978747572652d636f6e6e2d3031",
		"08011007621e0a122f6578616d706c652e4563686f2f4563686f120568656c6c6f18f403",
		"0801100d62190a122f6578616d706c652e4563686f2f4563686f120018f403",
		"080110076a070a0568656c6c6f",
		"0801100d6a020a00",
		"080110076a141212080c120e756e6b6e6f776e206d6574686f64",
		"08017a090a076576656e742d31",
		"0801100c7200",
	}
	for _, h := range hexes {
		f, err := UnmarshalFrame(mustHex(t, h))
		if err != nil {
			t.Fatalf("%s: %v", h, err)
		}
		raw, err := MarshalFrame(f)
		if err != nil {
			t.Fatalf("%s: %v", h, err)
		}
		back, err := UnmarshalFrame(raw)
		if err != nil {
			t.Fatalf("%s: %v", h, err)
		}
		if !proto.Equal(f, back) {
			t.Fatalf("%s: logical round trip differs", h)
		}
	}
}

// TestDuplicateBodies feeds raw wire with two body alternatives. The
// generated decoder would collapse them into the last one; the pre-scan
// must reject them first (RFC 0001 B4).
func TestDuplicateBodies(t *testing.T) {
	t.Run("request-plus-result", func(t *testing.T) {
		// GOLD-PROT-REQ-01 with a result alternative appended.
		raw := mustHex(t, "08011007621e0a122f6578616d706c652e4563686f2f4563686f120568656c6c6f18f4036a070a0568656c6c6f")
		_, err := UnmarshalFrame(raw)
		rerr, ok := err.(*RpcError)
		if !ok || !IsInvalidArgument(rerr.Code) || !strings.Contains(rerr.Message, "multiple bodies") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("request-plus-cancel", func(t *testing.T) {
		raw := mustHex(t, "08011007621e0a122f6578616d706c652e4563686f2f4563686f120568656c6c6f18f4037200")
		_, err := UnmarshalFrame(raw)
		rerr, ok := err.(*RpcError)
		if !ok || !IsInvalidArgument(rerr.Code) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("result-two-outcomes", func(t *testing.T) {
		// result{...} with payload AND error alternatives on the wire.
		raw := mustHex(t, "080110076a1b0a0568656c6c6f1212080c120e756e6b6e6f776e206d6574686f64")
		_, err := UnmarshalFrame(raw)
		rerr, ok := err.(*RpcError)
		if !ok || !IsInvalidArgument(rerr.Code) || !strings.Contains(rerr.Message, "multiple outcomes") {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestReservedFields enforces reserved envelope numbers 16/17 and names
// event/resume/ack (SNTR-SER-008).
func TestReservedFields(t *testing.T) {
	t.Run("field-16", func(t *testing.T) {
		_, err := UnmarshalFrame(mustHex(t, "0801800100"))
		if rerr, ok := err.(*RpcError); !ok || !IsInvalidArgument(rerr.Code) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("field-17", func(t *testing.T) {
		_, err := UnmarshalFrame(mustHex(t, "08018a0100"))
		if rerr, ok := err.(*RpcError); !ok || !IsInvalidArgument(rerr.Code) {
			t.Fatalf("err = %v", err)
		}
	})
	for _, name := range []string{"event", "resume", "ack"} {
		if !IsReservedFieldName(name) {
			t.Fatalf("%q not reserved", name)
		}
	}
	if IsReservedFieldName("hello") || IsReservedFieldName("notification") {
		t.Fatal("live body name reported reserved")
	}
	if !IsReservedFieldNumber(16) || !IsReservedFieldNumber(17) || IsReservedFieldNumber(15) {
		t.Fatal("reserved number set wrong")
	}
}

// TestTruncation rejects truncated varints, truncated messages, illegal
// wire types, and invalid UTF-8 deterministically (SNTR-SER-007).
func TestTruncation(t *testing.T) {
	cases := map[string]string{
		"truncated-varint": "08",
		"truncated-frame":  "08011007621e0a122f6578616d706c652e4563686f2f",
		"illegal-group":    "0b",
		"bad-length":       "0801ff",
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := UnmarshalFrame(mustHex(t, h))
			if rerr, ok := err.(*RpcError); !ok || !IsInvalidArgument(rerr.Code) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	t.Run("invalid-utf8-method", func(t *testing.T) {
		// Frame{id:7, request{method: "\xff" (invalid UTF-8)}}.
		raw := mustHex(t, "0801100762030a01ff")
		_, err := UnmarshalFrame(raw)
		if rerr, ok := err.(*RpcError); !ok || !IsInvalidArgument(rerr.Code) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("empty-input", func(t *testing.T) {
		_, err := UnmarshalFrame(nil)
		if rerr, ok := err.(*RpcError); !ok || !IsInvalidArgument(rerr.Code) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		_, err := UnmarshalFrame(make([]byte, MaxFrameBytes+1))
		if rerr, ok := err.(*RpcError); !ok || !IsResourceExhausted(rerr.Code) {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestEnumNormalization maps unknown received codes to UNKNOWN, never to
// success, and rejects code zero as a failure (SNTR-ERR-005/001).
func TestEnumNormalization(t *testing.T) {
	t.Run("unknown-code-normalizes", func(t *testing.T) {
		// result{error{code: 99}} — no message.
		f, err := UnmarshalFrame(mustHex(t, "080110076a0412020863"))
		if err != nil {
			t.Fatal(err)
		}
		if got := f.GetResult().GetError().GetCode(); got != ErrorCodeUnknown {
			t.Fatalf("code = %v", got)
		}
	})
	t.Run("zero-code-rejected", func(t *testing.T) {
		// result{error{}} — code 0 is never a valid failure.
		_, err := UnmarshalFrame(mustHex(t, "080110076a021200"))
		if rerr, ok := err.(*RpcError); !ok || !IsInvalidArgument(rerr.Code) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("emission-normalizes", func(t *testing.T) {
		f := NewResultFrame(1, 9, &RpcResult{Outcome: &syntrav1.RpcResult_Error{Error: &syntrav1.RpcError{Code: 99, Message: "future"}}})
		// Bypass the constructor (which maps Unspecified only) to prove
		// MarshalFrame normalizes any out-of-range code on emission.
		if _, err := MarshalFrame(f); err != nil {
			t.Fatal(err)
		}
		if got := f.GetResult().GetError().GetCode(); got != ErrorCodeUnknown {
			t.Fatalf("emitted code = %v", got)
		}
	})
	t.Run("table", func(t *testing.T) {
		if NormalizeErrorCode(-1) != ErrorCodeUnknown || NormalizeErrorCode(99) != ErrorCodeUnknown {
			t.Fatal("out-of-range must normalize to UNKNOWN")
		}
		for n := int32(0); n <= 16; n++ {
			if NormalizeErrorCode(n) != ErrorCode(n) {
				t.Fatalf("code %d changed", n)
			}
		}
		if ErrorCodeName(99) != "ERROR_CODE_UNKNOWN" {
			t.Fatal("unknown number must report as ERROR_CODE_UNKNOWN")
		}
	})
}

// TestMethodValidation checks the canonical /package.Service/Method shape
// (SNTR-RPC-001).
func TestMethodValidation(t *testing.T) {
	valid := []string{"/example.Echo/Echo", "/example.KV/Get", "/a.B/C", "/pkg.SVC/method_1", "/x-y.Z/w"}
	for _, m := range valid {
		if err := ValidateMethod(m); err != nil {
			t.Fatalf("%q: %v", m, err)
		}
	}
	invalid := []string{"", "example.Echo/Echo", "/example.Echo", "/example/Echo/Echo/Extra", "//Echo", "/example/", "example", "/example.Echo/Echo WithSpace", "/example.Echo/Ech\to", string([]byte{0x2f, 0xff})}
	for _, m := range invalid {
		if err := ValidateMethod(m); err == nil {
			t.Fatalf("%q accepted", m)
		} else if rerr, ok := err.(*RpcError); !ok || !IsInvalidArgument(rerr.Code) {
			t.Fatalf("%q: wrong error %v", m, err)
		}
	}
	if err := ValidateMethod("/" + strings.Repeat("a", MaxMethodLength)); err == nil {
		t.Fatal("oversize method accepted")
	}
}

// TestFrameValidationMatrix covers the request_id polarity and variant
// legality matrix (SNTR-WIRE-003).
func TestFrameValidationMatrix(t *testing.T) {
	req := &RpcRequest{Method: "/example.Echo/Echo"}
	cases := []struct {
		name    string
		frame   *Frame
		wantErr bool
	}{
		{"request-zero-id", NewRequestFrame(1, 0, req), true},
		{"result-zero-id", NewResultFrame(1, 0, NewSuccessResult(nil)), true},
		{"cancel-zero-id", NewCancelFrame(1, 0), true},
		{"ready-nonzero-id", &Frame{Version: 1, RequestId: 3, Body: &syntrav1.Frame_Ready{Ready: &ServerReady{ConnectionId: "x"}}}, true},
		{"notification-nonzero-id", &Frame{Version: 1, RequestId: 3, Body: &syntrav1.Frame_Notification{Notification: &Notification{}}}, true},
		{"hello-zero-version", NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 0), true},
		{"hello-version-mismatch", &Frame{Version: 1, Body: &syntrav1.Frame_Hello{Hello: &ClientHello{MinVersion: 1, MaxVersion: 2}}}, true},
		{"hello-min-max-inverted", NewHelloFrame(&ClientHello{MinVersion: 2, MaxVersion: 1}, 2), true},
		{"ready-empty-connid", NewReadyFrame(1, &ServerReady{}), true},
		{"result-missing-outcome", NewResultFrame(1, 5, &RpcResult{}), true},
		{"result-zero-code", NewResultFrame(1, 5, &RpcResult{Outcome: &syntrav1.RpcResult_Error{Error: &syntrav1.RpcError{}}}), true},
		{"ok-request", NewRequestFrame(1, 7, req), false},
		{"ok-result", NewResultFrame(1, 7, NewSuccessResult([]byte("hi"))), false},
		{"ok-notification", NewNotificationFrame(1, &Notification{}), false},
		{"ok-cancel", NewCancelFrame(1, 9), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := MarshalFrame(tc.frame)
			if tc.wantErr && err == nil {
				t.Fatal("accepted invalid frame")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("rejected valid frame: %v", err)
			}
		})
	}
}

func TestDecodeDefersOnlyRequestMethodValidation(t *testing.T) {
	for _, method := range []string{"", "not-a-method", "/example.Echo/With Space", "/" + strings.Repeat("a", MaxMethodLength)} {
		t.Run(method, func(t *testing.T) {
			f := NewRequestFrame(1, 7, &RpcRequest{Method: method})
			if code := callCode(t, ValidateFrame(f)); code != ErrorCodeInvalidArgument {
				t.Fatalf("ValidateFrame code = %v", code)
			}
			if _, err := MarshalFrame(f); callCode(t, err) != ErrorCodeInvalidArgument {
				t.Fatalf("MarshalFrame error = %v", err)
			}
			raw, err := proto.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := UnmarshalFrame(raw)
			if err != nil || !proto.Equal(decoded, f) {
				t.Fatalf("decode = %v, %v", decoded, err)
			}
		})
	}
	for _, f := range []*Frame{
		NewRequestFrame(1, 0, &RpcRequest{}),
		NewRequestFrame(0, 7, &RpcRequest{}),
		NewRequestFrame(2, 7, &RpcRequest{}),
		NewReadyFrame(1, &ServerReady{}),
		NewResultFrame(1, 7, &RpcResult{}),
	} {
		raw, err := proto.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := UnmarshalFrame(raw); err == nil {
			t.Fatalf("accepted structurally invalid frame: %v", f)
		}
	}
}

// TestTrackerLifecycle covers duplicate outstanding IDs, reuse after
// completion, unknown finishes, cancel advisory semantics, and expiry.
func TestTrackerLifecycle(t *testing.T) {
	now := time.Now()
	tr := NewTracker()
	if err := tr.StartWithBudget(now, 1, "/example.Echo/Echo", 1000); err != nil {
		t.Fatal(err)
	}
	if err := tr.StartWithBudget(now, 1, "/example.Echo/Echo", 1000); err == nil {
		t.Fatal("duplicate outstanding id accepted")
	}
	if !tr.Cancel(1) || !tr.IsCancelled(1) {
		t.Fatal("cancel not observed")
	}
	if tr.Cancel(999) || tr.IsCancelled(999) {
		t.Fatal("unknown cancel reported")
	}
	// Advisory cancel still accepts the late terminal result.
	if err := tr.FinishResult(1, NewSuccessResult([]byte("late"))); err != nil {
		t.Fatalf("late finish after cancel: %v", err)
	}
	// Reuse after terminal result is permitted by the core model.
	if err := tr.StartWithBudget(now, 1, "/example.Echo/Echo", 1000); err != nil {
		t.Fatalf("reuse after completion: %v", err)
	}
	if err := tr.FinishResult(1, &RpcResult{}); err == nil {
		t.Fatal("missing outcome accepted")
	}
	if err := tr.FinishResult(999, NewSuccessResult(nil)); err == nil {
		t.Fatal("unknown finish accepted")
	}
	if err := tr.FinishResult(1, NewSuccessResult([]byte("ok"))); err != nil {
		t.Fatal(err)
	}
	// Expiry removes and reports exactly once.
	if err := tr.StartWithBudget(now, 2, "/example.Echo/Echo", 50); err != nil {
		t.Fatal(err)
	}
	expired := tr.Expired(now.Add(100 * time.Millisecond))
	if len(expired) != 1 || expired[0] != 2 {
		t.Fatalf("expired = %v", expired)
	}
	if err := tr.FinishResult(2, NewSuccessResult(nil)); err == nil {
		t.Fatal("finish after expiry accepted")
	}
	if n := tr.Pending(); n != 0 {
		t.Fatalf("pending = %d", n)
	}
}

// TestTrackerConcurrencyBound enforces the 16-concurrent minimum budget.
func TestTrackerConcurrencyBound(t *testing.T) {
	tr := NewTracker()
	now := time.Now()
	for i := uint64(1); i <= MaxConcurrentRPCs; i++ {
		if err := tr.StartWithBudget(now, i, "/example.Echo/Echo", 1000); err != nil {
			t.Fatalf("slot %d: %v", i, err)
		}
	}
	if err := tr.StartWithBudget(now, MaxConcurrentRPCs+1, "/example.Echo/Echo", 1000); err == nil {
		t.Fatal("budget overflow accepted")
	} else if rerr, ok := err.(*RpcError); !ok || !IsResourceExhausted(rerr.Code) {
		t.Fatalf("wrong error: %v", err)
	}
}

// TestHandshakeMachine covers negotiation and the six-state transitions.
func TestHandshakeMachine(t *testing.T) {
	v, err := NegotiateVersion(1, 1)
	if err != nil || v != 1 {
		t.Fatalf("v=%d err=%v", v, err)
	}
	if _, err := NegotiateVersion(2, 2); err == nil {
		t.Fatal("disjoint range accepted")
	}
	if _, err := NegotiateVersion(0, 1); err == nil {
		t.Fatal("zero bound accepted")
	}
	c, err := NewConnection(HandshakeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.OnHello(&ClientHello{MinVersion: 1, MaxVersion: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.OnHello(&ClientHello{MinVersion: 1, MaxVersion: 1}); err == nil {
		t.Fatal("second hello accepted")
	}
	if err := c.BeginAuth(); err != nil {
		t.Fatal(err)
	}
	if err := c.AuthSuccess(""); err == nil {
		t.Fatal("empty principal accepted")
	}
	if err := c.AuthSuccess("principal-1"); err != nil {
		t.Fatal(err)
	}
	if st := c.State(); st != StateActive {
		t.Fatalf("state = %s", st)
	}
	next, err := NextState(StateActive, BodyKindReady)
	if err == nil || next != StateClosing {
		t.Fatalf("re-handshake: %v %v", next, err)
	}
	if _, err := NextState(StateClosed, BodyKindRequest); err == nil {
		t.Fatal("closed accepted frame")
	}
}

func TestCredentialAndConnectionID(t *testing.T) {
	if err := ValidateCredentialSize(make([]byte, MaxCredentialBytes+1)); err == nil {
		t.Fatal("oversize credential accepted")
	}
	if err := ValidateCredentialSize(nil); err != nil {
		t.Fatalf("empty credential rejected: %v", err)
	}
	a, err := NewConnectionID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewConnectionID()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 || a == b {
		t.Fatalf("connection ids: %q %q", a, b)
	}
}
