package syntra

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestUnknownFrameContentClassification(t *testing.T) {
	known, err := MarshalFrame(NewRequestFrame(1, 7, &RpcRequest{Method: "/example.Echo/Echo"}))
	if err != nil {
		t.Fatal(err)
	}
	// No future-body tag interval is allocated by envelope.proto. Exercise
	// unallocated fields below and above known bodies, including Rust's
	// field-90 fixture and the maximum legal protobuf field number.
	for _, num := range []protowire.Number{3, 9, 18, 31, 90, 100, protowire.MaxValidNumber} {
		for _, typ := range []protowire.Type{protowire.VarintType, protowire.Fixed32Type, protowire.Fixed64Type, protowire.BytesType} {
			t.Run(fmt.Sprintf("field%d/type%d", num, typ), func(t *testing.T) {
				unknown := protowire.AppendTag(nil, num, typ)
				switch typ {
				case protowire.VarintType:
					unknown = protowire.AppendVarint(unknown, 1)
				case protowire.Fixed32Type:
					unknown = protowire.AppendFixed32(unknown, 1)
				case protowire.Fixed64Type:
					unknown = protowire.AppendFixed64(unknown, 1)
				case protowire.BytesType:
					unknown = protowire.AppendBytes(unknown, []byte("x"))
				}
				_, err := UnmarshalFrame(append([]byte{0x08, 0x01}, unknown...))
				var rpcErr *RpcError
				if !errors.As(err, &rpcErr) || rpcErr.Code != ErrorCodeUnimplemented {
					t.Fatalf("unknown-only error = %v, want UNIMPLEMENTED", err)
				}
				for _, raw := range [][]byte{
					append(append([]byte(nil), known...), unknown...),
					append(append([]byte(nil), unknown...), known...),
				} {
					f, err := UnmarshalFrame(raw)
					if err != nil || f.GetRequestId() != 7 || f.GetRequest().GetMethod() != "/example.Echo/Echo" {
						t.Fatalf("known body with unknown metadata = %v, %v", f, err)
					}
					if len(f.ProtoReflect().GetUnknown()) == 0 {
						t.Fatal("unknown metadata was discarded")
					}
				}
			})
		}
	}
}

func TestDuplicateScalarsFollowProtobufLastWins(t *testing.T) {
	// Duplicate version/request_id follow protobuf merge semantics
	// (last wins), matching the Rust core and SNTR-SER-002. Duplicate
	// bodies remain rejected (see TestDuplicateBodies).
	for name, tc := range map[string]struct {
		hex     string
		version uint32
		id      uint64
	}{
		"version-2-then-1":    {"080208011007621e0a122f6578616d706c652e4563686f2f4563686f120568656c6c6f18f403", 1, 7},
		"request-id-7-then-8": {"080110071008621e0a122f6578616d706c652e4563686f2f4563686f120568656c6c6f18f403", 1, 8},
	} {
		t.Run(name, func(t *testing.T) {
			f, err := UnmarshalFrame(mustHex(t, tc.hex))
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if f.GetVersion() != tc.version || f.GetRequestId() != tc.id {
				t.Fatalf("got v%d id%d, want v%d id%d", f.GetVersion(), f.GetRequestId(), tc.version, tc.id)
			}
		})
	}
}

func TestNonemptyCancelTolerated(t *testing.T) {
	// Cancel carries no defined fields; inner unknown bytes are tolerated
	// per SNTR-SER-003, matching the Rust core.
	for name, hex := range map[string]string{
		"empty":          "0801100c7200",
		"unknown-varint": "0801100c72020801",
	} {
		t.Run(name, func(t *testing.T) {
			f, err := UnmarshalFrame(mustHex(t, hex))
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if f.GetRequestId() != 12 || f.GetCancel() == nil {
				t.Fatalf("cancel = %+v", f)
			}
		})
	}
}

func TestNestedUnassignedNumbersTolerated(t *testing.T) {
	// Numbers 16/17 are reserved only at the top-level Frame. Inside
	// nested messages they are unassigned unknown fields tolerated per
	// SNTR-SER-003, matching the Rust core. Top-level 16/17 stay rejected.
	for name, hex := range map[string]string{
		"nested-16": "080110076a0a0a0568656c6c6f800100",
		"nested-17": "080110076a0a0a0568656c6c6f880100",
	} {
		t.Run(name, func(t *testing.T) {
			f, err := UnmarshalFrame(mustHex(t, hex))
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if string(f.GetResult().GetPayload()) != "hello" {
				t.Fatalf("payload = %q", f.GetResult().GetPayload())
			}
		})
	}
	for name, hex := range map[string]string{
		"top-16": "0801800100",
		"top-17": "08018a0100",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := UnmarshalFrame(mustHex(t, hex))
			var rpcErr *RpcError
			if !errors.As(err, &rpcErr) || rpcErr.Code != ErrorCodeInvalidArgument {
				t.Fatalf("error = %v, want INVALID_ARGUMENT", err)
			}
		})
	}
}

func TestUnknownFrameContentDoesNotHideInvalidWire(t *testing.T) {
	for name, raw := range map[string][]byte{
		"empty-body":           {0x08, 0x01},
		"reserved16":           {0x08, 0x01, 0x82, 0x01, 0},
		"reserved17":           {0x08, 0x01, 0x8a, 0x01, 0},
		"truncated-unknown":    {0x08, 0x01, 0xd2, 0x05, 0x02, 'x'},
		"unknown-then-bad-tag": {0x08, 0x01, 0xd2, 0x05, 0x01, 'x', 0},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := UnmarshalFrame(raw)
			var rpcErr *RpcError
			if !errors.As(err, &rpcErr) || rpcErr.Code != ErrorCodeInvalidArgument {
				t.Fatalf("error = %v, want INVALID_ARGUMENT", err)
			}
		})
	}
}
