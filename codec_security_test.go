package syntra

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func codecSecurityBytes(num protowire.Number, value []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, num, protowire.BytesType), value)
}

func codecSecurityVarint(num protowire.Number, value uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, num, protowire.VarintType), value)
}

func codecSecurityGroups(levels int, value []byte) []byte {
	var raw []byte
	for i := 0; i < levels; i++ {
		raw = protowire.AppendTag(raw, protowire.Number(100+i), protowire.StartGroupType)
	}
	raw = append(raw, value...)
	for i := levels - 1; i >= 0; i-- {
		raw = protowire.AppendTag(raw, protowire.Number(100+i), protowire.EndGroupType)
	}
	return raw
}

func codecSecurityMarshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	raw, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func codecSecurityInvalid(t *testing.T, err error) {
	t.Helper()
	var rpcErr *RpcError
	if !errors.As(err, &rpcErr) || rpcErr.Code != ErrorCodeInvalidArgument {
		t.Fatalf("error = %v, want INVALID_ARGUMENT", err)
	}
}

type codecSecurityMessage struct {
	name    string
	frame   *Frame
	message proto.Message
	depth   int
}

func codecSecurityMessages() []codecSecurityMessage {
	root := NewCancelFrame(1, 7)
	hello := &ClientHello{MinVersion: 1, MaxVersion: 1}
	ready := &ServerReady{ConnectionId: "diagnostic-id"}
	request := &RpcRequest{Method: "/example.Echo/Echo"}
	result := NewSuccessResult(nil)
	cancel := NewCancelFrame(1, 7)
	notification := &Notification{}
	failure := NewWireErrorResult(ErrorCodeInternal, "public failure")
	return []codecSecurityMessage{
		{"frame", root, root, 1},
		{"hello", NewHelloFrame(hello, 1), hello, 2},
		{"ready", NewReadyFrame(1, ready), ready, 2},
		{"request", NewRequestFrame(1, 7, request), request, 2},
		{"result", NewResultFrame(1, 7, result), result, 2},
		{"cancel", cancel, cancel.GetCancel(), 2},
		{"notification", NewNotificationFrame(1, notification), notification, 2},
		{"error", NewResultFrame(1, 7, failure), failure.GetError(), 3},
	}
}

func TestCodecSecurityReservedEmission(t *testing.T) {
	for _, num := range []protowire.Number{16, 17} {
		for _, typ := range []protowire.Type{0, 1, 2, 3, 5} {
			t.Run(fmt.Sprintf("field%d/type%d", num, typ), func(t *testing.T) {
				unknown := protowire.AppendTag(nil, num, typ)
				switch typ {
				case protowire.VarintType:
					unknown = protowire.AppendVarint(unknown, 1)
				case protowire.Fixed64Type:
					unknown = protowire.AppendFixed64(unknown, 1)
				case protowire.BytesType:
					unknown = protowire.AppendBytes(unknown, nil)
				case protowire.StartGroupType:
					unknown = protowire.AppendTag(unknown, num, protowire.EndGroupType)
				case protowire.Fixed32Type:
					unknown = protowire.AppendFixed32(unknown, 1)
				}
				frame := NewCancelFrame(1, 7)
				frame.ProtoReflect().SetUnknown(unknown)
				out, err := MarshalFrame(frame)
				codecSecurityInvalid(t, err)
				if out != nil {
					t.Fatal("invalid emission returned wire bytes")
				}
				_, err = UnmarshalFrame(codecSecurityMarshal(t, frame))
				codecSecurityInvalid(t, err)
			})
		}
	}
}

func TestCodecSecurityInjectedBodiesAndOutcomes(t *testing.T) {
	for num := protowire.Number(10); num <= 15; num++ {
		t.Run(fmt.Sprintf("body%d", num), func(t *testing.T) {
			frame := NewCancelFrame(1, 7)
			frame.ProtoReflect().SetUnknown(codecSecurityBytes(num, nil))
			out, err := MarshalFrame(frame)
			codecSecurityInvalid(t, err)
			if out != nil {
				t.Fatal("duplicate body returned wire bytes")
			}
			raw := codecSecurityMarshal(t, frame)
			codecSecurityInvalid(t, scanFrameTags(raw))
			_, err = UnmarshalFrame(raw)
			codecSecurityInvalid(t, err)
		})
	}
	for _, failure := range []bool{false, true} {
		for num := protowire.Number(1); num <= 2; num++ {
			t.Run(fmt.Sprintf("failure%t/outcome%d", failure, num), func(t *testing.T) {
				result := NewSuccessResult(nil)
				if failure {
					result = NewWireErrorResult(ErrorCodeInternal, "public failure")
				}
				result.ProtoReflect().SetUnknown(codecSecurityBytes(num, nil))
				frame := NewResultFrame(1, 7, result)
				out, err := MarshalFrame(frame)
				codecSecurityInvalid(t, err)
				if out != nil {
					t.Fatal("duplicate outcome returned wire bytes")
				}
				raw := codecSecurityMarshal(t, frame)
				codecSecurityInvalid(t, scanFrameTags(raw))
				_, err = UnmarshalFrame(raw)
				codecSecurityInvalid(t, err)
			})
		}
	}
}

func TestCodecSecurityMetadataRoundTrip(t *testing.T) {
	for _, tc := range codecSecurityMessages() {
		t.Run(tc.name, func(t *testing.T) {
			metadata := codecSecurityVarint(100, 9)
			metadata = append(metadata, protowire.AppendFixed32(protowire.AppendTag(nil, 101, protowire.Fixed32Type), 42)...)
			metadata = append(metadata, protowire.AppendFixed64(protowire.AppendTag(nil, 102, protowire.Fixed64Type), 43)...)
			metadata = append(metadata, codecSecurityBytes(103, []byte{0xff, 0, 0x80})...)
			metadata = append(metadata, codecSecurityVarint(protowire.MaxValidNumber, 1)...)
			if tc.depth > 1 {
				metadata = append(metadata, codecSecurityVarint(16, 1)...)
				metadata = append(metadata, codecSecurityBytes(17, nil)...)
			}
			// Field numbers inside unknown groups belong to the group, not Frame or RpcResult.
			groupFields := append(codecSecurityVarint(16, 1), codecSecurityBytes(17, nil)...)
			groupFields = append(groupFields, codecSecurityBytes(10, nil)...)
			groupFields = append(groupFields, codecSecurityBytes(13, nil)...)
			groupFields = append(groupFields, codecSecurityBytes(1, nil)...)
			groupFields = append(groupFields, codecSecurityBytes(2, nil)...)
			metadata = append(metadata, codecSecurityGroups(2, groupFields)...)
			metadata = append(metadata, codecSecurityVarint(104, 10)...)
			tc.message.ProtoReflect().SetUnknown(metadata)
			raw, err := MarshalFrame(tc.frame)
			if err != nil {
				t.Fatal(err)
			}
			round, err := UnmarshalFrame(raw)
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(tc.frame, round) {
				t.Fatal("metadata round trip changed the message")
			}
			if allocs := testing.AllocsPerRun(100, func() {
				if err := scanFrameTags(raw); err != nil {
					panic(err)
				}
			}); allocs != 0 {
				t.Fatalf("successful scan allocations = %g, want 0", allocs)
			}
		})
	}
}

func TestCodecSecurityCredentialBound(t *testing.T) {
	for _, size := range []int{0, MaxCredentialBytes, MaxCredentialBytes + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			frame := NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1, Credential: bytes.Repeat([]byte{0xff}, size)}, 1)
			raw := codecSecurityMarshal(t, frame)
			scanErr := scanFrameTags(raw)
			_, decodeErr := UnmarshalFrame(raw)
			out, encodeErr := MarshalFrame(frame)
			if size > MaxCredentialBytes {
				codecSecurityInvalid(t, scanErr)
				codecSecurityInvalid(t, decodeErr)
				codecSecurityInvalid(t, encodeErr)
				if out != nil {
					t.Fatal("oversized credential returned wire bytes")
				}
			} else if scanErr != nil || decodeErr != nil || encodeErr != nil {
				t.Fatalf("bounded credential failed: scan=%v decode=%v encode=%v", scanErr, decodeErr, encodeErr)
			}
		})
	}
	for _, oversizedFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("duplicate/oversizedFirst%t", oversizedFirst), func(t *testing.T) {
			large := codecSecurityBytes(3, bytes.Repeat([]byte("codec-private-marker"), MaxCredentialBytes))
			small := codecSecurityBytes(3, []byte{0xff, 0})
			hello := []byte{8, 1, 16, 1}
			if oversizedFirst {
				hello = append(append(hello, large...), small...)
			} else {
				hello = append(append(hello, small...), large...)
			}
			raw := append([]byte{8, 1}, codecSecurityBytes(10, hello)...)
			err := scanFrameTags(raw)
			codecSecurityInvalid(t, err)
			if strings.Contains(err.Error(), "codec-private-marker") {
				t.Fatal("credential contents appeared in error")
			}
			_, err = UnmarshalFrame(raw)
			codecSecurityInvalid(t, err)
		})
	}
	t.Run("retained-credential-injection", func(t *testing.T) {
		hello := &ClientHello{MinVersion: 1, MaxVersion: 1, Credential: []byte{0xff}}
		hello.ProtoReflect().SetUnknown(codecSecurityBytes(3, make([]byte, MaxCredentialBytes+1)))
		out, err := MarshalFrame(NewHelloFrame(hello, 1))
		codecSecurityInvalid(t, err)
		if out != nil {
			t.Fatal("injected oversized credential returned wire bytes")
		}
	})
}

func TestCodecSecurityDuplicateScalarsLastWins(t *testing.T) {
	hello := []byte{8, 2, 8, 1, 16, 2, 16, 1}
	hello = append(hello, codecSecurityBytes(3, []byte{0xff})...)
	hello = append(hello, codecSecurityBytes(3, []byte{0, 0x80})...)
	raw := append([]byte{8, 2, 8, 1, 16, 7, 16, 0}, codecSecurityBytes(10, hello)...)
	frame, err := UnmarshalFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	if frame.GetVersion() != 1 || frame.GetRequestId() != 0 || frame.GetHello().GetMinVersion() != 1 ||
		frame.GetHello().GetMaxVersion() != 1 || !bytes.Equal(frame.GetHello().GetCredential(), []byte{0, 0x80}) {
		t.Fatal("duplicate scalar last-wins semantics changed")
	}
	result := codecSecurityBytes(2, []byte{8, 0, 8, byte(ErrorCodeInternal)})
	raw = append([]byte{8, 1, 16, 7}, codecSecurityBytes(13, result)...)
	frame, err = UnmarshalFrame(raw)
	if err != nil || frame.GetResult().GetError().GetCode() != ErrorCodeInternal {
		t.Fatalf("duplicate error code failed: %v", err)
	}
}

func TestCodecSecurityMalformedUnknownWire(t *testing.T) {
	start := protowire.AppendTag(nil, 100, protowire.StartGroupType)
	end := protowire.AppendTag(nil, 100, protowire.EndGroupType)
	badNumber := protowire.AppendVarint(nil, uint64(protowire.MaxValidNumber+1)<<3)
	for _, tc := range codecSecurityMessages() {
		for name, unknown := range map[string][]byte{
			"zero-field":             {0},
			"field-above-maximum":    append(append([]byte(nil), badNumber...), 1),
			"overflow-tag":           protowire.AppendVarint(nil, ^uint64(0)),
			"wire-type6":             protowire.AppendTag(nil, 100, 6),
			"wire-type7":             protowire.AppendTag(nil, 100, 7),
			"truncated-tag":          {0x80},
			"truncated-varint":       protowire.AppendTag(nil, 100, protowire.VarintType),
			"truncated-fixed32":      protowire.AppendTag(nil, 100, protowire.Fixed32Type),
			"truncated-fixed64":      protowire.AppendTag(nil, 100, protowire.Fixed64Type),
			"truncated-bytes":        append(protowire.AppendTag(nil, 100, protowire.BytesType), 1),
			"unexpected-end":         end,
			"missing-end":            start,
			"mismatched-end":         protowire.AppendTag(append([]byte(nil), start...), 101, protowire.EndGroupType),
			"nested-mismatched-end":  append(append(append([]byte(nil), start...), codecSecurityGroups(1, nil)...), protowire.AppendTag(nil, 101, protowire.EndGroupType)...),
			"group-invalid-number":   append(append(append([]byte(nil), start...), badNumber...), end...),
			"group-zero-field":       append(append(append([]byte(nil), start...), 0), end...),
			"group-invalid-type":     append(append(append([]byte(nil), start...), protowire.AppendTag(nil, 101, 6)...), end...),
			"group-truncated-varint": append(append([]byte(nil), start...), protowire.AppendTag(nil, 101, protowire.VarintType)...),
		} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				tc.message.ProtoReflect().SetUnknown(unknown)
				raw := codecSecurityMarshal(t, tc.frame)
				codecSecurityInvalid(t, scanFrameTags(raw))
				frame, err := UnmarshalFrame(raw)
				codecSecurityInvalid(t, err)
				if frame != nil {
					t.Fatal("malformed decode returned a frame")
				}
				out, err := MarshalFrame(tc.frame)
				codecSecurityInvalid(t, err)
				if out != nil {
					t.Fatal("malformed retained unknown returned wire bytes")
				}
			})
		}
	}
}

func TestCodecSecurityCombinedRecursionLimit(t *testing.T) {
	for _, tc := range codecSecurityMessages() {
		for _, totalDepth := range []int{31, 32, 33, 256} {
			t.Run(fmt.Sprintf("%s/depth%d", tc.name, totalDepth), func(t *testing.T) {
				tc.message.ProtoReflect().SetUnknown(codecSecurityGroups(totalDepth-tc.depth, codecSecurityVarint(200, 1)))
				raw := codecSecurityMarshal(t, tc.frame)
				scanErr := scanFrameTags(raw)
				_, decodeErr := UnmarshalFrame(raw)
				out, encodeErr := MarshalFrame(tc.frame)
				if totalDepth > 32 {
					codecSecurityInvalid(t, scanErr)
					codecSecurityInvalid(t, decodeErr)
					codecSecurityInvalid(t, encodeErr)
					if out != nil {
						t.Fatal("excessive recursion returned wire bytes")
					}
				} else {
					if scanErr != nil || decodeErr != nil || encodeErr != nil {
						t.Fatalf("bounded recursion failed: scan=%v decode=%v encode=%v", scanErr, decodeErr, encodeErr)
					}
					if allocs := testing.AllocsPerRun(100, func() {
						if err := scanFrameTags(raw); err != nil {
							panic(err)
						}
					}); allocs != 0 {
						t.Fatalf("depth-limited successful scan allocations = %g, want 0", allocs)
					}
				}
			})
		}
	}
}

func TestCodecSecurityOpaqueBytesUnchanged(t *testing.T) {
	for name, opaque := range map[string][]byte{
		"arbitrary":        {0xff, 0, 0x80, 0x0f},
		"deep-groups":      codecSecurityGroups(100, nil),
		"reserved-tags":    append(codecSecurityBytes(16, nil), codecSecurityBytes(17, nil)...),
		"duplicate-bodies": append(codecSecurityBytes(10, nil), codecSecurityBytes(13, nil)...),
	} {
		for kind, frame := range map[string]*Frame{
			"credential":   NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1, Credential: opaque}, 1),
			"request":      NewRequestFrame(1, 7, &RpcRequest{Method: "/example.Echo/Echo", Payload: opaque}),
			"result":       NewResultFrame(1, 7, NewSuccessResult(opaque)),
			"notification": NewNotificationFrame(1, &Notification{Payload: opaque}),
			"unknown":      NewCancelFrame(1, 7),
		} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				frame.ProtoReflect().SetUnknown(codecSecurityBytes(100, opaque))
				raw, err := MarshalFrame(frame)
				if err != nil {
					t.Fatal(err)
				}
				round, err := UnmarshalFrame(raw)
				if err != nil {
					t.Fatal(err)
				}
				if !proto.Equal(frame, round) {
					t.Fatal("opaque bytes changed")
				}
			})
		}
	}
}

func TestCodecSecurityMarshalFrameBound(t *testing.T) {
	for name, frame := range map[string]*Frame{
		"payload": NewNotificationFrame(1, &Notification{Payload: make([]byte, MaxFrameBytes)}),
		"unknown": NewCancelFrame(1, 7),
	} {
		t.Run(name, func(t *testing.T) {
			if name == "unknown" {
				frame.ProtoReflect().SetUnknown(codecSecurityBytes(100, make([]byte, MaxFrameBytes)))
			}
			out, err := MarshalFrame(frame)
			var rpcErr *RpcError
			if !errors.As(err, &rpcErr) || rpcErr.Code != ErrorCodeResourceExhausted || out != nil {
				t.Fatalf("oversized emission: bytes=%d error=%v", len(out), err)
			}
		})
	}
}
