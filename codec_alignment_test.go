package syntra

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func alignmentCode(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	var rpcErr *RpcError
	if !errors.As(err, &rpcErr) || rpcErr.Code != want {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func callCode(t *testing.T, err error) ErrorCode {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var rerr *RpcError
	if !errors.As(err, &rerr) {
		t.Fatalf("not an RpcError: %v", err)
	}
	return rerr.Code
}

func alignmentBytes(n protowire.Number, value []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, n, protowire.BytesType), value)
}

func TestAlignmentRawChoicesAndStructuralPrecedence(t *testing.T) {
	known := []byte{8, 1, 16, 7, 114, 0}
	for _, tag := range []protowire.Number{18, 31} {
		future := append([]byte{8, 1}, alignmentBytes(tag, nil)...)
		_, err := UnmarshalFrame(future)
		alignmentCode(t, err, ErrorCodeUnimplemented)
		_, err = UnmarshalFrame(append(append([]byte(nil), known...), alignmentBytes(tag, nil)...))
		alignmentCode(t, err, ErrorCodeInvalidArgument)
		_, err = UnmarshalFrame(append(future, 0))
		alignmentCode(t, err, ErrorCodeInvalidArgument)
	}
	for _, tag := range []protowire.Number{3, 9, 32, 90} {
		metadata := alignmentBytes(tag, []byte{0xff})
		_, err := UnmarshalFrame(append([]byte{8, 1}, metadata...))
		alignmentCode(t, err, ErrorCodeInvalidArgument)
		if _, err := UnmarshalFrame(append(append([]byte(nil), known...), metadata...)); err != nil {
			t.Fatal(err)
		}
	}
	for _, tag := range []protowire.Number{3, 15} {
		result := append([]byte{8, 1, 16, 7}, alignmentBytes(13, alignmentBytes(tag, nil))...)
		_, err := UnmarshalFrame(result)
		alignmentCode(t, err, ErrorCodeUnimplemented)
		result = append([]byte{8, 1, 16, 7}, alignmentBytes(13, append(alignmentBytes(1, nil), alignmentBytes(tag, nil)...))...)
		_, err = UnmarshalFrame(result)
		alignmentCode(t, err, ErrorCodeInvalidArgument)
	}
	// A semantic choice failure must not hide a later structural depth failure.
	groups := make([]byte, 0)
	for i := 0; i < 33; i++ {
		groups = protowire.AppendTag(groups, 100, protowire.StartGroupType)
	}
	for i := 0; i < 33; i++ {
		groups = protowire.AppendTag(groups, 100, protowire.EndGroupType)
	}
	for _, prefix := range [][]byte{
		append(append([]byte(nil), known...), alignmentBytes(14, nil)...),
		append([]byte{8, 1}, alignmentBytes(16, nil)...),
		append([]byte{8, 1}, alignmentBytes(18, nil)...),
	} {
		_, err := UnmarshalFrame(append(prefix, groups...))
		alignmentCode(t, err, ErrorCodeResourceExhausted)
	}
}

func TestAlignmentRawOccurrenceBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   protowire.Number
		field  protowire.Number
		bound  int
		prefix []byte
		code   ErrorCode
	}{
		{"credential", 10, 3, MaxCredentialBytes, []byte{8, 1, 16, 1}, ErrorCodeResourceExhausted},
		{"connection-id", 11, 1, MaxConnectionIDBytes, nil, ErrorCodeInvalidArgument},
		{"diagnostic", 13, 2, MaxDiagnosticBytes, []byte{8, 13}, ErrorCodeInvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, oversizedFirst := range []bool{false, true} {
				large := alignmentBytes(tc.field, bytes.Repeat([]byte("x"), tc.bound+1))
				small := alignmentBytes(tc.field, []byte("ok"))
				nested := append([]byte(nil), tc.prefix...)
				if oversizedFirst {
					nested = append(append(nested, large...), small...)
				} else {
					nested = append(append(nested, small...), large...)
				}
				if tc.body == 13 {
					nested = alignmentBytes(2, nested)
				}
				header := []byte{8, 1}
				if tc.body == 13 {
					header = append(header, 16, 7)
				}
				raw := append(header, alignmentBytes(tc.body, nested)...)
				_, err := UnmarshalFrame(raw)
				alignmentCode(t, err, tc.code)
				// Complete structural validation also checks overwritten strings.
				if tc.body == 10 {
					nested = append(nested, 0)
					_, err = UnmarshalFrame(append([]byte{8, 1}, alignmentBytes(10, nested)...))
					alignmentCode(t, err, ErrorCodeInvalidArgument)
				}
			}
		})
	}
	badUTF8 := append(alignmentBytes(1, []byte{0xff}), alignmentBytes(1, []byte("ok"))...)
	_, err := UnmarshalFrame(append([]byte{8, 1}, alignmentBytes(11, badUTF8)...))
	alignmentCode(t, err, ErrorCodeInvalidArgument)
}

func TestAlignmentStateDrainAndDiagnostics(t *testing.T) {
	for _, f := range []*Frame{
		NewResultFrame(1, 1, NewSuccessResult(nil)),
		NewCancelFrame(1, 1),
		NewNotificationFrame(1, &Notification{}),
	} {
		if err := ValidateFrameForState(f, StateClosing); err != nil {
			t.Fatal(err)
		}
	}
	alignmentCode(t, ValidateFrameForState(NewReadyFrame(1, &ServerReady{ConnectionId: "id"}), StateConnected), ErrorCodeFailedPrecondition)
	alignmentCode(t, ValidateFrameForState(NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1), StateActive), ErrorCodeFailedPrecondition)
	result := NewWireErrorResult(ErrorCodeInternal, string(bytes.Repeat([]byte("é"), MaxDiagnosticBytes)))
	if len(result.GetError().GetMessage()) != MaxDiagnosticBytes || ValidateResult(result) != nil {
		t.Fatal("public diagnostic was not bounded")
	}
}
