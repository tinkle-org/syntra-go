package syntra

import (
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

type wireSchema uint8

const (
	wireUnknown wireSchema = iota
	wireFrame
	wireHello
	wireReady
	wireRequest
	wireResult
	wireError
	wireCancel
	wireNotification
)

type rawChoice struct {
	count  int
	future bool
}

func (c rawChoice) validate() error {
	if c.count != 1 {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: exactly one raw choice required")
	}
	if c.future {
		return NewRpcError(ErrorCodeUnimplemented, "syntra: unknown variant")
	}
	return nil
}

type wireScan struct {
	reserved  bool
	version   uint32
	bodyTag   protowire.Number
	body      rawChoice
	outcome   rawChoice
	hasResult bool
	bound     *RpcError
}

// scanFrameTags completes a bounded structural walk before classifying raw
// choices and field admission. Every known occurrence is checked, including
// overwritten singular values; opaque bytes and unknown metadata stay opaque.
func scanFrameTags(data []byte) error {
	scan, err := scanWireStructure(data)
	if err != nil {
		return err
	}
	return scan.validate(false)
}

func (s wireScan) validate(allowMissingOutcome bool) error {
	if s.reserved {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: reserved frame field number")
	}
	if err := s.body.validate(); err != nil {
		return err
	}
	if s.hasResult && !(allowMissingOutcome && s.outcome.count == 0) {
		if err := s.outcome.validate(); err != nil {
			return err
		}
	}
	if s.bound != nil {
		return s.bound
	}
	return nil
}

func scanWireStructure(data []byte) (wireScan, error) {
	var scan wireScan
	if err := ValidateFrameSize(len(data)); err != nil {
		return scan, err
	}
	if len(data) == 0 {
		return scan, NewRpcError(ErrorCodeInvalidArgument, "syntra: empty frame")
	}
	_, err := walkWire(data, wireFrame, 0, 0, &scan)
	return scan, err
}

// invalidResultID recovers correlation only for a missing outcome or a zero
// error code in an otherwise valid result. It never trusts merged raw choices.
func invalidResultID(raw []byte, version uint32) (uint64, bool) {
	scan, err := scanWireStructure(raw)
	if err != nil || scan.validate(true) != nil || !scan.hasResult {
		return 0, false
	}
	var f Frame
	if (proto.UnmarshalOptions{RecursionLimit: 33}).Unmarshal(raw, &f) != nil || f.GetVersion() != version || f.GetRequestId() == 0 || f.GetResult() == nil {
		return 0, false
	}
	result := f.GetResult()
	if scan.outcome.count == 0 || (result.GetError() != nil && result.GetError().GetCode() == ErrorCodeUnspecified) {
		return f.GetRequestId(), true
	}
	return 0, false
}

// prepareCallFrame receives an already validated, locally constructed request.
// Copy payload bytes before sampling the remaining budget, then finish only
// the small timeout/envelope headers. Headroom avoids moving the payload when
// a shrinking timeout changes the envelope's length-prefix width.
func prepareCallFrame(f *Frame, deadline time.Time) ([]byte, error) {
	const headroom = 32
	req := f.GetRequest()
	buf := make([]byte, headroom, headroom+proto.Size(req)+6)
	buf = protowire.AppendBytes(protowire.AppendTag(buf, 1, protowire.BytesType), []byte(req.GetMethod()))
	if len(req.GetPayload()) > 0 {
		buf = protowire.AppendBytes(protowire.AppendTag(buf, 2, protowire.BytesType), req.GetPayload())
	}
	remaining := time.Until(deadline) / time.Millisecond
	if remaining <= 0 {
		return nil, NewRpcError(ErrorCodeDeadlineExceeded, "syntra: queued call expired")
	}
	buf = protowire.AppendVarint(protowire.AppendTag(buf, 3, protowire.VarintType), uint64(remaining))
	var header [headroom]byte
	prefix := protowire.AppendVarint(protowire.AppendTag(header[:0], 1, protowire.VarintType), uint64(f.GetVersion()))
	prefix = protowire.AppendVarint(protowire.AppendTag(prefix, 2, protowire.VarintType), f.GetRequestId())
	prefix = protowire.AppendVarint(protowire.AppendTag(prefix, 12, protowire.BytesType), uint64(len(buf)-headroom))
	start := headroom - len(prefix)
	copy(buf[start:headroom], prefix)
	buf = buf[start:]
	if err := ValidateFrameSize(len(buf)); err != nil {
		return nil, err
	}
	return buf, nil
}

// wireField describes declared types. Future choice values must be LEN but
// their contents are opaque. Root depth is zero; groups share the depth budget.
func wireField(schema wireSchema, num protowire.Number) (known bool, scalar bool, text bool, nested wireSchema) {
	switch schema {
	case wireFrame:
		if num == 1 || num == 2 {
			return true, true, false, 0
		}
		switch num {
		case 10:
			return true, false, false, wireHello
		case 11:
			return true, false, false, wireReady
		case 12:
			return true, false, false, wireRequest
		case 13:
			return true, false, false, wireResult
		case 14:
			return true, false, false, wireCancel
		case 15:
			return true, false, false, wireNotification
		}
		if num >= 18 && num <= 31 {
			return true, false, false, 0
		}
	case wireHello:
		if num == 1 || num == 2 {
			return true, true, false, 0
		}
		if num == 3 {
			return true, false, false, 0
		}
	case wireReady:
		if num == 1 {
			return true, false, true, 0
		}
	case wireRequest:
		if num == 1 {
			return true, false, true, 0
		}
		if num == 2 {
			return true, false, false, 0
		}
		if num == 3 {
			return true, true, false, 0
		}
	case wireResult:
		if num == 2 {
			return true, false, false, wireError
		}
		if num >= 1 && num <= 15 {
			return true, false, false, 0
		}
	case wireError:
		if num == 1 {
			return true, true, false, 0
		}
		if num == 2 {
			return true, false, true, 0
		}
	case wireNotification:
		if num == 1 {
			return true, false, false, 0
		}
	}
	return false, false, false, 0
}

func walkWire(raw []byte, schema wireSchema, depth int, end protowire.Number, scan *wireScan) ([]byte, error) {
	if depth > 32 {
		return nil, NewRpcError(ErrorCodeResourceExhausted, "syntra: exceeded max recursion depth")
	}
	var outcome rawChoice
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 || !num.IsValid() {
			return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed field tag")
		}
		raw = raw[n:]
		known, scalar, text, nested := wireField(schema, num)
		if known && ((scalar && typ != protowire.VarintType) || (!scalar && typ != protowire.BytesType)) {
			return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: wrong wire type for core field")
		}
		if typ == protowire.EndGroupType {
			if end == num {
				return raw, nil
			}
			return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: unexpected end group")
		}
		if schema == wireFrame {
			if num == 16 || num == 17 {
				scan.reserved = true
			}
			if num >= 10 && num <= 31 {
				scan.body.count++
				scan.body.future = scan.body.future || num >= 18
				scan.bodyTag = num
			}
		}
		if schema == wireResult && num <= 15 {
			outcome.count++
			outcome.future = outcome.future || num >= 3
		}
		switch typ {
		case protowire.BytesType:
			length, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed field length")
			}
			if length > MaxFrameBytes {
				return nil, NewRpcError(ErrorCodeResourceExhausted, "syntra: field exceeds allocation bound")
			}
			if length > uint64(len(raw)-m) {
				return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: truncated field")
			}
			value := raw[m : m+int(length)]
			raw = raw[m+int(length):]
			if nested != wireUnknown {
				if _, err := walkWire(value, nested, depth+1, 0, scan); err != nil {
					return nil, err
				}
			} else if text && !utf8.Valid(value) {
				return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: invalid UTF-8 in core string")
			}
			if scan.bound == nil {
				switch {
				case schema == wireHello && num == 3 && length > MaxCredentialBytes:
					scan.bound = NewRpcError(ErrorCodeResourceExhausted, "syntra: credential exceeds bound")
				case schema == wireReady && num == 1 && length > MaxConnectionIDBytes:
					scan.bound = NewRpcError(ErrorCodeInvalidArgument, "syntra: invalid connection_id length")
				case schema == wireError && num == 2 && length > MaxDiagnosticBytes:
					scan.bound = NewRpcError(ErrorCodeInvalidArgument, "syntra: error message exceeds diagnostic bound")
				}
			}
		case protowire.StartGroupType:
			var err error
			raw, err = walkWire(raw, wireUnknown, depth+1, num, scan)
			if err != nil {
				return nil, err
			}
		default:
			var m int
			switch typ {
			case protowire.VarintType:
				var value uint64
				value, m = protowire.ConsumeVarint(raw)
				if schema == wireFrame && num == 1 {
					scan.version = uint32(value)
				}
			case protowire.Fixed32Type:
				_, m = protowire.ConsumeFixed32(raw)
			case protowire.Fixed64Type:
				_, m = protowire.ConsumeFixed64(raw)
			default:
				return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: illegal wire type")
			}
			if m < 0 {
				return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: truncated field")
			}
			raw = raw[m:]
		}
	}
	if end != 0 {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: unterminated group")
	}
	if schema == wireResult {
		scan.hasResult = true
		scan.outcome = outcome
	}
	return raw, nil
}
