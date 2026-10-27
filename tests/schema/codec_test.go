package schema_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
	"google.golang.org/protobuf/proto"
)

func fixtures(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile("fixtures/frames.json")
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]string
	if err := json.Unmarshal(data, &values); err != nil {
		t.Fatal(err)
	}
	return values
}

func decode(t *testing.T, raw string) *pb.Frame {
	t.Helper()
	data, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	frame := new(pb.Frame)
	if err := proto.Unmarshal(data, frame); err != nil {
		t.Fatal(err)
	}
	return frame
}

// Shared independent fixtures cover every defined body and both result outcomes.
func TestFixtures(t *testing.T) {
	for name, raw := range fixtures(t) {
		t.Run(name, func(t *testing.T) {
			frame := decode(t, raw)
			if frame.Version != 1 || frame.Body == nil {
				t.Fatal("missing envelope metadata/body")
			}
			encoded, err := proto.Marshal(frame)
			if err != nil {
				t.Fatal(err)
			}
			var round pb.Frame
			if err := proto.Unmarshal(encoded, &round); err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(frame, &round) {
				t.Fatal("logical round trip differs")
			}
		})
	}
	values := fixtures(t)
	frame := decode(t, values["request"])
	if frame.RequestId != 7 || frame.GetRequest().Method != "/example.Echo/Echo" ||
		hex.EncodeToString(frame.GetRequest().Payload) != "00ff80" || frame.GetRequest().TimeoutMs != 1 {
		t.Fatal("request fixture fields differ")
	}
	if hex.EncodeToString(decode(t, values["notification"]).GetNotification().Payload) != "00ff80" {
		t.Fatal("opaque event bytes differ")
	}
	if decode(t, values["ready"]).GetReady().ConnectionId != "c" ||
		decode(t, values["hello"]).GetHello().MinVersion != 1 ||
		decode(t, values["error"]).GetResult().GetError().Code != pb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT {
		t.Fatal("fixture semantics differ")
	}
}

func TestPresenceAndDefaults(t *testing.T) {
	selected := decode(t, fixtures(t)["empty_success"]).GetResult()
	if _, ok := selected.Outcome.(*pb.RpcResult_Payload); !ok || len(selected.GetPayload()) != 0 {
		t.Fatal("selected empty success lost presence")
	}
	unset := decode(t, "080110076a00").GetResult()
	if unset.Outcome != nil {
		t.Fatal("unset outcome became success")
	}
	if decode(t, "0801").Body != nil {
		t.Fatal("missing body became selected")
	}
	if decode(t, fixtures(t)["cancel"]).GetCancel() == nil {
		t.Fatal("empty cancel lost presence")
	}
	if (&pb.RpcRequest{}).TimeoutMs != 0 {
		t.Fatal("timeout default changed")
	}
	// Codecs can represent invalid protocol states: semantic rejection is runtime work.
	invalid := decode(t, "080110076a0412020800").GetResult().GetError()
	if invalid == nil || invalid.Code != 0 {
		t.Fatal("zero-error fixture differs")
	}
}

func TestUnknownValuesAndOrder(t *testing.T) {
	a := decode(t, "080110077200")
	b := decode(t, "720010070801")
	if !proto.Equal(a, b) {
		t.Fatal("field-order dependence")
	}
	unknown := decode(t, "080110077200a00601") // Unknown metadata tag 100.
	if unknown.GetCancel() == nil || len(unknown.ProtoReflect().GetUnknown()) == 0 {
		t.Fatal("known body or unknown metadata lost")
	}
	errorFrame := decode(t, "080110076a05120308e707") // Unknown enum 999.
	if int32(errorFrame.GetResult().GetError().Code) != 999 {
		t.Fatal("unknown enum coerced")
	}
	// No reporting policy is implemented here; runtime maps this number to UNKNOWN.
	for number := int32(0); number <= 16; number++ {
		value := &pb.RpcError{Code: pb.ErrorCode(number)}
		data, err := proto.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var round pb.RpcError
		if err := proto.Unmarshal(data, &round); err != nil || int32(round.Code) != number {
			t.Fatalf("enum %d failed", number)
		}
	}
	max := &pb.Frame{Version: 1, RequestId: ^uint64(0), Body: &pb.Frame_Cancel{Cancel: &pb.Cancel{}}}
	data, err := proto.Marshal(max)
	if err != nil {
		t.Fatal(err)
	}
	var round pb.Frame
	if err := proto.Unmarshal(data, &round); err != nil || !proto.Equal(max, &round) {
		t.Fatal("uint64 truncated")
	}
}

func TestCodecBoundaryNegatives(t *testing.T) {
	// A decoder accepts multiple oneof fields, keeps the last; it is not a raw-wire validator.
	if decode(t, "080172007a00").GetNotification() == nil {
		t.Fatal("oneof decoder behavior changed")
	}
	if decode(t, "0801820100").Body != nil {
		t.Fatal("reserved tag became body")
	}
	if decode(t, "0801a20100").Body != nil {
		t.Fatal("future-only tag became known body")
	}
	for _, raw := range []string{"80", "08015202ff", "0f", "08015a030a01ff"} {
		data, err := hex.DecodeString(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := proto.Unmarshal(data, new(pb.Frame)); err == nil {
			t.Fatalf("malformed bytes accepted: %s", raw)
		}
	}
}
