package syntra

import (
	"bytes"
	"runtime"
	"testing"

	"google.golang.org/protobuf/proto"
)

const benchmarkEchoMethod = "/example.Echo/Echo"

var benchmarkPayloadSizes = []struct {
	name string
	size int
}{
	{"empty", 0},
	{"64B", 64},
	{"1KiB", 1 << 10},
	{"64KiB", 64 << 10},
	// Leave room for method, timeout, request ID, tags and length prefixes.
	{"near1MiB", MaxFrameBytes - 128},
}

type benchmarkWireFixture struct {
	name  string
	frame *Frame
	raw   []byte
}

func benchmarkWireFixtures(tb testing.TB) []benchmarkWireFixture {
	tb.Helper()
	fixtures := []benchmarkWireFixture{
		{name: "hello", frame: NewHelloFrame(&ClientHello{
			MinVersion: 1, MaxVersion: 1, Credential: []byte("benchmark-credential"),
		}, 1)},
		{name: "ready", frame: NewReadyFrame(1, &ServerReady{ConnectionId: "0123456789abcdef0123456789abcdef"})},
		{name: "error", frame: NewResultFrame(1, 7, NewWireErrorResult(ErrorCodeUnimplemented, "unknown method"))},
		{name: "cancel", frame: NewCancelFrame(1, 7)},
	}
	for _, size := range benchmarkPayloadSizes {
		payload := bytes.Repeat([]byte{0x61}, size.size)
		fixtures = append(fixtures,
			benchmarkWireFixture{name: "request/" + size.name, frame: NewRequestFrame(1, 7, &RpcRequest{
				Method: benchmarkEchoMethod, Payload: payload, TimeoutMs: 5000,
			})},
			benchmarkWireFixture{name: "success/" + size.name, frame: NewResultFrame(1, 7, NewSuccessResult(payload))},
			benchmarkWireFixture{name: "notification/" + size.name, frame: NewNotificationFrame(1, &Notification{Payload: payload})},
		)
	}
	for i := range fixtures {
		fixture := &fixtures[i]
		raw, err := MarshalFrame(fixture.frame)
		if err != nil {
			tb.Fatalf("%s marshal: %v", fixture.name, err)
		}
		if err := scanFrameTags(raw); err != nil {
			tb.Fatalf("%s scan: %v", fixture.name, err)
		}
		decoded, err := UnmarshalFrame(raw)
		if err != nil {
			tb.Fatalf("%s unmarshal: %v", fixture.name, err)
		}
		if !proto.Equal(fixture.frame, decoded) {
			tb.Fatalf("%s round trip differs", fixture.name)
		}
		fixture.raw = raw
	}
	return fixtures
}

func TestBenchmarkWireFixtures(t *testing.T) {
	fixtures := benchmarkWireFixtures(t)
	if len(fixtures) != 19 {
		t.Fatalf("fixture count = %d, want 19", len(fixtures))
	}
	for _, fixture := range fixtures {
		if len(fixture.raw) > MaxFrameBytes {
			t.Fatalf("%s exceeds envelope bound", fixture.name)
		}
	}
}

// Each operation reuses the same validated, canonical input. Fixture creation
// and correctness checks are excluded; RoundTrip counts encoded bytes twice.
func BenchmarkWire(b *testing.B) {
	fixtures := benchmarkWireFixtures(b)
	for _, operation := range []string{"ScanFrameTags", "MarshalFrame", "UnmarshalFrame", "RoundTrip"} {
		b.Run(operation, func(b *testing.B) {
			for _, fixture := range fixtures {
				b.Run(fixture.name, func(b *testing.B) {
					b.ReportAllocs()
					processed := int64(len(fixture.raw))
					if operation == "RoundTrip" {
						processed *= 2
					}
					b.SetBytes(processed)
					var raw []byte
					var decoded *Frame
					var err error
					b.ResetTimer()
					switch operation {
					case "ScanFrameTags":
						for i := 0; i < b.N; i++ {
							if err = scanFrameTags(fixture.raw); err != nil {
								b.Fatal(err)
							}
						}
					case "MarshalFrame":
						for i := 0; i < b.N; i++ {
							raw, err = MarshalFrame(fixture.frame)
							if err != nil {
								b.Fatal(err)
							}
						}
					case "UnmarshalFrame":
						for i := 0; i < b.N; i++ {
							decoded, err = UnmarshalFrame(fixture.raw)
							if err != nil {
								b.Fatal(err)
							}
						}
					case "RoundTrip":
						for i := 0; i < b.N; i++ {
							raw, err = MarshalFrame(fixture.frame)
							if err != nil {
								b.Fatal(err)
							}
							decoded, err = UnmarshalFrame(raw)
							if err != nil {
								b.Fatal(err)
							}
						}
					}
					b.StopTimer()
					runtime.KeepAlive(raw)
					runtime.KeepAlive(decoded)
					runtime.KeepAlive(err)
				})
			}
		})
	}
}
