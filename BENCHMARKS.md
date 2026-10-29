# Wire, session and SC1 benchmarks

Use **Go 1.26.10** for current benchmarks, CI and production builds, selecting
it with `export GOTOOLCHAIN=go1.26.10`. The root module's Go 1.23.0 floor and
Go 1.23.12 CI lane verify API/build compatibility, not production security;
production binaries require a security-patched toolchain. Historical samples
below retain their actual measured Go 1.26.4 toolchain.
Benchmarks use `b.N` loops and report allocations. Root benchmarks require no
Docker. Session cases exercise the linked production core (pure Go by default);
securechannel and transport cases exercise the Go SC1 implementation.

## Cases and accounting

- `BenchmarkWire/{ScanFrameTags,MarshalFrame,UnmarshalFrame,RoundTrip}` uses
  validated hello, ready, error and cancel fixtures, plus request, success and
  notification fixtures at empty, 64B, 1KiB, 64KiB and near1MiB payload sizes.
  Control fixtures have fixed representative contents. The largest payload is
  `MaxFrameBytes - 128` (1,048,448 bytes); serialized envelopes remain below the
  1MiB limit. Fixture creation and logical round-trip validation happen before
  timing. Canonical inputs are reused without benchmark-side mutations.
  `SetBytes` is the actual serialized size, doubled for marshal + unmarshal.
  Scans skip opaque byte contents: their MB/s is logical envelope throughput,
  not memory bandwidth.
- `BenchmarkSessionLoopback/{empty,64B,1KiB,64KiB,near1MiB}/{Serial,Workers1,Workers4,Workers16}`
  runs echo RPCs through `OpenClient`, `OpenHost` and `LoopbackPair`, with
  explicit `AllowAllAuthorize`. The independent `testing.TB` pair helper waits
  for `client.activated`, with no warmup RPC or sleep. Configuration, session
  handshake, fixture allocation and worker creation are excluded. Worker start
  release, all calls, payload comparisons and completion collection are timed;
  session teardown is excluded. There are exactly 1, 4 or 16 workers, each with
  at most one outstanding call. Static iteration partitions total exactly
  `b.N` calls; errors fail the sample without retry. The `calls` metric counts
  successful, payload-verified completions; `rpc/s` divides them by timed elapsed
  seconds. `SetBytes` counts request + echo
  application bytes (`2 * payload length`), excluding envelopes. Empty calls
  intentionally have no MB/s metric.
- `BenchmarkSessionCoreHandshake` times core construction, hello encoding and
  acceptance, authentication completion, ready encoding and activation, and
  both core closes. Configuration resolution is excluded. It has no transport
  or application warmup.
- `BenchmarkSessionHandshake` times the complete loopback lifecycle, from
  session/transport construction through activation and cancellation/join/close.
  Configuration construction is excluded. It sends no application RPC. Neither
  handshake benchmark reports MB/s because its unit is a completed lifecycle.
- `BenchmarkSessionHeaderValidation` measures allocation-free phase-header
  checking without creating another Protobuf object. The core still performs
  complete decoding and semantic validation before admitting effects.

Session shutdown cancels the shared context and joins both pumps with a shared
five-second bound before releasing the host and transports. RPCs have five-second
budgets. Worker results are collected before teardown. No pooling is introduced.

### SC1 and transport cases

- `securechannel.BenchmarkAppendContext/{bootstrap,returning}` appends the exact
  canonical context into preallocated storage; `SetBytes` counts context bytes.
  Fixture setup and the final canonical-byte comparison are outside timing.
- `securechannel.BenchmarkHandshakeAndConfirm/{NK,NKpsk0}` times both handshake
  roles with real `crypto/rand` ephemerals, one verified 64-byte record in each
  direction and channel close. Static provisioning fixtures are outside timing.
  `SetBytes` counts the context, both 48-byte handshake messages and both
  80-byte ciphertext records; carrier headers are excluded.
- `securechannel.BenchmarkRecordWarm` measures one encrypt/decrypt pair for
  bootstrap and returning modes, both directions, at 64, 1,024 and 65,519
  plaintext bytes. Cipher setup and one warmup pair are excluded. Buffers are
  reused, nonces advance without reset, and final payload/nonce checks happen
  outside timing. `SetBytes` counts one plaintext length per complete pair.
- `transport/ordered.BenchmarkPrefixPreallocated` and
  `transport/tcp.BenchmarkTCPPrefixPreallocated` measure preallocated u32 frame
  and u16 carrier-prefix writes respectively, without socket or crypto work.
- `transport/tcp.BenchmarkNetPipeReassembly` sends/reassembles 128 KiB frames
  through the production encrypted TCP adapter over `net.Pipe`. Handshake and
  fixture allocation are outside timing; send/receive and worker synchronization
  are timed. `SetBytes` counts one 128 KiB frame per iteration, excluding headers
  and tags. This is in-process carrier work, not a network deployment benchmark.
- `transport/websocket.BenchmarkWebSocketAdapterPipeEcho/{64B,1KiB,64KiB}`
  measures serial encrypted adapter `Send`/`Recv` echoes over `net.Pipe`, with a
  real in-memory HTTP/WebSocket upgrade and no OS sockets or Docker. Provisioning,
  upgrade, SC1 handshakes and cleanup are outside timing. One operation is a
  verified round trip with two owned frames: ns/op counts the round trip,
  `SetBytes` counts twice the application-frame length and `frames/s` counts
  both directions. The full adapter path includes active assembly timers,
  encryption, framing, masking and I/O; it is not a high-level RPC or WSS/TLS
  deployment benchmark.
- `transport/websocket.BenchmarkWebSocketHeaderEncode/{ServerUnmasked,ClientMasked}`
  measures the dependency's actual binary-message encoder over an in-memory
  upgraded connection without SC1. Empty messages produce two-byte unmasked
  server headers or six-byte masked client headers. `SetBytes` counts those
  wire bytes; `frames/s` counts messages. Upgrade and teardown are excluded.
- `transport/websocket.BenchmarkWebSocketObserver/{Header2,Header6,Header8,Header14}`
  replays actual library-encoded frames through the adapter's wire observer.
  Header widths cover unmasked/masked and extended-length cases, with an
  unarmed budget to isolate parsing and underlying read calls. `SetBytes`
  counts the full encoded frame; `reads/frame` and `frames/s` report observer
  work. Fixture encoding and cleanup are outside timing. These microbenchmarks
  are in `transport/websocket/websocket_benchmark_test.go`.

## Targeted checks

These selectors execute only tests/benchmarks added in the two benchmark files:

```sh
go test . -run '^TestBenchmark(WireFixtures|SessionReadinessAndEcho)$' -count=1
go test . -run '^$' -bench '^Benchmark(Wire|Session)' -benchtime=1x -count=1
```

To smoke-test every benchmark in the root module:

```sh
go test -mod=readonly -run '^$' -bench . -benchmem -benchtime=1x -count=1 ./...
```

## Benchmark workflow

`.github/workflows/benchmarks.yml` uses Go 1.26.10 with CGO disabled and runs
**all root-module packages**, including securechannel and transport:

```sh
go test -mod=readonly -run '^$' -bench . -benchmem -count=3 -benchtime=100ms -cpu=1,4 -timeout=10m ./...
```

The artifact records raw samples, source revision and toolchain. Timing is
report-only: no fixed ns/op threshold or automatic baseline-comparison gate;
execution errors still fail the job. `./...` does not cross into the separate
module under [tests/integration/](tests/integration/README.md). That tooling
requires Docker and has its own execution/verification instructions.

## Initial baseline

The initial capture started from commit
`188007a882f79183b2d37808803530f1eb6bc723` on `feat/sc1-connectivity`, with no
tracked working-tree changes, before core refactoring. It includes all 76 wire
cases, the four 1KiB loopback modes and both handshake cases, each repeated three
times with a 100ms target. It was captured with Go 1.26.4, darwin/arm64, Apple M4,
default GOMAXPROCS 10. These are the original measured toolchain and settings;
the current Go 1.23 floor does not relabel those measurements. This short local
baseline is for subsequent comparison, not a performance claim.

The parent directory was verified with `ls` before creating the output:

```sh
ls "/var/folders/xv/g_j4t2793xdbd_wnr290xgyw0000gn/T/opencode"
set -o pipefail && (git rev-parse HEAD && git status --short && go version && go test . -run '^$' -bench '^BenchmarkWire$|^BenchmarkSessionLoopback$/^1KiB$|^BenchmarkSession(CoreHandshake|Handshake)$' -benchmem -benchtime=100ms -count=3) | tee "/var/folders/xv/g_j4t2793xdbd_wnr290xgyw0000gn/T/opencode/syntra-baseline.txt"
```

Capture passed in 32.943s. Representative observed ranges:

| Case | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| Wire scan request/1KiB | 12.14–13.48 | 0 | 0 |
| Wire marshal request/1KiB | 247.7–248.7 | 1,184 | 2 |
| Wire unmarshal request/1KiB | 257.8–259.0 | 1,232 | 5 |
| Wire round trip request/1KiB | 517.5–523.2 | 2,416 | 7 |
| Loopback 1KiB Serial | 6,254–6,299 | 10,936 | 48 |
| Loopback 1KiB Workers4 | 4,271–4,295 | 10,938–10,939 | 48 |
| Loopback 1KiB Workers16 | 3,592–3,680 | 10,938 | 48 |
| Core handshake | 1,145–1,150 | 1,400 | 25 |

Compare like-for-like toolchains, CPU settings, selectors and timing boundaries.
Concurrent development and machine load can affect timing. The saved capture
records the starting revision and working-tree status; it does not freeze later
production edits by other contributors.

## Comparing changes

Use the same benchmark harness, Go version, build tags, CPU settings and fixture
sizes for both revisions. Keep setup and measurement boundaries identical. On
an otherwise idle, externally powered host, collect at least ten samples per
revision, preferably interleaving before/after runs. The three short CI samples
are smoke/reporting evidence, not a statistically significant performance claim.

```sh
go test -mod=readonly -run '^$' -bench . -benchmem -count=10 -cpu=1,4 ./...
# Save equivalent before/after outputs, then compare with the pinned tool:
go run golang.org/x/perf/cmd/benchstat@v0.0.0-20261009192801-be2c69fb417e before.txt after.txt
```

Inspect both allocation counts and retained memory before introducing pools.
Full Protobuf decoding owns messages and byte fields; zero-allocation header
scanning does not mean full decoding or RPC dispatch is allocation-free. Warm
Noise encrypt/decrypt pairs currently retain two allocations (32 bytes) in the
dependency path. Do not trade buffer ownership, authentication, or nonce safety
for a lower allocation count.

Socket macrobenchmarks belong on dedicated hardware, outside shared-runner
timing gates. Record OS, CPU, toolchain, core backend, payload distribution,
parallelism and repeated-run distributions. `GOMAXPROCS` controls Go execution
parallelism, not CPU affinity; pin CPUs using appropriate OS controls where
available. These in-memory benchmarks are not end-to-end network measurements.
