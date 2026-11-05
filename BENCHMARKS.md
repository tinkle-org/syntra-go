# Benchmarks

The available benchmarks measure core/session and encrypted-record work in
memory. They report allocations and use `b.N` loops. CI uses Go 1.26.10 with CGO
disabled. Record the actual toolchain,
platform, CPU, source revision and working-tree state with any local sample.

## Measurement boundaries

- `BenchmarkWire` measures envelope scans, marshal, unmarshal, and round trips
  for control messages and representative payload sizes. Fixtures are prepared
  and checked before timing. Byte throughput uses serialized envelope size;
  round trips count both encode and decode. Scans skip opaque payload contents,
  so their throughput is logical envelope throughput.
- `BenchmarkSessionLoopback` measures echo RPCs through `OpenClient`, `OpenHost`
  and `LoopbackPair`, with serial and fixed-worker cases. Setup, readiness and
  teardown are excluded; calls, payload comparisons and completion collection
  are timed. Bytes count request and echoed application payloads. The loopback
  harness exercises internal session dispatch without encrypted record I/O.
- `BenchmarkSessionCoreHandshake` includes core construction, hello/ready
  processing, authentication completion, activation and close.
  `BenchmarkSessionHandshake` includes the loopback session lifecycle through
  shutdown. These measure internal session work, not full encrypted connection
  establishment.
- `BenchmarkSessionHeaderValidation` isolates phase-header checks. Complete
  decoding and semantic validation still occur during normal session dispatch.
- `securechannel.BenchmarkAppendContext` measures canonical context encoding
  into preallocated storage. `BenchmarkHandshakeAndConfirm` measures both Noise
  roles, one authenticated 64-byte record in each direction, and channel close;
  static provisioning is outside timing.
- `securechannel.BenchmarkRecordWarm` measures an encrypt/decrypt pair with
  advancing nonces. Cipher setup and warmup are excluded. Bytes count one
  plaintext length per pair, not total wire traffic.
- `transport/ordered.BenchmarkPrefixPreallocated` measures frame-prefix encoding
  without encryption or I/O.

### Session worker admission and metrics

`WorkersN` is the number of caller goroutines sharing one loopback connection,
not a guarantee of N simultaneous RPCs. Worker cases report `inflight-limit`,
the configured maximum outstanding benchmark calls per connection (not an
observed peak). The benchmark estimates each echo frame as payload plus 128
bytes for the envelope, capped at `MaxFrameBytes` (1 MiB). It admits at most
`min(workers, hostWriterMaxBytes / estimatedFrameBytes - 1)` calls. The writer's
8 MiB byte cap includes queued and active sends, independently of
`WriterCapacity`. Reserving one additional frame covers a caller receiving its
result and admitting another call before the writer releases the active send's
charge. This estimate applies to this echo-only fixture, not arbitrary host
traffic or notifications.

With the current fixtures, only `near1MiB/Workers16` is restricted: all 16
goroutines still perform their assigned calls, with at most 7 calls outstanding.
The empty, 64 B, 1 KiB and 64 KiB cases keep their original concurrency and do
not use the admission channel. Serial cases are unchanged. Admission waiting is
inside the timed worker loop; setup of the bound and channel is outside timing.
Every call must succeed and echo exactly; errors still fail the sample and all
workers are joined. No production resource limits are changed.

Existing metrics retain their meaning: `calls` is the successfully completed
count and must equal `b.N`; `rpc/s` is completed calls divided by total timed
elapsed seconds; `ns/op` is elapsed time per completed call, not individual RPC
latency; `MB/s` counts both request and echoed application payloads, not wire
bytes. Allocations cover the timed work. The bounded large-payload workload is
not directly comparable to the previous unrestricted Workers16 workload as a
production performance improvement. Record `inflight-limit` with comparisons.

There are no benchmark functions for managed `network`, `routes`, `proxy`, TCP,
WS/WSS, TLS stream establishment, or the HTTP/HTTPS candidate carrier. Their real
loopback integration tests verify behavior and lifecycle, not performance.
These benchmark cases do not measure socket/netpoll costs, TLS certificate
verification, proxy negotiation, reconnect supervision, idle push latency,
application persistence, credential-service latency, deployment throughput, or
durable recovery from real connection failures. Header scans and prefix
microbenchmarks do not establish allocation-free RPC processing.

## Run

Smoke-test wire and session fixtures, then run selected cases:

```sh
go test -mod=readonly -run '^TestBenchmark(WireFixtures|SessionReadinessAndEcho)$' -count=1 .
go test -mod=readonly -run '^$' -bench '^Benchmark(Wire|Session)' -benchmem -benchtime=1x -count=1 .
```

Run all SDK benchmark cases once to check execution:

```sh
CGO_ENABLED=0 go test -mod=readonly -run '^$' -bench . -benchmem -benchtime=1x -count=1 ./...
```

The benchmark workflow collects repeated samples across root-module packages:

```sh
CGO_ENABLED=0 go test -mod=readonly -run '^$' -bench . -benchmem -count=3 -benchtime=100ms -cpu=1,4 -timeout=10m ./...
```

Timing is report-only. Execution failures still fail the workflow. Short CI
samples check execution and provide observations; they are not a performance
baseline or evidence of a statistically significant improvement.
Selecting `./...` does not create benchmarks for packages that have none; use
only functions present in the tree when selecting individual cases.

Stress the large-payload worker admission at both CI CPU settings:

```sh
go test -mod=readonly -run '^TestBenchmarkSession(InflightLimit|FrameBudget|ReadinessAndEcho)$' -count=1 .
CGO_ENABLED=0 go test -mod=readonly -run '^$' -bench '^BenchmarkSessionLoopback/near1MiB/Workers16$' -benchmem -count=20 -benchtime=100ms -cpu=1,4 -timeout=10m .
```

## Compare changes

Use the same toolchain, machine, CPU settings, benchmark code and fixture sizes
for both revisions. Collect repeated samples on an otherwise idle host. Preserve
raw output and compare distributions and allocations, not a single fastest
sample. `GOMAXPROCS` controls Go execution parallelism, not CPU affinity.

```sh
go test -mod=readonly -run '^$' -bench . -benchmem -count=10 -cpu=1,4 ./...
```

No measured timing baseline is published here. Do not trade buffer ownership,
authentication checks, nonce safety, or persistence semantics for lower counts.
