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
