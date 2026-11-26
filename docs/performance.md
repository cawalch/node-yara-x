# Performance

Measurements for `@litko/yara-x`: compile cost, scan cost by payload size and rule shape,
fast-path matching, and asynchronous throughput. The README's
[Performance](../README.md#performance) section links here; the numbers below are the full set.

They come from the committed baseline, [`__test__/baseline-performance.json`](../__test__/baseline-performance.json):

- **Machine**: Apple Silicon (darwin/arm64), 14 cores, 36 GB RAM
- **Node**: v26.10.0, release build with LTO
- **Recorded**: 2026-10-04
- **Reproduce**: `pnpm profile:baseline`, then `pnpm profile:compare __test__/baseline-performance.json`
  to check a change for regressions

The payloads are synthetic and highly repetitive — for example, 100 KB filled with a single byte plus
three planted patterns — so the throughput column is an upper bound for a warm-cache microbenchmark,
not a prediction for real files.

## Compiling rules

50 iterations per rule shape.

| Rule shape | mean | p50 | p95 | p99 |
| :--- | ---: | ---: | ---: | ---: |
| 2 strings, `any of them` | 1.86 ms | 1.81 ms | 2.18 ms | 2.43 ms |
| 10 strings, `2 of ($a*) and 1 of ($b*)` | 1.87 ms | 1.85 ms | 2.05 ms | 2.13 ms |
| 4 regular expressions | 10.21 ms | 10.19 ms | 10.45 ms | 11.11 ms |
| 5 separate rules | 2.16 ms | 2.14 ms | 2.28 ms | 2.62 ms |
| Hex patterns, regex and anchored strings | 2.27 ms | 2.25 ms | 2.41 ms | 2.85 ms |

Adding sources to an existing scanner costs one rebuild per batch, not one per call: 120 one-rule
sources take ≈100 ms against 5.67 s when each addition recompiles the whole set, and a single
`compile()` of the same 120 rules takes ≈10 ms. See
[Build a scanner incrementally](../README.md#build-a-scanner-incrementally).

## Scanning by payload size

Two-string rule, `any of them`, 100 iterations (10 for the 5 MB payload).

| Payload | mean | p50 | p95 | p99 | Throughput |
| :--- | ---: | ---: | ---: | ---: | ---: |
| 58 B | 3.7 µs | 3.5 µs | 5.3 µs | 11.4 µs | — |
| 100 KB | 14.8 µs | 14.0 µs | 17.8 µs | 19.8 µs | ~6.9 GB/s |
| 5 MB | 520 µs | 519 µs | 599 µs | 599 µs | ~10 GB/s |
| 50 KB with ~512 matches | 221 µs | 216 µs | 289 µs | 342 µs | ~0.23 GB/s |

Matches cost the time. The 50 KB payload holds roughly 512 occurrences of the pattern, and scanning it
takes longer than the 5 MB payload with three occurrences.

## Fast boolean matching vs. full scanning

`isMatch()` skips building `RuleMatch` objects, string buffers, and metadata records, so it also skips
the V8 allocation and collection they cause:

| Payload | `scan()` (full objects) | `isMatch()` (boolean) | Speedup |
| :--- | ---: | ---: | ---: |
| 58 B (clean) | 3.5 µs | 3.5 µs | 1.0× |
| 100 KB (matching) | 14.0 µs | 9.0 µs | 1.5× |
| 50 KB (~512 matches) | 221 µs | 118 µs | 1.9× |
| 100 KB (~1,000 matches) | 1.28 ms | 0.67 ms | 1.9× |

For match-dense scans at a larger scale, the [binary match ABI](./binary-match-abi.md) avoids the
per-match objects altogether.

## Asynchronous scanning throughput

`scanAsync()` and `isMatchAsync()` reuse thread-local scanner instances across libuv worker threads to
keep per-task dispatch overhead low. Buffer inputs are copied once at dispatch (see
[Scan asynchronously](../README.md#scan-asynchronously)); the numbers below include that copy.

2,000 requests against a compiled pattern:

| Workload | Latency (mean) | Throughput |
| :--- | ---: | ---: |
| Sequential `scanAsync` (2,000 requests) | 27 µs/op | ~37,000 ops/s |
| Concurrent `scanAsync` (2,000 parallel requests) | 5.6 µs/op | ~178,000 ops/s |

## Scanning by rule shape

100 KB payload, 50 iterations per rule shape.

| Rule shape | mean | p50 | p95 | p99 |
| :--- | ---: | ---: | ---: | ---: |
| 2 strings | 13.8 µs | 12.5 µs | 19.2 µs | 44.5 µs |
| 10 strings | 12.5 µs | 11.9 µs | 14.9 µs | 28.1 µs |
| 4 regular expressions | 65.6 µs | 63.6 µs | 78.1 µs | 79.9 µs |
| 5 separate rules | 15.9 µs | 14.4 µs | 19.6 µs | 22.0 µs |
| Hex patterns, regex and anchored strings | 8.9 µs | 8.4 µs | 10.6 µs | 17.5 µs |

The baseline also records memory, CPU, and GC statistics for each run; see the JSON for the full set.

## Other measurements

- **`deserialize()` vs `compile()`**: ~17% on a 120-rule set (75.5 ms compile vs 62.8 ms deserialize).
  Parsing and pattern-automaton construction are skipped, but the WASM condition module is still
  compiled for the local platform, so the speedup is partial.
- **Blob load cost**: ~1.7 ms per process for the two-rule set in
  [`__test__/performance-regression.mjs`](../__test__/performance-regression.mjs).
- **`isMatch()` under Bun and Deno**: a 5 MB scan takes ~0.5 ms under Node and ~3.1 ms under Bun and
  Deno, so the cost is in the Node-API call boundary, not the scan — prefer fewer large buffers over
  many tiny ones there.
