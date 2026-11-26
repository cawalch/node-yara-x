# @litko/yara-x

[![npm version](https://img.shields.io/npm/v/@litko%2Fyara-x)](https://www.npmjs.com/package/@litko/yara-x)
[![Node.js](https://img.shields.io/node/v/@litko%2Fyara-x)](https://www.npmjs.com/package/@litko/yara-x)
[![CI](https://github.com/cawalch/node-yara-x/actions/workflows/CI.yml/badge.svg)](https://github.com/cawalch/node-yara-x/actions/workflows/CI.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cawalch/node-yara-x/badge)](https://scorecard.dev/viewer/?uri=github.com/cawalch/node-yara-x)

Node.js bindings for [YARA-X](https://github.com/VirusTotal/yara-x), the Rust rewrite of YARA, built with [napi-rs](https://napi-rs.com). Scan buffers and files from JavaScript with no YARA installation and no runtime dependency.

- `compile()` and `fromFile()` return a scanner that reuses its compiled state: parse once, scan many times.
- `scan()` returns full match details; `isMatch()` returns a boolean and skips match-object construction.
- `scanBinary()` returns match records in a flat buffer, for match-dense scans.
- `scanFiles()` and `scanDirectory()` scan many files in parallel across a Rayon worker pool.
- `scanAsync()` runs on libuv worker threads with thread-local scanner caching.
- `serialize()` and `deserialize()` move compiled rules between processes and worker threads.
- `getRules()`, `ruleCount`, and `getImports()` describe a compiled rule set without scanning.
- Six prebuilt targets (macOS, Linux, Windows — see [Platform support](#platform-support)). Nothing is compiled at install time and there is no `postinstall` script.

## Install

```sh
npm install @litko/yara-x    # or: pnpm add @litko/yara-x | yarn add @litko/yara-x
```

Requires Node.js 20 or newer. CI runs the full suite on Node 20, 22, 24 and 26 on Linux, macOS and Windows; the floor is tested even though Node 20 is end-of-life upstream, because supporting it is a promise rather than an accident. The installer picks the matching prebuilt binary from an optional platform package; if no binary exists for your platform, see [Troubleshooting](#troubleshooting). Type definitions ship with the package, and both module systems are supported.

ES modules:

```javascript
import { compile } from "@litko/yara-x";
```

CommonJS:

```javascript
const { compile } = require("@litko/yara-x");
```

## Quick start

Compile a rule from source, then scan a buffer:

```javascript
import { compile } from "@litko/yara-x";

const rules = compile(`
  rule HelloWorld {
    strings:
      $greeting = "hello world"
    condition:
      $greeting
  }
`);

const matches = rules.scan(Buffer.from("This is a test with hello world in it"));

for (const match of matches) {
  console.log(`${match.ruleIdentifier} matched at ${match.matches[0].offset}`);
}
```

Rule syntax is documented upstream: [Anatomy of a rule](https://virustotal.github.io/yara-x/docs/writing_rules/anatomy-of-a-rule/) and [differences with YARA](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/). The examples below use a one-line rule where its shape is not the point.

## Scan a file

`fromFile()` compiles rules from a file. `scanFile()` reads the target from disk instead of copying it into the Node.js heap first:

```javascript
import { fromFile } from "@litko/yara-x";

const rules = fromFile("./rules/malware_rules.yar");
const matches = rules.scanFile("./samples/suspicious_file.exe");
console.log(`Found ${matches.length} matching rule(s).`);
```

## Scan asynchronously

`scanAsync()` and `scanFileAsync()` run the scan on a worker thread and return a promise:

```javascript
import { compile } from "@litko/yara-x";

const rules = compile(`rule Payload { strings: $p = "sensitive payload" condition: $p }`);
const matches = await rules.scanFileAsync("./samples/large_file.bin");
console.log(`Found ${matches.length} matching rule(s).`);
```

The async methods that take a buffer (`scanAsync()`, `isMatchAsync()`, `scanBinaryAsync()`) copy their input at dispatch, so changing the `Buffer` afterwards does not change the result. The synchronous variants read the buffer directly and stay zero-copy.

## Cancel work you no longer want

Every async scan method takes an `AbortSignal` as its last argument, so a client disconnect or a shutdown can stop work that has not started:

```javascript
import { compile } from "@litko/yara-x";

const rules = compile(`rule Payload { strings: $p = "sensitive payload" condition: $p }`);
const controller = new AbortController();
const sweep = rules.scanDirectory("./incoming", { concurrency: 4 }, null, controller.signal);
setTimeout(() => controller.abort(), 500);

const result = await sweep;
if (result.cancelled) console.log(`Stopped after ${result.scannedFiles} files; ${result.cancelledFiles} never started.`);
```

- Fired **before the call or while it is queued** — the promise rejects (it never throws from the call) with `name: "AbortError"` and `code: "Cancelled"`, and nothing is scanned.
- Fired **part-way through a batch** — the promise resolves with the partial sweep, `cancelled: true`, and `cancelledFiles` counting the files that never started; directory traversal stops too.
- Fired **while a single scan is already running** — nothing: a scan in flight cannot be interrupted, so `setTimeout()` and `setMaxScanSize()` are the bounds for that, and the synchronous methods take no `signal` at all because they block the thread that would deliver it.

While a scan is in flight the binding hangs one `abort` listener on your signal and takes it off the moment the promise settles, so `signal.onabort` and your own listeners stay untouched.

## Fast boolean matching

When you only need to know whether a rule matched — filtering clean files in a high-throughput pipeline, for example — `isMatch()` and `isFileMatch()` skip allocating `RuleMatch`, `MatchData`, string buffers, and metadata objects:

```javascript
import { compile } from "@litko/yara-x";

const rules = compile(`rule Payload { strings: $p = "sensitive payload" condition: $p }`);

if (rules.isMatch(buffer)) console.log("Found match!"); // synchronous fast path
const hasMatch = await rules.isFileMatchAsync("./samples/suspicious_file.exe"); // worker thread
```

The speedup grows with the number of matches — up to 1.9× on a 1,000-match payload, and nothing for a clean file (see [Fast boolean matching vs. full scanning](./docs/performance.md#fast-boolean-matching-vs-full-scanning)).

## Variables

Define global variables at compile time, and override them per scan:

```javascript
import { compile } from "@litko/yara-x";

const rules = compile(
  `rule VariableRule { condition: string_var contains "secret" and int_var > 10 and bool_var }`,
  { defineVariables: { string_var: "this is a secret message", int_var: 20, bool_var: true } },
);

// Uses the compile-time defaults.
console.log(rules.scan(Buffer.from("test payload")).length);

// Overrides them for this scan only.
console.log(rules.scan(Buffer.from("test payload"), { string_var: "no secrets here", int_var: 5, bool_var: false }).length);
```

Values keep their JavaScript type: `"42"` is a string global and `42` is an integer. Use `bigint` for exact values outside the safe-integer range; it must fit in a signed 64-bit integer. An incremental scanner takes the same types through `defineVariable()`:

```javascript
const scanner = create();
scanner.defineVariable("threshold", 42);
scanner.defineVariable("family", "42"); // string, not an integer
scanner.defineVariable("huge", 9007199254740993n);
```

## Namespaces

Namespaces keep rule identifiers unique across rule sets:

```javascript
import { compile, create } from "@litko/yara-x";

const rules = compile(`rule NamespacedRule { strings: $p = "namespace indicator" condition: $p }`, {
  namespace: "alpha",
});
const [match] = rules.scan(Buffer.from("namespace indicator"));
console.log(match.namespace); // "alpha"

const scanner = create();
scanner.addRuleSource('rule SharedName { strings: $a = "one" condition: $a }', "first_ns");
scanner.addRuleSource('rule SharedName { strings: $a = "two" condition: $a }', "second_ns");
```

## Build a scanner incrementally

`create()` returns an empty scanner that accepts rule sources one at a time:

```javascript
import { create } from "@litko/yara-x";

const scanner = create();
scanner.addRuleSource(`rule FirstRule { strings: $p = "first pattern" condition: $p }`);
scanner.addRuleFile("./rules/more_rules.yar", "custom_namespace");
scanner.addRuleSources([
  { source: "rule BatchRule1 { condition: true }", namespace: "batch" },
  { source: "rule BatchRule2 { condition: true }" },
]);

const matches = scanner.scan(Buffer.from("test data with first pattern"));
console.log(`Found ${matches.length} matching rule(s).`);
```

An addition does not recompile the accumulated rule set. The new source is checked on its own, and the set is rebuilt once, on the next read or scan. Adding 120 one-rule sources therefore costs one rebuild — measured ≈100 ms (100–110 ms across runs) against 5.67 s when every addition recompiled the whole set, release build on macOS/arm64. `addRuleSources()` does the same work in one call, so prefer it when you already have the sources.

Which call reports an error depends on whether the source can be judged alone:

| Reported | Against | Codes measured on this binding |
| :--- | :--- | :--- |
| The adding call | the new source by itself | `E001` syntax, `E010` unknown module, `E100` banned module, `E043` missing include, `E014` invalid regex, `E025` unknown pattern, `E012` duplicate inside the source, `E018` slow pattern under `errorOnSlowPattern`, `E013` against a global. In tolerant mode, any source-level error also reports here. |
| The next read or scan | the whole rule set | `E009` unknown identifier, `E012` across sources, `E013` across sources — for example a rule named `pe` added after a source that does `import "pe"`. |

A deferred error carries the same message and `ruleCode`. To get every error at add time, read the set inside the same `try`:

```javascript
try {
  for (const file of files) scanner.addRuleFile(file);
  scanner.getRules(); // deferred errors land here
} catch (error) {
  console.error(error.ruleCode, error.source, error.line);
}
```

The async methods run the rebuild before dispatching, so they throw a deferred error from the call rather than rejecting the promise. Without `ignoreInvalidRules` nothing can skip the offending source, so a strict scanner reports it on every read until you fix the rules — build a new scanner instead of reusing that one. With that option the rule is skipped and listed by `getIgnoredRules()`; see [Tolerating invalid rules](#tolerating-invalid-rules).

## Batch and directory scanning

`scanFiles()` and `scanDirectory()` scan many files in parallel across a native Rayon work-stealing thread pool, outside the libuv pool:

```javascript
import { compile } from "@litko/yara-x";

const scanner = compile(`rule Payload { strings: $p = "MALICIOUS_PAYLOAD" condition: $p }`);

// An array of paths
const batch = await scanner.scanFiles(["/data/file1.bin", "/data/file2.bin"]);
console.log(`Scanned ${batch.scannedFiles} files in ${batch.durationMs.toFixed(1)}ms (${batch.matchedFiles} matched).`);

// A directory, recursively, with glob filters, a depth limit, and size guards
const dirResult = await scanner.scanDirectory("/var/log", {
  maxDepth: 3,
  includePatterns: ["*.log", "*.txt"],
  excludePatterns: ["**/node_modules/**", "**/.git/**"],
  minFileSize: 1024, // ignore files smaller than 1 KB
  maxFileSize: 50 * 1024 * 1024, // ignore files larger than 50 MB
  onlyMatches: true, // boolean fast path (omits full match objects)
});
for (const file of dirResult.results) console.log(`Matched: ${file.filePath}`);
```

`totalFiles` counts files that passed the filters and `filteredFiles` counts the discovered ones the filters removed, so a scan that matched nothing because of a typo in a pattern is visible in the result.

## Binary match ABI

In a match-dense scan, building V8 objects and strings for every match costs more than the scan itself. The binary match ABI packs the records into one flat buffer instead.

`scanBinary()` returns a `BinaryScanResult` — `matchCount`, the record `buffer`, and the rule `catalog`. Wrap it in `BinaryMatchView` to get indexed accessors:

```javascript
import { BinaryMatchView } from "@litko/yara-x";

const scanner = compile(`rule Threat { strings: $a = "malicious_string" $b = "suspicious_signature" condition: any of them }`);
const view = new BinaryMatchView(scanner.scanBinary(sampleBuffer));

console.log(`Total match occurrences: ${view.matchCount}`);
console.log(`Matched rules: ${view.catalog.rules.map((rule) => rule.identifier).join(", ")}`);

for (let i = 0; i < view.matchCount; i++) {
  // O(1) indexed access to the raw records
  console.log(`${view.getRule(i).identifier} / ${view.getPattern(i)} at ${view.getOffset(i)}, length ${view.getLength(i)}`);
}

const ruleMatches = view.toRuleMatches(sampleBuffer); // materialize RuleMatch[] when needed
```

`matchCount`, `buffer`, and `catalog` are on the result itself; the view adds `getRule()`, `getRuleId()`, `getPattern()`, `getOffset()`, `getLength()`, `getFlags()`, `getXorKey()`, `getSlice()`, and `toRuleMatches()`.

Read [`docs/binary-match-abi.md`](./docs/binary-match-abi.md) for the raw record layout (24 bytes per match, little-endian), the `flags` word and XOR key, and how `view.catalog` is shared between reads.

## Inspect compiled rules

Read rule counts, imported modules, names, namespaces, tags, and pattern identifiers without scanning or re-parsing:

```javascript
import { compile } from "@litko/yara-x";

const rules = compile(`
  import "pe"
  import "math"

  rule SuspiciousBinary : HighRisk {
    strings:
      $entry = "payload"
    condition:
      $entry and pe.is_pe
  }
`);

console.log(rules.ruleCount); // 1
console.log(rules.getImports()); // ["pe", "math"]

for (const rule of rules.getRules()) {
  console.log(`Rule: ${rule.identifier} in namespace "${rule.namespace}"`);
  console.log(`Tags: ${rule.tags.join(", ")}, patterns: ${rule.patterns.join(", ")}`);
}
```

## Serialize compiled rules

`serialize()` returns a self-contained `Buffer` that another process or worker thread restores with `deserialize()`. Parsing and pattern-automaton construction are skipped; the WASM condition module is still compiled for the local platform, so the speedup is partial (measured ~17% on a 120-rule set). Restored rules behave like freshly compiled ones, and conditions are recompiled for the local platform when the blob loads: ~1.7 ms per process for the two-rule set in [`__test__/performance-regression.mjs`](./__test__/performance-regression.mjs).

```javascript
import { compile, deserialize } from "@litko/yara-x";
import { readFile, writeFile } from "node:fs/promises";

const rules = compile(`rule ProductionIndicator { strings: $t = "malicious payload" condition: $t }`);
await writeFile("./rules.yarx", rules.serialize());

const restored = deserialize(await readFile("./rules.yarx"));
console.log(`Matches from restored rules: ${restored.scan(Buffer.from("malicious payload")).length}`);
```

`rulesFormatInfo()` returns the blob format version and the versions that produce it, so a cache can key on compatibility instead of discovering it at load time:

```javascript
const info = rulesFormatInfo();
// { formatVersion: 12, yaraXVersion: "1.23.0", packageVersion: "0.13.0" }
await cache.set(`${info.formatVersion}:${info.yaraXVersion}`, rules.serialize());
```

> [!NOTE]
> The producer and consumer must report the same `formatVersion`/`yaraXVersion` (the YARA-X version is pinned exactly in [`Cargo.toml`](./Cargo.toml)) with the same module feature set. Treat blobs as trusted input: they contain compiled bytecode and pattern tables, and they do not obfuscate pattern strings.

## Validate rules

`validate()` checks syntax and semantics without building a scanner:

```javascript
import { validate } from "@litko/yara-x";

const result = validate(`rule Example { strings: $p = "valid pattern" condition: $p }`);
for (const error of result.errors) {
  console.error(`[${error.code}] line ${error.line}, col ${error.column}: ${error.message}`);
}
```

A rejected rule set throws, and the thrown error carries the same facts as fields, so you can branch without parsing prose. `compile()`, `fromFile()`, `addRuleSource()`, `addRuleSources()`, and `addRuleFile()` set `ruleCode` to the E-code plus `source` / `line` / `column` when the diagnostic has them, as do the reads that materialize a pending addition. `code` and `message` are unchanged:

```javascript
try {
  compile(untrustedRules);
} catch (error) {
  if (error.ruleCode === "E018") console.error("refusing the pathological regex at", error.line);
}
```

### Branch on the class of failure

An error from a synchronous entry point also carries `kind`, a stable label for what failed, so you do not have to match on message text:

```javascript
const scanner = compile("rule quiet { condition: false }");
try {
  scanner.scanFile("/definitely/missing");
} catch (error) {
  if (error.kind === "io") console.log("unreadable sample");
}
```

| `kind`         | Failure                                                                |
| :------------- | :--------------------------------------------------------------------- |
| `compile`      | A rule set was rejected. `ruleCode` still names the E-code.             |
| `timeout`      | A scan passed the deadline set with `setTimeout()`.                     |
| `io`           | Reading a rule file, a sample, or a serialized blob failed.             |
| `mmap`         | Memory-mapping a sample failed.                                         |
| `protobuf`     | A module produced protobuf that could not be decoded.                    |
| `unknown-module` | A rule referenced a module this build does not include.                |

`kind` never replaces `code` (the N-API status) or `message`. An async rejection carries no `kind`: a task's compute phase has no JavaScript environment to decorate, so those errors keep only `code` and `message`.

## Compiler warnings

`getWarnings()` returns the warnings emitted while compiling, and the compiler options decide how many reach you. Which problems are warnings is YARA-X's decision: a pattern no condition uses is the `E022` error, while a duplicated pattern value is the `duplicate_pattern_value` warning.

```javascript
const rules = compile(`rule Duplicate { strings: $a = "x" $b = "x" condition: any of them }`);
for (const warning of rules.getWarnings()) {
  console.log(`[${warning.code}] ${warning.message}`);
}
// [duplicate_pattern_value] ..., plus two [slow_pattern]

const quietRules = compile(sourceText, {
  maxWarnings: 10, // report at most 10 warnings
  disableWarnings: ["slow_pattern", "duplicate_pattern_value"], // drop these codes
  // enableAllWarnings: false, // suppress every warning
});
```

## Tolerating invalid rules

`ignoreInvalidRules` keeps a large corpus compiling when a few rules are broken. Per-rule failures are skipped and reported. Source-level failures that no single rule can be blamed for — syntax errors, invalid UTF-8, banned or unknown module imports, missing includes — still throw, because a scanner silently missing rules is worse than a failed load:

```javascript
const rules = compile(mixedCorpus, { ignoreInvalidRules: true });

for (const rule of rules.getIgnoredRules()) {
  console.log(`Skipped "${rule.name}" (${rule.reason}): ${rule.detail}`);
}

// Errors attributed to a skipped rule (also summarized in its `detail`).
for (const error of rules.getCompilationErrors()) {
  console.log(`[${error.code}] ${error.source ?? "line:"}:${error.line ?? "?"}`);
}
```

## Include directives

`include` statements resolve against `includeDirectories` and, for `fromFile()`, `addRuleFile()`, and `compileFileToWasm()`, against the directory of the rule file. Explicit `includeDirectories` are searched first, so a configured directory wins when both contain the same file. The rules referenced by the condition live in the included files:

```javascript
const rules = compile(
  `
  include "common/strings.yar"
  include "malware/patterns.yar"

  rule MainDetection { condition: common_string_rule or malware_rule }
  `,
  { enableIncludes: true, includeDirectories: ["./rules", "./rules/common", "./rules/malware"] },
);
```

## Scan limits and safety

These controls apply to the scanner instance and guard against pathological rules and inputs.

```javascript
rules.setMaxMatchesPerPattern(1000); // collect at most 1,000 matches per pattern
rules.setFastScan(true); // stop searching a pattern after its first match
rules.setUseMmap(false); // stream instead of memory-mapping (safer if the file may change mid-scan)
rules.setMatchContextSize(10); // return 10 bytes of surrounding context with each match
rules.setMaxScanSize(10 * 1024 * 1024); // scan at most 10 MB per target; offsets beyond it are ignored
```

### Scan timeout

```javascript
rules.setTimeout(5000); // milliseconds; 0 disables the timeout

try {
  const matches = rules.scan(largeBuffer);
} catch (error) {
  console.error(`Scan aborted: ${error.message}`);
}
```

The timeout is a best-effort deadline: YARA-X stops at the next work-unit boundary, so a scan can overrun it — a 50 ms setting has taken over a second on pathological regexes. Because `0` means no deadline, an unbounded scan is only as safe as the rules you feed it; a regex whose atom matches at nearly every offset (`/a+b/` over a run of `a`) is quadratic by construction. Bound the work structurally instead: `setMaxScanSize()` caps the bytes examined, and `errorOnSlowPattern: true` rejects those patterns at compile time instead of leaving them as a `slow_pattern` warning that only `getWarnings()` reports.

```javascript
const rules = compile(untrustedSource, { errorOnSlowPattern: true }); // throws E018 on a pathological regex
```

For rules you did not write, `safeRules: true` is the one switch, so you do not have to know which options combine into a safe read:

```javascript
// errorOnSlowPattern is part of the preset, so this throws E018 on a pathological regex
const rules = compile(untrustedSource, { safeRules: true });
```

| Limb | Effect |
| :--- | :--- |
| `errorOnSlowPattern` | A pathological regex throws `E018` instead of surviving as a `slow_pattern` warning. |
| `ignoreInvalidRules` | Forced off, so a hostile corpus is not silently trimmed. |
| `include` | Disabled, so a rule set cannot choose which files the compiler opens (`E044`). |

Naming any of them `false` alongside the preset does not re-enable it — an options object assembled by merging can otherwise undo a preset quietly. `errorOnSlowLoop` is deliberately not in the bundle: measured on `/a+b/`, it leaves the pattern compiling. The preset is compile-time only, so a scan already running is still bounded by `setTimeout()` and `setMaxScanSize()`.

### Match context

`setMatchContextSize()` returns surrounding bytes with every match, which is what triage output usually needs:

```javascript
rules.setMatchContextSize(10);
const [first] = rules.scan(Buffer.from("header data confidential payload trailer info"));
const [{ data, contextData, contextMatchOffset }] = first.matches;
console.log(`"${data}" at offset ${contextMatchOffset} inside context "${contextData}"`);
```

`contextMatchOffset` is the match's offset inside `contextData`, not its offset in the payload.

### Matched bytes

`MatchData.data` is a UTF-8 view of the match, so invalid bytes become replacement characters. Scan results also carry `dataBytes`, the exact matched slice as a `Buffer`:

```javascript
const rules = compile(`rule Bytes { strings: $a = { 80 FF 41 } condition: $a }`);
const [match] = rules.scan(Buffer.from([0x80, 0xff, 0x41]));
match.matches[0].data;      // "\uFFFD\uFFFDA" (lossy)
match.matches[0].dataBytes; // <Buffer 80 ff 41>
```

`dataBytes` makes binary patterns round-trippable without re-slicing the input, which matters for `scanFile()` results, where you hold no buffer. It is copied per match, so a scan that expects thousands of matches should consider `setMaxMatchesPerPattern()` or the binary match ABI. Metadata values are decoded the same way: raw bytes (invalid UTF-8, NUL, or escape bytes) become lossy strings rather than being dropped, and the original bytes are not exposed.

### XOR key matches

A pattern compiled with an `xor` modifier reports which key produced the match, so you can unpack an obfuscated sample without a second scan:

```javascript
const rules = compile(`rule XoredPayload { strings: $a = "malware" xor(0x01-0xff) condition: $a }`);

// "malware" XOR 0x42, as it appears in an obfuscated sample.
const sample = Buffer.from("malware").map((byte) => byte ^ 0x42);
const [match] = rules.scan(sample);
const { xorKey, data } = match.matches[0];

xorKey; // 0x42
Buffer.from(data, "latin1").map((byte) => byte ^ xorKey).toString(); // "malware"
```

The matched bytes stay as they appear in the sample, since `data` is a lossy UTF-8 view of them, and keys above `0x7f` can produce bytes that do not round-trip as a string. Use `match.matches[0].dataBytes` (or `scanBinary()` with `getSlice()`) when you need the exact bytes. `xorKey` is absent for plain patterns, so a rule mixing plain and XOR'd strings tells the two apart without inspecting the data.

### Rule logging

Rules can call `console.log()` through the `console` module. Messages arrive on the event loop, so a synchronous scan returns before the callback runs:

```javascript
const rules = compile(`import "console"\nrule Debug { condition: console.log("checked sample") and true }`);

rules.setConsoleLog((message) => console.log(`[rule] ${message}`));
rules.scan(buffer); // logs on the next tick
rules.setConsoleLog(); // stop receiving messages
```

Setting a callback does not keep the process alive, so a script that finishes scanning exits normally. Messages still queued at exit may not be delivered.

### Rule profiling

`getSlowestRules()` reports which rules dominate scan time:

```javascript
rules.scan(buffer);
for (const rule of rules.getSlowestRules(5)) {
  console.log(`${rule.identifier}: ${rule.patternMatchingMs.toFixed(1)} ms patterns, ${rule.conditionMs.toFixed(1)} ms condition`);
}
rules.clearProfilingData(); // reset the counters
```

Timings accumulate across synchronous scans and only rules above 100 ms in total are reported, so this is for tuning a rule set over real traffic rather than single-sample measurement. Async and batch scans run on their own scanners and are not included.

## Emit a WebAssembly module

YARA-X compiles rule conditions to WebAssembly. `compileToWasm()` and `compileFileToWasm()` write that module to disk, and an existing scanner can emit its own:

```javascript
import { compileToWasm } from "@litko/yara-x";

compileToWasm(ruleString, "./output/rules.wasm");

const rules = compile(ruleString);
rules.emitWasmFile("./output/instance.wasm");
await rules.emitWasmFileAsync("./output/async_instance.wasm");
```

> [!NOTE]
> The output is a raw WebAssembly module containing the compiled conditions — useful for inspection with tools such as `wasm2wat`, or for running the conditions in a sandbox that accepts WebAssembly. To move compiled rules between machines, use `serialize()` and `deserialize()` instead.

## Verify a release

GitHub-hosted runners build releases, npm publishes them with trusted publishing and provenance, the native binaries carry GitHub artifact attestations, and release assets are signed keyless with Sigstore:

```sh
npm audit signatures            # npm registry signature and provenance attestations
gh attestation verify path/to/yara-x.*.node -R cawalch/node-yara-x   # GitHub artifact attestation
cosign verify-blob --bundle yara-x.<target>.node.sigstore yara-x.<target>.node \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com   # Sigstore bundle
```

## Performance

[`docs/performance.md`](./docs/performance.md) has the full tables — compile cost by rule shape, scan cost by payload size and rule shape, fast-path comparison, async throughput — plus the machine, the Node version, and the commands to reproduce or compare a baseline (`pnpm profile:baseline`, `pnpm profile:compare`). Headline numbers, from a warm-cache microbenchmark on synthetic payloads: treat them as upper bounds, not predictions for real files.

- 100 KB scan: 14.0 µs p50 (~6.9 GB/s); 5 MB: 519 µs p50 (~10 GB/s).
- Matches cost the time: 50 KB with ~512 matches takes 216 µs p50, longer than the 5 MB payload.
- `isMatch()` beats `scan()` by up to 1.9× when many matches occur, and by nothing on a clean file.
- Concurrent `scanAsync()`: ~178,000 ops/s at 5.6 µs/op; sequential: ~37,000 ops/s.

## API

[`docs/api.md`](./docs/api.md) documents every function, method, and option with its types; [`index.d.ts`](./index.d.ts) is the authoritative source it mirrors. Grouped by task:

| Task | API |
| :--- | :--- |
| Compile a rule set | `compile()`, `fromFile()`, `create()`, `validate()`, `deserialize()`, `rulesFormatInfo()` |
| Scan | `scan()`, `scanFile()`, and the `Async` variants; `isMatch()`, `isFileMatch()` for a boolean |
| Scan many files | `scanFiles()`, `scanDirectory()` (plus `Sync` variants) with `BatchScanOptions` |
| Scan cheaply at scale | `scanBinary()`, `scanFileBinary()` and the `Async` variants — see [Binary match ABI](./docs/binary-match-abi.md) |
| Compile incrementally | `addRuleSource()`, `addRuleSources()`, `addRuleFile()`, `defineVariable()` |
| Inspect and store | `ruleCount`, `getRules()`, `getImports()`, `serialize()` |
| Reports | `getWarnings()`, `getIgnoredRules()`, `getCompilationErrors()` |
| Guard the scan | `setMaxMatchesPerPattern()`, `setMaxScanSize()`, `setTimeout()`, `setFastScan()`, `setUseMmap()`, `errorOnSlowPattern`, `safeRules` |
| Cancel queued work | the `signal` argument on the async scan methods — see [Cancel work you no longer want](#cancel-work-you-no-longer-want) |
| Log and profile | `setConsoleLog()`, `getSlowestRules()`, `clearProfilingData()` |
| WebAssembly | `compileToWasm()`, `compileFileToWasm()`, `emitWasmFile()`, `emitWasmFileAsync()` |
| Options | `CompilerOptions` (compile-time), `BatchScanOptions` (batch scans), per-scan `variables` argument |

## YARA-X modules

The native binary ships every YARA-X module except `vt`, which pulls in the public-suffix list and costs ~1.2 MB on its own:

| Shipped | Compiled out |
| :--- | :--- |
| `console`, `pe`, `elf`, `macho`, `dotnet`, `math`, `hash`, `string`, `time`, `zip`, `lnk`, `dex`, `crx`, `cuckoo` | `vt` |

A rule that imports a compiled-out module fails with `error[E010]: unknown module`. `getImports()` reports the modules a compiled rule set actually uses.

## Platform support

| Platform | Architectures | Binary package |
| :--- | :--- | :--- |
| macOS | x64, arm64 | `@litko/yara-x-darwin-x64`, `@litko/yara-x-darwin-arm64` |
| Linux (glibc) | x64, arm64 | `@litko/yara-x-linux-x64-gnu`, `@litko/yara-x-linux-arm64-gnu` |
| Windows | x64, arm64 | `@litko/yara-x-win32-x64-msvc`, `@litko/yara-x-win32-arm64-msvc` |

The installer adds these as optional dependencies; do not depend on them directly.

## Runtimes

Node.js (>= 20) is the primary target. Bun and Deno load the same prebuilt binary through their Node-API compatibility layers — no separate package, no rebuild:

| Runtime | Status | Notes |
| :--- | :--- | :--- |
| Node.js | primary | 20, 22, 24, 26 — tested on every platform |
| Bun | works | same API; more Node-API call overhead per scan |
| Deno | works | needs `--allow-ffi` (plus `--allow-read` for rule files) |

Deno holds back a release less than 24 hours old by default; install a fresh version with `--min-dep-age 0`. On the same machine a 5 MB scan took ~0.5 ms under Node and ~3.1 ms under Bun and Deno, so the cost is in the call boundary rather than the scan — prefer fewer large scans over many tiny ones there.

Browsers and edge workers cannot load a native addon; use [`@virustotal/yara-x`](https://www.npmjs.com/package/@virustotal/yara-x) (WebAssembly) in those environments.

## Troubleshooting

**`Cannot find module '@litko/yara-x-<platform>'`** — no prebuilt binary exists for your platform and the optional dependency was skipped. The Linux builds target glibc, so musl-based images such as Alpine are unsupported; use a glibc image such as `node:22-bookworm-slim`. On other platforms, [open an issue](https://github.com/cawalch/node-yara-x/issues/new) with your `process.platform`, `process.arch`, and Node.js version.

**`unknown module "vt"`** — `vt` is the only module compiled out. See [YARA-X modules](#yara-x-modules), and [open an issue](https://github.com/cawalch/node-yara-x/issues/new) if a rule set needs it.

**`Unsupported platform` on an unusual architecture** — the six targets above are the full supported set; `armv7`, 32-bit `x86`, and `s390x` are not built.

**`Node.js 20 or newer required`** — the package declares `"engines": { "node": ">= 20" }` and uses `napi-rs` v3, which needs Node 20+.

**Deserialized rules fail to scan** — the producing and consuming environments must use the same YARA-X version and module features. See [Serialize compiled rules](#serialize-compiled-rules).

## Related documentation

- [API reference](./docs/api.md)
- [Performance measurements](./docs/performance.md)
- [Binary match ABI](./docs/binary-match-abi.md)
- [Release process](./docs/release-process.md)
- [YARA-X rule syntax](https://virustotal.github.io/yara-x/docs/writing_rules/anatomy-of-a-rule/) and [differences from YARA](https://virustotal.github.io/yara-x/docs/intro/yara-x-vs-yara/)
- [Releases and changelogs](https://github.com/cawalch/node-yara-x/releases)
- [Security policy](./SECURITY.md) — report vulnerabilities privately

## License

This package is distributed under two licenses:

- **MIT** — the Node.js bindings and project code. See [`LICENSE-MIT`](./LICENSE-MIT).
- **BSD-3-Clause** — the bundled YARA-X library code, which is Copyright (c) VirusTotal. See [`LICENSE-BSD-3-Clause`](./LICENSE-BSD-3-Clause).
