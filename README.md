# @litko/yara-x

[![npm version](https://img.shields.io/npm/v/@litko%2Fyara-x)](https://www.npmjs.com/package/@litko/yara-x)
[![Node.js](https://img.shields.io/node/v/@litko%2Fyara-x)](https://www.npmjs.com/package/@litko/yara-x)
[![CI](https://github.com/cawalch/node-yara-x/actions/workflows/CI.yml/badge.svg)](https://github.com/cawalch/node-yara-x/actions/workflows/CI.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cawalch/node-yara-x/badge)](https://scorecard.dev/viewer/?uri=github.com/cawalch/node-yara-x)

Node.js bindings for [YARA-X](https://github.com/VirusTotal/yara-x), the Rust rewrite of YARA, built with [napi-rs](https://napi-rs.com). Scan buffers and files with YARA rules from JavaScript, with no YARA installation and no JavaScript runtime dependency.

- `compile()` and `fromFile()` return a scanner that reuses its compiled state, so a rule set is parsed once and scanned many times.
- `scanAsync()` and `scanFileAsync()` run on a libuv worker thread, so a large scan does not block the event loop.
- `serialize()` and `deserialize()` move compiled rules between processes and worker threads.
- `emitWasmFile()` writes the compiled rule conditions as a WebAssembly module for inspection and sandboxing.
- Six prebuilt targets (macOS, Linux, Windows — see [Platform support](#platform-support)). Nothing is compiled at install time and there is no `postinstall` script.

## Install

```sh
npm install @litko/yara-x
```

```sh
pnpm add @litko/yara-x
yarn add @litko/yara-x
```

Requires Node.js 20 or newer. The matching prebuilt binary is installed automatically through an optional platform package; if no binary exists for your platform, see [Troubleshooting](#troubleshooting).

Both module systems work:

```javascript
// ES modules
import { compile } from "@litko/yara-x";

// CommonJS
const { compile } = require("@litko/yara-x");
```

Type definitions ship with the package, so TypeScript picks them up with no extra dependency.

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

Rule syntax is documented upstream: [Anatomy of a rule](https://virustotal.github.io/yara-x/docs/writing_rules/anatomy-of-a-rule/) and [differences with YARA](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/).

## Scan a file

`fromFile()` compiles rules from a file, and `scanFile()` reads the target from disk without copying it into the Node.js heap first:

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

const rules = compile(`
  rule LargeFileDetection {
    strings:
      $pattern = "sensitive payload"
    condition:
      $pattern
  }
`);

const matches = await rules.scanFileAsync("./samples/large_file.bin");
console.log(`Found ${matches.length} matching rule(s).`);
```

## Variables

Global variables can be defined at compile time and overridden per scan:

```javascript
import { compile } from "@litko/yara-x";

const rules = compile(
  `
  rule VariableRule {
    condition:
      string_var contains "secret" and int_var > 10 and bool_var
  }
  `,
  {
    defineVariables: {
      string_var: "this is a secret message",
      int_var: 20,
      bool_var: true,
    },
  },
);

// Uses the compile-time defaults.
console.log(rules.scan(Buffer.from("test payload")).length);

// Overrides them for this scan only.
console.log(
  rules.scan(Buffer.from("test payload"), {
    string_var: "no secrets here",
    int_var: 5,
    bool_var: false,
  }).length,
);
```

Incremental scanners use `defineVariable()` instead:

```javascript
const scanner = create();
scanner.defineVariable("threshold", 42);
```

## Namespaces

Namespaces keep rule identifiers unique across rule sets:

```javascript
import { compile, create } from "@litko/yara-x";

const rules = compile(
  `
  rule NamespacedRule {
    strings:
      $pattern = "namespace indicator"
    condition:
      $pattern
  }
  `,
  { namespace: "alpha" },
);

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

scanner.addRuleSource(`
  rule FirstRule {
    strings:
      $pattern = "first pattern"
    condition:
      $pattern
  }
`);

scanner.addRuleFile("./rules/more_rules.yar", "custom_namespace");

scanner.addRuleSources([
  { source: "rule BatchRule1 { condition: true }", namespace: "batch" },
  { source: "rule BatchRule2 { condition: true }" },
]);

const matches = scanner.scan(Buffer.from("test data with first pattern"));
console.log(`Found ${matches.length} matching rule(s).`);
```

Each `addRuleSource()` recompiles the accumulated rule set. When adding more than a couple of sources, prefer `addRuleSources()`, which compiles them in one pass.

## Serialize compiled rules

`serialize()` returns a self-contained `Buffer` that another process or worker thread can restore with `deserialize()`, skipping rule parsing and pattern compilation:

```javascript
import { compile, deserialize } from "@litko/yara-x";
import { readFile, writeFile } from "node:fs/promises";

const rules = compile(`
  rule ProductionIndicator {
    strings:
      $target = "malicious payload"
    condition:
      $target
  }
`);

await writeFile("./rules.yarx", rules.serialize());

const restored = deserialize(await readFile("./rules.yarx"));
const matches = restored.scan(Buffer.from("malicious payload"));
console.log(`Matches from restored rules: ${matches.length}`);
```

Restored rules behave exactly like freshly compiled ones. Conditions still have to be recompiled for the local platform when the blob is loaded: measured at ~1.7 ms per process for the two-rule set in [`__test__/performance-regression.mjs`](./__test__/performance-regression.mjs).

> [!NOTE]
> The producer and consumer must run the same YARA-X version (`1.21.x`) with the same module feature set. Serialized blobs contain compiled bytecode and pattern tables, and they do not obfuscate pattern strings.

## Validate rules

`validate()` checks syntax and semantics without building a scanner:

```javascript
import { validate } from "@litko/yara-x";

const result = validate(`
  rule ValidationExample {
    strings:
      $pattern = "valid pattern"
    condition:
      $pattern
  }
`);

if (result.errors.length > 0) {
  for (const error of result.errors) {
    console.error(`[${error.code}] line ${error.line}, col ${error.column}: ${error.message}`);
  }
}
```

## Compiler warnings

`getWarnings()` returns the warnings emitted while compiling, and the compiler can be told to report fewer of them:

```javascript
import { compile } from "@litko/yara-x";

const rules = compile(`
  rule WarningRule {
    strings:
      $unused = "unused string"
    condition:
      true
  }
`);

for (const warning of rules.getWarnings()) {
  console.log(`[${warning.code}] ${warning.message}`);
}

const quietRules = compile(sourceText, {
  maxWarnings: 10,
  disableWarnings: ["slow_pattern", "duplicate_pattern_value"],
  // enableAllWarnings: false,  // suppress all compiler warnings
});
```

## Tolerating invalid rules

`ignoreInvalidRules` keeps a large corpus compiling when a few rules are broken:

```javascript
import { compile } from "@litko/yara-x";

const rules = compile(mixedCorpus, { ignoreInvalidRules: true });

// Rules that were skipped, and why.
for (const rule of rules.getIgnoredRules()) {
  console.log(`Skipped "${rule.name}" (${rule.reason}): ${rule.detail}`);
}

// Errors that could not be attributed to a single rule.
for (const error of rules.getCompilationErrors()) {
  console.log(`[${error.code}] ${error.message}`);
}
```

## Include directives

`include` statements are resolved against `includeDirectories`:

```javascript
import { compile } from "@litko/yara-x";

const rules = compile(
  `
  include "common/strings.yar"
  include "malware/patterns.yar"

  rule MainDetection {
    condition:
      common_string_rule or malware_rule
  }
  `,
  {
    enableIncludes: true,
    includeDirectories: ["./rules", "./rules/common", "./rules/malware"],
  },
);
```

## Scan limits and safety

These controls apply to the scanner instance and protect against pathological rules and inputs.

### Limit matches per pattern

```javascript
// Collect at most 1,000 matches per pattern.
rules.setMaxMatchesPerPattern(1000);

const matches = rules.scan(Buffer.from("pattern ".repeat(10000)));
console.log(matches[0].matches.length); // 1000
```

### Memory-mapped file scanning

File scans use memory-mapped I/O by default. Turning it off falls back to streaming reads, which is safer when the file could be modified while it is being scanned:

```javascript
rules.setUseMmap(false);
const matches = rules.scanFile("./untrusted_sample.bin");
```

### Scan timeout

```javascript
rules.setTimeout(5000); // milliseconds

try {
  const matches = rules.scan(largeBuffer);
} catch (error) {
  console.error(`Scan aborted: ${error.message}`);
}
```

### Match context

`setMatchContextSize()` includes surrounding bytes with every match, which is usually what you want for triage output:

```javascript
rules.setMatchContextSize(10);

const matches = rules.scan(Buffer.from("header data confidential payload trailer info"));
for (const match of matches[0]?.matches ?? []) {
  console.log(`Match: "${match.data}"`);
  console.log(`Context: "${match.contextData}" (offset ${match.contextMatchOffset})`);
}
```

## Emit a WebAssembly module

YARA-X compiles rule conditions to WebAssembly. `compileToWasm()` and `compileFileToWasm()` write that module to disk, and an existing scanner can emit its own module with `emitWasmFile()`:

```javascript
import { compile, compileToWasm } from "@litko/yara-x";

compileToWasm(ruleString, "./output/rules.wasm");

const rules = compile(ruleString);
rules.emitWasmFile("./output/instance.wasm");
await rules.emitWasmFileAsync("./output/async_instance.wasm");
```

> [!NOTE]
> The output is a raw WebAssembly module containing the compiled conditions — useful for inspection with tools such as `wasm2wat`, or for running the conditions in a sandbox that accepts WebAssembly. To move compiled rules between machines, use `serialize()` and `deserialize()` instead.

## Verify a release

Releases are built on GitHub-hosted runners, published to npm with trusted publishing and provenance, and the native binaries carry GitHub artifact attestations. Release assets are additionally signed keyless with Sigstore.

```sh
# npm registry signature and provenance attestations
npm audit signatures

# GitHub artifact attestation for a downloaded binary
gh attestation verify path/to/yara-x.*.node -R cawalch/node-yara-x

# Sigstore bundle attached to the GitHub release
cosign verify-blob --bundle yara-x.<target>.node.sigstore yara-x.<target>.node \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Performance

The numbers below come from the repository's committed baseline, [`__test__/baseline-performance.json`](./__test__/baseline-performance.json), and can be regenerated with `pnpm profile:baseline`.

- **Machine**: Apple Silicon (darwin/arm64), 14 cores, 36 GB RAM
- **Node**: v26.10.0, release build with LTO
- **Recorded**: 2026-10-04
- **Reproduce**: `pnpm profile:baseline`, then `pnpm profile:compare __test__/baseline-performance.json` to check a change for regressions

The payloads are synthetic and highly repetitive (for example, 100 KB filled with a single byte plus three planted patterns), so the throughput column is an upper bound for a warm-cache microbenchmark rather than a prediction for real files.

### Compiling rules

| Rule shape | mean | p50 | p95 | p99 |
| :--- | ---: | ---: | ---: | ---: |
| 2 strings, `any of them` | 1.86 ms | 1.81 ms | 2.18 ms | 2.43 ms |
| 10 strings, `2 of ($a*) and 1 of ($b*)` | 1.87 ms | 1.85 ms | 2.05 ms | 2.13 ms |
| 4 regular expressions | 10.21 ms | 10.19 ms | 10.45 ms | 11.11 ms |
| 5 separate rules | 2.16 ms | 2.14 ms | 2.28 ms | 2.62 ms |
| Hex patterns, regex and anchored strings | 2.27 ms | 2.25 ms | 2.41 ms | 2.85 ms |

50 iterations per rule shape.

### Scanning by payload size

Two-string rule, `any of them`, 100 iterations (10 for the 5 MB payload):

| Payload | mean | p50 | p95 | p99 | Throughput |
| :--- | ---: | ---: | ---: | ---: | ---: |
| 58 B | 3.7 µs | 3.5 µs | 5.3 µs | 11.4 µs | — |
| 100 KB | 14.8 µs | 14.0 µs | 17.8 µs | 19.8 µs | ~6.9 GB/s |
| 5 MB | 520 µs | 519 µs | 599 µs | 599 µs | ~10 GB/s |
| 50 KB with ~512 matches | 221 µs | 216 µs | 289 µs | 342 µs | ~0.23 GB/s |

Matches are what cost time: the 50 KB payload holds roughly 512 occurrences of the pattern, and scanning it takes longer than the 5 MB payload with three occurrences.

### Scanning by rule shape

100 KB payload, 50 iterations per rule shape:

| Rule shape | mean | p50 | p95 | p99 |
| :--- | ---: | ---: | ---: | ---: |
| 2 strings | 13.8 µs | 12.5 µs | 19.2 µs | 44.5 µs |
| 10 strings | 12.5 µs | 11.9 µs | 14.9 µs | 28.1 µs |
| 4 regular expressions | 65.6 µs | 63.6 µs | 78.1 µs | 79.9 µs |
| 5 separate rules | 15.9 µs | 14.4 µs | 19.6 µs | 22.0 µs |
| Hex patterns, regex and anchored strings | 8.9 µs | 8.4 µs | 10.6 µs | 17.5 µs |

The baseline also records memory, CPU, and GC statistics for each of these runs; see the JSON for the full set.

## API

The generated type definitions in [`index.d.ts`](./index.d.ts) are the authoritative reference for signatures; it is what TypeScript resolves when you import the package.

### Functions

| Function | Description |
| :--- | :--- |
| `compile(ruleSource, options?)` | Compiles YARA rules from a string and returns a `YaraX` scanner. |
| `fromFile(rulePath, options?)` | Compiles YARA rules from a file and returns a `YaraX` scanner. |
| `create()` | Returns an empty `YaraX` scanner for incremental rule compilation. |
| `deserialize(data)` | Restores a `YaraX` scanner from a serialized `Buffer`. |
| `validate(ruleSource, options?)` | Validates rules without creating a scanner. |
| `compileToWasm(ruleSource, outputPath, options?)` | Compiles rules from a string and writes the WebAssembly module to `outputPath`. |
| `compileFileToWasm(rulesPath, outputPath, options?)` | Compiles rules from a file and writes the WebAssembly module to `outputPath`. |

### YaraX methods

| Method | Description |
| :--- | :--- |
| `scan(data, variables?)` | Scans a `Buffer` synchronously and returns the matching rules. |
| `scanFile(filePath, variables?)` | Scans a file on disk synchronously. |
| `scanAsync(data, variables?)` | Scans a `Buffer` on a worker thread. |
| `scanFileAsync(filePath, variables?)` | Scans a file on disk on a worker thread. |
| `serialize()` | Serializes compiled rules into a portable `Buffer`. |
| `addRuleSource(ruleSource, namespace?)` | Adds one rule source to an incremental scanner. |
| `addRuleSources(ruleSources)` | Adds several rule sources in a single compilation pass. |
| `addRuleFile(filePath, namespace?)` | Adds rules from a file to an incremental scanner. |
| `defineVariable(name, value)` | Defines a global variable on an incremental scanner. |
| `getWarnings()` | Returns compiler warnings from the last compilation. |
| `getIgnoredRules()` | Returns rules skipped by tolerant compilation or ignored modules. |
| `getCompilationErrors()` | Returns source-level errors collected when `ignoreInvalidRules` is set. |
| `setMaxMatchesPerPattern(maxMatches)` | Caps the matches collected per pattern. |
| `setUseMmap(useMmap)` | Enables or disables memory-mapped file scanning. |
| `setTimeout(timeoutMs)` | Sets the scan timeout in milliseconds. |
| `setMatchContextSize(size)` | Sets how many context bytes are returned with each match. |
| `emitWasmFile(outputPath)` | Writes the compiled WebAssembly condition module to disk synchronously. |
| `emitWasmFileAsync(outputPath)` | Writes the compiled WebAssembly condition module to disk asynchronously. |

### CompilerOptions

| Option | Type | Description |
| :--- | :--- | :--- |
| `namespace` | `string` | Target namespace for the compiled rules. |
| `defineVariables` | `Record<string, string \| number \| boolean>` | Global variables defined on the compiler. |
| `ignoreInvalidRules` | `boolean` | Skips invalid rules instead of failing compilation. |
| `ignoreModules` | `string[]` | Module names to ignore during compilation. |
| `bannedModules` | `BannedModule[]` | Modules that raise a compilation error when imported. |
| `features` | `string[]` | Feature flags to enable. |
| `relaxedReSyntax` | `boolean` | Enables relaxed regular expression syntax. |
| `conditionOptimization` | `boolean` | Enables rule condition optimization. |
| `errorOnSlowPattern` | `boolean` | Promotes slow pattern warnings to errors. |
| `errorOnSlowLoop` | `boolean` | Promotes slow loop warnings to errors. |
| `maxWarnings` | `number` | Maximum number of warnings reported. |
| `disableWarnings` | `string[]` | Warning codes to suppress. |
| `enableAllWarnings` | `boolean` | Enables or disables all compiler warnings (default `true`). |
| `includeDirectories` | `string[]` | Directories searched when resolving `include` statements. |
| `enableIncludes` | `boolean` | Enables or disables `include` processing. |

### Types

`BannedModule`, `CompileResult`, `CompilerError`, `CompilerWarning`, `IgnoredRule`, `MatchData`, `RuleMatch`, `RuleSource`, and the `YaraX` class are all exported and documented in `index.d.ts`.

## Platform support

| Platform | Architectures | Binary package |
| :--- | :--- | :--- |
| macOS | x64, arm64 | `@litko/yara-x-darwin-x64`, `@litko/yara-x-darwin-arm64` |
| Linux (glibc) | x64, arm64 | `@litko/yara-x-linux-x64-gnu`, `@litko/yara-x-linux-arm64-gnu` |
| Windows | x64, arm64 | `@litko/yara-x-win32-x64-msvc`, `@litko/yara-x-win32-arm64-msvc` |

These packages are installed automatically as optional dependencies — do not depend on them directly.

## Troubleshooting

**`Cannot find module '@litko/yara-x-<platform>'`** — there is no prebuilt binary for your platform and npm skipped the optional dependency. The most common cause is a musl-based Linux image such as Alpine: the Linux builds target glibc. Use a glibc-based image (`node:22-bookworm-slim`, `node:22-alpine` will not work) or install `libc6-compat`. On other platforms, [open an issue](https://github.com/cawalch/node-yara-x/issues/new) with your `process.platform`, `process.arch`, and Node.js version.

**`Unsupported platform` on an unusual architecture** — the six targets above are the full supported set. `armv7`, 32-bit `x86`, and `s390x` are not built.

**`Node.js 20 or newer required`** — the package declares `"engines": { "node": ">= 20" }` and uses `napi-rs` v3, which requires Node 20+.

**Deserialized rules fail to scan** — the producing and consuming environments must use the same YARA-X version and module features. See [Serialize compiled rules](#serialize-compiled-rules).

## Related documentation

- [YARA-X rule syntax](https://virustotal.github.io/yara-x/docs/writing_rules/anatomy-of-a-rule/) and [differences from YARA](https://virustotal.github.io/yara-x/docs/intro/yara-x-vs-yara/)
- [Release process](./docs/release-process.md)
- [Releases and changelogs](https://github.com/cawalch/node-yara-x/releases)
- [Security policy](./SECURITY.md) — please report vulnerabilities privately

## License

This package is distributed under two licenses:

- **MIT** — the Node.js bindings and project code. See [`LICENSE-MIT`](./LICENSE-MIT).
- **BSD-3-Clause** — the bundled YARA-X library code, which is Copyright (c) VirusTotal. See [`LICENSE-BSD-3-Clause`](./LICENSE-BSD-3-Clause).
