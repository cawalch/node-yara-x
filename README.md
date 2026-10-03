# @litko/yara-x

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cawalch/node-yara-x/badge)](https://scorecard.dev/viewer/?uri=github.com/cawalch/node-yara-x)

The `@litko/yara-x` package provides Node.js bindings for [VirusTotal/yara-x](https://github.com/VirusTotal/yara-x) powered by [napi-rs](https://napi-rs.com). It offers pattern matching and rule evaluation across in-memory buffers and files with zero external runtime dependencies.

## Key features

- **High performance**: Native Rust execution with thread-safe scanner caching.
- **Asynchronous scanning**: Non-blocking asynchronous buffer and file scanning for high-throughput applications.
- **Rules serialization**: Fast zero-copy rule serialization and restoration across processes.
- **WebAssembly compilation**: Compile conditions to WebAssembly for inspection and sandboxed environments.
- **Zero runtime dependencies**: Ships precompiled native binaries for macOS, Linux, and Windows.

## Installation

Install `@litko/yara-x` using your package manager of choice:

```sh
npm install @litko/yara-x
```

### Verify release integrity

Releases are built on GitHub-hosted runners and published to npm with Trusted Publishing and provenance. Native `.node` binaries include GitHub artifact attestations.

To verify npm registry signatures and provenance attestations:

```sh
npm audit signatures
```

To verify downloaded native binaries against GitHub artifact attestations:

```sh
gh attestation verify path/to/yara-x.*.node -R cawalch/node-yara-x
```

## Quickstart

To compile a YARA rule from a string and scan an in-memory buffer:

```javascript
import { compile } from "@litko/yara-x";

// Compile a rule from source text.
const rules = compile(`
  rule HelloWorld {
    strings:
      $greeting = "hello world"
    condition:
      $greeting
  }
`);

// Scan an in-memory buffer.
const buffer = Buffer.from("This is a test with hello world in it");
const matches = rules.scan(buffer);

if (matches.length > 0) {
  console.log(`Found ${matches.length} matching rule(s):`);
  for (const match of matches) {
    console.log(`- Rule: ${match.ruleIdentifier}`);
    for (const stringMatch of match.matches) {
      console.log(`  * Offset ${stringMatch.offset}: ${stringMatch.data}`);
    }
  }
} else {
  console.log("No matches found.");
}
```

## Scan files

To scan a file on disk without reading the entire contents into Node.js heap memory:

```javascript
import { fromFile } from "@litko/yara-x";

// Compile rules directly from a file.
const rules = fromFile("./rules/malware_rules.yar");

try {
  // Scan a file path synchronously.
  const matches = rules.scanFile("./samples/suspicious_file.exe");
  console.log(`Found ${matches.length} matching rule(s).`);
} catch (error) {
  console.error(`Scanning error: ${error.message}`);
}
```

## Scan asynchronously

To avoid blocking the Node.js event loop during large file or buffer scans:

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

async function scanTarget(filePath) {
  try {
    const matches = await rules.scanFileAsync(filePath);
    console.log(`Found ${matches.length} matching rule(s).`);
  } catch (error) {
    console.error(`Async scan error: ${error.message}`);
  }
}

await scanTarget("./samples/large_file.bin");
```

## Define and override variables

You can define global variables during compilation and optionally override them at scan time:

```javascript
import { compile } from "@litko/yara-x";

// Define global variables at compile time.
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

// Scan using default variable values.
let matches = rules.scan(Buffer.from("test payload"));
console.log(`Matches with default variables: ${matches.length}`);

// Override variable values for this scan operation.
matches = rules.scan(Buffer.from("test payload"), {
  string_var: "no secrets here",
  int_var: 5,
  bool_var: false,
});
console.log(`Matches with overridden variables: ${matches.length}`);
```

## Organize rules with namespaces

Namespaces isolate rule identifiers, preventing naming collisions across rule sets:

```javascript
import { compile, create } from "@litko/yara-x";

// Compile rules into a specific namespace.
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
console.log(`Matched rule namespace: ${match.namespace}`); // "alpha"

// Add rules into separate namespaces on an incremental scanner.
const scanner = create();
scanner.addRuleSource('rule SharedName { strings: $a = "one" condition: $a }', "first_ns");
scanner.addRuleSource('rule SharedName { strings: $a = "two" condition: $a }', "second_ns");
```

## Serialize and restore compiled rules

You can serialize compiled rules into a compact, self-contained binary `Buffer` and restore them in another process or worker thread without re-parsing rule source text. Conditions are recompiled for the local platform in 1–2 ms on load:

```javascript
import { compile, deserialize } from "@litko/yara-x";
import { readFile, writeFile } from "node:fs/promises";

// Producer: compile rules once and serialize to a Buffer.
const rules = compile(`
  rule ProductionIndicator {
    strings:
      $target = "malicious payload"
    condition:
      $target
  }
`);
const blob = rules.serialize();
await writeFile("./rules.yarx", blob);

// Consumer: restore compiled rules without parsing source text.
const diskBlob = await readFile("./rules.yarx");
const restoredRules = deserialize(diskBlob);

// All scanning methods function identically on restored rules.
const matches = restoredRules.scan(Buffer.from("malicious payload"));
console.log(`Matches from restored rules: ${matches.length}`);
```

> [!NOTE]
> Serialized blobs require identical YARA-X versions (`1.20.x`) and compiled module feature sets between producer and consumer environments. Serialization stores compiled bytecode and pattern tables, but does not obfuscate pattern strings.

## Build rules incrementally

To construct a scanner dynamically from multiple strings or files:

```javascript
import { create } from "@litko/yara-x";

const scanner = create();

// Add an individual rule string.
scanner.addRuleSource(`
  rule FirstRule {
    strings:
      $pattern = "first pattern"
    condition:
      $pattern
  }
`);

// Add rules from an external file with an optional namespace.
scanner.addRuleFile("./rules/more_rules.yar", "custom_namespace");

// Add multiple rule sources in a single pass for optimal performance.
scanner.addRuleSources([
  {
    source: `
      rule BatchRule1 {
        condition: true
      }
    `,
    namespace: "batch",
  },
  {
    source: `
      rule BatchRule2 {
        condition: true
      }
    `,
  },
]);

const matches = scanner.scan(Buffer.from("test data with first pattern"));
console.log(`Found ${matches.length} matching rule(s).`);
```

> [!TIP]
> Use `addRuleSources()` when loading multiple rule sources dynamically. It compiles all sources in a single pass ($O(n)$) rather than recompiling the accumulated rule set on each addition ($O(n^2)$).

## Validate rules

To validate rule syntax and semantic correctness without creating an active scanner instance:

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

if (result.errors.length === 0) {
  console.log("Rules are valid.");
} else {
  console.error("Rule validation failed:");
  for (const error of result.errors) {
    console.error(`- [${error.code}] line ${error.line}, col ${error.column}: ${error.message}`);
  }
}
```

## Manage compiler warnings

Inspect warnings generated during compilation, or configure warning limits for noisy rule corpora:

```javascript
import { compile } from "@litko/yara-x";

// Retrieve compiler warnings.
const rules = compile(`
  rule WarningRule {
    strings:
      $unused = "unused string"
    condition:
      true // Triggers invariant boolean warning
  }
`);

const warnings = rules.getWarnings();
for (const warning of warnings) {
  console.log(`Warning [${warning.code}]: ${warning.message}`);
}

// Suppress specific warnings or cap reporting.
const quietRules = compile(sourceText, {
  // Cap the total number of warnings emitted.
  maxWarnings: 10,

  // Silence specific noisy warning codes.
  disableWarnings: ["slow_pattern", "duplicate_pattern_value"],

  // Or disable all compiler warnings entirely.
  // enableAllWarnings: false,
});
```

## Fault-tolerant compilation

To compile large rule corpora without aborting the entire compilation when individual rules contain errors, set `ignoreInvalidRules`:

```javascript
import { compile } from "@litko/yara-x";

const rules = compile(mixedCorpus, {
  ignoreInvalidRules: true,
});

// Inspect rules that were skipped due to compilation errors or missing modules.
const ignored = rules.getIgnoredRules();
for (const rule of ignored) {
  console.log(`Skipped rule "${rule.name}" (${rule.reason}): ${rule.detail}`);
}

// Inspect source-level errors that could not be attributed to an individual rule.
const sourceErrors = rules.getCompilationErrors();
for (const err of sourceErrors) {
  console.log(`Source error [${err.code}]: ${err.message}`);
}
```

## Configure include directories

To resolve external files referenced via `include "..."` statements:

```javascript
import { compile } from "@litko/yara-x";

const mainRule = `
  include "common/strings.yar"
  include "malware/patterns.yar"

  rule MainDetection {
    condition:
      common_string_rule or malware_rule
  }
`;

const rules = compile(mainRule, {
  enableIncludes: true,
  includeDirectories: [
    "./rules",
    "./rules/common",
    "./rules/malware",
  ],
});
```

## Tune scan performance

Configure runtime controls to protect against resource exhaustion and optimize execution.

### Limit matches per pattern

Cap the number of matches captured per pattern to prevent unbounded memory growth on repeated bytes:

```javascript
import { compile } from "@litko/yara-x";

const rules = compile(`
  rule MatchLimiter {
    strings:
      $a = "pattern"
    condition:
      $a
  }
`);

// Collect at most 1,000 matches per pattern.
rules.setMaxMatchesPerPattern(1000);

const data = Buffer.from("pattern ".repeat(10000));
const matches = rules.scan(data);

console.log(`Matches collected: ${matches[0].matches.length}`); // 1000
```

### Memory-mapped file scanning

Control whether file scans use memory-mapped I/O (`mmap`). Disabling `mmap` uses standard streaming file reads, which is safer when scanning untrusted files that could be modified concurrently:

```javascript
// Disable memory-mapped files.
rules.setUseMmap(false);

const matches = rules.scanFile("./untrusted_sample.bin");
```

### Scan execution timeout

Enforce a timeout on scan operations to protect against pathological regular expressions:

```javascript
// Timeout in milliseconds.
rules.setTimeout(5000);

try {
  const matches = rules.scan(largeBuffer);
} catch (error) {
  console.error(`Scan aborted: ${error.message}`);
}
```

### Capture match context

Retrieve surrounding bytes around a match for triage and reporting:

```javascript
// Capture 10 bytes before and after each pattern match.
rules.setMatchContextSize(10);

const data = Buffer.from("header data confidential payload trailer info");
const matches = rules.scan(data);

for (const match of matches[0]?.matches ?? []) {
  console.log(`Match: "${match.data}"`);
  console.log(`Surrounding context: "${match.contextData}"`);
  console.log(`Match offset within context: ${match.contextMatchOffset}`);
}
```

## WebAssembly compilation

You can compile rules directly to WebAssembly for inspection or sandboxed execution:

```javascript
import { compile, compileToWasm } from "@litko/yara-x";

// Compile rules directly to a WASM binary file.
compileToWasm(ruleString, "./output/rules.wasm");

// Or emit WASM from an existing compiled scanner instance.
const rules = compile(ruleString);
rules.emitWasmFile("./output/instance.wasm");
await rules.emitWasmFileAsync("./output/async_instance.wasm");
```

> [!NOTE]
> `emitWasmFile` produces a raw WebAssembly debug artifact containing compiled conditions for inspection with tools like `wasm2wat`. To distribute compiled rules across machines, use `serialize()` and `deserialize()`.

## Performance benchmarks

The following benchmarks demonstrate scanner creation, scanning throughput, and feature overhead.

### Benchmark environment

- **Hardware**: Apple Silicon M3 Max, 36 GB RAM
- **Build**: Release build with Link-Time Optimization (LTO)
- **Methodology**: Statistical analysis across repeated runs with percentile reporting

### Scanner creation performance

| Rule type | Mean | p50 | p95 | p99 |
| :--- | :--- | :--- | :--- | :--- |
| Simple rule | 2.43 ms | 2.41 ms | 2.87 ms | 3.11 ms |
| Complex rule | 2.57 ms | 2.52 ms | 2.96 ms | 3.06 ms |
| Regex rule | 7.57 ms | 7.47 ms | 8.29 ms | 8.70 ms |
| Multiple rules | 2.05 ms | 2.03 ms | 2.24 ms | 2.42 ms |

### Scanning performance by payload size

| Payload size | Rule type | Mean duration | Throughput |
| :--- | :--- | :--- | :--- |
| 64 B | Simple | 3 µs | ~21 MB/s |
| 100 KB | Simple | 6 µs | ~16.7 GB/s |
| 100 KB | Complex | 73 µs | ~1.4 GB/s |
| 100 KB | Regex | 7 µs | ~14.3 GB/s |
| 100 KB | Multiple rules | 73 µs | ~1.4 GB/s |
| 10 MB | Simple | 204 µs | ~49 GB/s |

### Feature overhead

| Feature | Mean duration | Notes |
| :--- | :--- | :--- |
| Variable scanning | 1 µs | Pre-compiled variables |
| Runtime variables | 2 µs | Variables set at scan time |
| Asynchronous scanning | 11 µs | Non-blocking async event loop delegation |

## API reference

### Functions

| Function | Description |
| :--- | :--- |
| `compile(ruleSource, options?)` | Compiles YARA rules from a string and returns a `YaraX` scanner instance. |
| `fromFile(rulePath, options?)` | Compiles YARA rules from a file path and returns a `YaraX` scanner instance. |
| `create()` | Creates an empty `YaraX` scanner instance for incremental rule compilation. |
| `deserialize(data)` | Restores a `YaraX` scanner instance from a serialized binary `Buffer`. |
| `validate(ruleSource, options?)` | Validates YARA rules from a string without creating an executable scanner. |
| `compileToWasm(ruleSource, outputPath, options?)` | Compiles rules from a string and writes the WebAssembly module to `outputPath`. |
| `compileFileToWasm(rulesPath, outputPath, options?)` | Compiles rules from a file and writes the WebAssembly module to `outputPath`. |

### YaraX methods

| Method | Description |
| :--- | :--- |
| `scan(data, variables?)` | Scans a `Buffer` synchronously and returns matching rules. |
| `scanFile(filePath, variables?)` | Scans a file on disk synchronously and returns matching rules. |
| `scanAsync(data, variables?)` | Scans a `Buffer` asynchronously and returns a `Promise` resolving to matching rules. |
| `scanFileAsync(filePath, variables?)` | Scans a file asynchronously and returns a `Promise` resolving to matching rules. |
| `serialize()` | Serializes compiled rules into a portable binary `Buffer`. |
| `addRuleSource(ruleSource, namespace?)` | Adds a rule string to an existing scanner instance. |
| `addRuleSources(ruleSources)` | Adds multiple rule sources in a single compilation pass ($O(n)$ batch addition). |
| `addRuleFile(filePath, namespace?)` | Adds rules from a file to an existing scanner instance. |
| `defineVariable(name, value)` | Defines a global variable on an incremental scanner. |
| `getWarnings()` | Returns compiler warnings generated during compilation. |
| `getIgnoredRules()` | Returns rules skipped during tolerant compilation or due to ignored modules. |
| `getCompilationErrors()` | Returns source-level errors collected during tolerant compilation (`ignoreInvalidRules: true`). |
| `setMaxMatchesPerPattern(maxMatches)` | Sets the maximum number of matches collected per pattern. |
| `setUseMmap(useMmap)` | Enables or disables memory-mapped files for file scanning. |
| `setTimeout(timeoutMs)` | Sets the scan execution timeout in milliseconds. |
| `setMatchContextSize(size)` | Sets the number of context bytes retrieved around each match. |
| `emitWasmFile(outputPath)` | Writes the compiled WebAssembly condition module synchronously to disk. |
| `emitWasmFileAsync(outputPath)` | Writes the compiled WebAssembly condition module asynchronously to disk. |

### CompilerOptions

| Option | Type | Description |
| :--- | :--- | :--- |
| `namespace` | `string` | Target namespace for the compiled rules. |
| `defineVariables` | `Record<string, string \| number \| boolean>` | Global variables defined for the compiler. |
| `ignoreInvalidRules` | `boolean` | Skips invalid rules instead of failing compilation (`getIgnoredRules()` / `getCompilationErrors()`). |
| `ignoreModules` | `string[]` | List of module names to ignore during compilation. |
| `bannedModules` | `BannedModule[]` | List of banned modules that trigger compilation errors when imported. |
| `features` | `string[]` | Feature flags to enable during compilation. |
| `relaxedReSyntax` | `boolean` | Enables relaxed regular expression syntax. |
| `conditionOptimization` | `boolean` | Enables rule condition optimization. |
| `errorOnSlowPattern` | `boolean` | Promotes slow pattern warnings to compilation errors. |
| `errorOnSlowLoop` | `boolean` | Promotes slow loop warnings to compilation errors. |
| `maxWarnings` | `number` | Maximum number of warnings reported by the compiler. |
| `disableWarnings` | `string[]` | List of specific warning codes to disable. |
| `enableAllWarnings` | `boolean` | Enables or disables all compiler warnings (default: `true`). |
| `includeDirectories` | `string[]` | Directories to search when resolving `include` statements. |
| `enableIncludes` | `boolean` | Enables or disables `include` statement processing. |

## License

This project is licensed under two separate licenses:

- **MIT License**: Node.js bindings and project code. See [`LICENSE-MIT`](./LICENSE-MIT) for details.
- **BSD-3-Clause License**: Included YARA-X library code. See [`LICENSE-BSD-3-Clause`](./LICENSE-BSD-3-Clause) for details.
