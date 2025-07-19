# @litko/yara-x

## Features

- High Performance: Built with [napi-rs](https://napi-rs.com) and [VirusTotal/yara-x](https://github.com/VirusTotal/yara-x)
- Async Support: First-class support for asynchronous scanning
- WASM Compilation: Compile rules to WebAssembly for portable execution
- Zero Dependencies: No external runtime dependencies

## Usage

### Installation

```bash
npm install @litko/yara-x
```

### Basic Example

```javascript
import { compile } from "@litko/yara-x";

// Compile yara rules
const rules = compile(`
  rule test_rule {
    strings:
      $a = "hello world"
    condition:
      $a
  }
`);

// Scan a buffer
const buffer = Buffer.from("This is a test with hello world in it");
const matches = rules.scan(buffer);

// Process matches
if (matches.length > 0) {
  console.log(`Found ${matches.length} matching rules:`);
  matches.forEach((match) => {
    console.log(`- Rule: ${match.ruleIdentifier}`);
    match.matches.forEach((stringMatch) => {
      console.log(
        `  * Match at offset ${stringMatch.offset}: ${stringMatch.data}`,
      );
    });
  });
} else {
  console.log("No matches found");
}
```

## Scanning Files

```javascript
import { fromFile, compile } from "@litko/yara-x";
import { readFileSync } from "fs";

// Load rules from a file
const rules = fromFile("./rules/malware_rules.yar");

try {
  // Scan a file directly
  const matches = rules.scanFile("./samples/suspicious_file.exe");

  console.log(`Found ${matches.length} matching rules`);
} catch (error) {
  console.error(`Scanning error: ${error.message}`);
}
```

## Asynchronous Scanning

```javascript
import { compile } from "@litko/yara-x";

async function scanLargeFile() {
  const rules = compile(`rule large_file_rule {
      strings:
        $a = "sensitive data"
      condition:
        $a
    }
  `);

  try {
    // Scan a file asynchronously
    const matches = await rules.scanFileAsync("./samples/large_file.bin");
    console.log(`Found ${matches.length} matching rules`);
  } catch (error) {
    console.error(`Async scanning error: ${error.message}`);
  }
}

scanLargeFile();
```

## Variables

```javascript
import { compile } from "@litko/yara-x";

// Create a scanner with variables
const rules = compile(
  `
  rule variable_rule {
    condition:
      string_var contains "secret" and int_var > 10
  }
`,
  {
    defineVariables: {
      string_var: "this is a secret message",
      int_var: "20",
    },
  },
);

// Scan with default variables
let matches = rules.scan(Buffer.from("test data"));
console.log(`Matches with default variables: ${matches.length}`);

// Override variables at scan time
matches = rules.scan(Buffer.from("test data"), {
  string_var: "no secrets here",
  int_var: 5, // Note: variables at scan time can be numbers as well
});
console.log(`Matches with overridden variables: ${matches.length}`);
```

## WASM Compilation

```javascript
import { compile, compileToWasm } from "@litko/yara-x";

// Compile rules to WASM
const rule = `
  rule wasm_test {
    strings:
      $a = "compile to wasm"
    condition:
      $a
  }
`;

// Static compilation
compileToWasm(rule, "./output/rules.wasm");

// Or from a compiled rules instance
const compiledRules = compile(rule);
compiledRules.emitWasmFile("./output/instance_rules.wasm");

// Async compilation
await compiledRules.emitWasmFileAsync("./output/async_rules.wasm");
```

## Incremental Rule Building

```javascript
import { create } from "@litko/yara-x";

// Create an empty scanner
const scanner = create();

// Add rules incrementally
scanner.addRuleSource(`
  wrule first_rule {
    strings:
      $a = "first pattern"
    condition:
      $a
  }
`);

// Add rules from a file
scanner.addRuleFile("./rules/more_rules.yar");

// Add another rule
scanner.addRuleSource(`
  rule another_rule {
    strings:
      $a = "another pattern"
    condition:
      $a
  }
`);

// Now scan with all the rules
const matches = scanner.scan(Buffer.from("test data with first pattern"));
```

## Rule Validation

```javascript
import { validate } from "@litko/yara-x";

// Validate rules without executing them
const result = validate(`
  rule valid_rule {
    strings:
      $a = "valid"
    condition:
      $a
    }
`);

if (result.errors.length === 0) {
  console.log("Rules are valid!");
} else {
  console.error("Rule validation failed:");
  result.errors.forEach((error) => {
    console.error(`- ${error.code}: ${error.message}`);
  });
}
```

## Advanced Options

```javascript
import { compile } from "@litko/yara-x";

// Create a scanner with advanced options
const rules = compile(
  `
  rule advanced_rule {
    strings:
      $a = /hello[[:space:]]world/ // Using POSIX character class
    condition:
      $a and test_var > 10
  }
`,
  {
    // Define variables
    defineVariables: {
      test_var: "20",
    },

    // Enable relaxed regular expression syntax
    relaxedReSyntax: true,

    // Enable condition optimization
    conditionOptimization: true,

    // Ignore specific modules
    ignoreModules: ["pe"],

  :  // Error on potentially slow patterns
    errorOnSlowPattern: true,

    // Error on potentially slow loops
    errorOnSlowLoop: true,
  },
);
```

## Error Handling

### Compilation Errors

```javascript
import { compile } from "@litko/yara-x";

try {
  // This will throw an error due to invalid syntax
  const rules = compile(`
    rule invalid_rule {
      strings:
        $a = "unclosed string
      condition:
        $a
    }
  `);
} catch (error) {
  console.error(`Compilation error: ${error.message}`);
  // Output: Compilation error: error[E001]: syntax error
  //  --> line:3:28
  //   |
  // 3 |         $a = "unclosed string
  //   |                            ^ expecting `"`, found end of file
  // 278:  }
}
```

### Scanning errors

```javascript
import { compile } from "@litko/yara-x";

const rules = compile(`
  rule test_rule {
    condition:
      true
  }
`);

try {
  // This will throw if the file doesn't exist
  rules.scanFile("/path/to/nonexistent/file.bin");
} catch (error) {
  console.error(`Scanning error: ${error.message}`);
  // Output: Scanning error: Error reading file: No such file or directory (os error 2)
}
```

### Async Errors

```javascript
import { compile, compileToWasm } from "@litko/yara-x";

async function handleAsyncErrors() {
  const rules = compile(`
    rule test_rule {
      condition:
        true
    }
  `);

  try {
    await rules.scanFileAsync("/path/to/nonexistent/file.bin");
  } catch (error) {
    console.error(`Async scanning error: ${error.message}`);
  }

  try {
    await compileToWasm(
      "rule test { condition: true }",
      "/invalid/path/rules.wasm",
    );
  } catch (error) {
    console.error(`WASM compilation error: ${error.message}`);
  }
}

handleAsyncErrors();
```

## Compiler Warnings

```javascript
import { compile } from "@litko/yara-x";

// Create a scanner with a rule that generates warnings
const rules = compile(`
  rule warning_rule {
    strings:
      $a = "unused string"
    condition:
      true  // Warning: invariant expression
    }
`);

// Get and display warnings
const warnings = rules.getWarnings();
if (warnings.length > 0) {
  console.log("Compiler warnings:");
  warnings.forEach((warning) => {
    console.log(`- ${warning.code}: ${warning.message}`);
  });
}
```

## Performance Benchmarks

`node-yara-x` delivers exceptional performance through intelligent scanner caching and optimized Rust implementation.

### Benchmark Results

Test Environment: MacBook Pro M3 Max, 36GB RAM, Release build with LTO
Methodology: Statistical analysis across multiple iterations with percentile reporting

#### Scanner Creation Performance

| Rule Type      | Mean   | p50    | p95    | p99    |
| -------------- | ------ | ------ | ------ | ------ |
| Simple Rule    | 2.44ms | 2.42ms | 2.67ms | 3.00ms |
| Complex Rule   | 2.79ms | 2.78ms | 3.00ms | 3.26ms |
| Regex Rule     | 8.63ms | 8.63ms | 8.91ms | 9.34ms |
| Multiple Rules | 2.42ms | 2.39ms | 2.69ms | 3.07ms |

#### Scanning Performance by Data Size

| Data Size | Rule Type      | Mean  | Throughput |
| --------- | -------------- | ----- | ---------- |
| 64 bytes  | Simple         | 3μs   | ~21 MB/s   |
| 100KB     | Simple         | 6μs   | ~16.7 GB/s |
| 100KB     | Complex        | 71μs  | ~1.4 GB/s  |
| 100KB     | Regex          | 7μs   | ~14.3 GB/s |
| 100KB     | Multiple Rules | 71μs  | ~1.4 GB/s  |
| 10MB      | Simple         | 196μs | ~51 GB/s   |

#### Advanced Features Performance

| Feature           | Mean | Notes                      |
| ----------------- | ---- | -------------------------- |
| Variable Scanning | 1μs  | Pre-compiled variables     |
| Runtime Variables | 2μs  | Variables set at scan time |
| Async Scanning    | 12μs | Non-blocking operations    |

## API Reference

### Functions

- `compile(ruleSource: string, options?: CompilerOptions)` - Compiles yara rules from a string.
- `compileToWasm(ruleSource: string, outputPath: string, options?: CompilerOptions)` - Compiles yara rules from a string to WASM file.
- `compileFileToWasm(rulesPath: string, outputPath: string, options?: CompilerOptions)` - Compiles yara rules from a file to WASM file.
- `validate(ruleSource: string, options?: CompilerOptions)` - Validates yara rules without executing them.
- `create()` - Creates an empty rules scanner to add rules incrementally.
- `fromFile(rulePath: string, options?: CompilerOptions)` - Compiles yara rules from a file.

### yarax Methods

- `getWarnings()` - Get compiler warnings.
- `scan(data: Buffer, variables?: Record<string, string | number>)` - Scan a buffer.
- `scanFile(filePath: string, variables?: Record<string, string | number>)` - Scan a file.
- `scanAsync(data: Buffer, variables?: Record<string, object | undefined | null>)` - Scan a buffer asynchronously.
- `scanFileAsync(filePath: string, variables?: Record<string, object | undefined | null>)` - Scan a file asynchronously.
- `emitWasmFile(filePath: string)` - Emit compiled rules to WASM file synchronously.
- `emitWasmFileAsync(filePath: string)` - Emit compiled rules to WASM file asynchronously.
- `addRuleSource(rules: string)` - Add rules from a string to an existing scanner.
- `addRuleFile(filePath: string)` - Add rules from a file to an existing scanner.
- `defineVariable(name: string, value: string)` - Define a variable for the YARA compiler.

## Licenses

This project incorporates code under two distinct licenses:

- **MIT License:**
  - The node.js bindings and other code specific to this module are licensed under the MIT license.
  - See `LICENSE-MIT` for the full text.
- **BSD-3-Clause License:**
  - The included yara-x library is licensed under the BSD-3-Clause license.
  - See `LICENSE-BSD-3-Clause` for the full text.
