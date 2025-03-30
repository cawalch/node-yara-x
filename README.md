# @litko/yara-x

**v0.1.0**

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
import { validate } from "yara-x";

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
import { compile } from "yara-x";

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
import { compile } from "yara-x";

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
import { compile } from "yara-x";

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
import { compile, compileToWasm } from "yara-x";

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
import { compile } from "yara-x";

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

**Test Setup:**

- **Hardware:** MacBook Pro (M3 Max, 36GB RAM)
- **Test Data:** Generated data of varying sizes (small: 64 bytes, medium: 100KB, large: 10MB). See `__test__/benchmark.mjs` for data generation and benchmarking code.
- The Large test file (10MB) is auto-generated, to prevent bloating the size of the repository.

**Key Metrics (Averages):**

| Operation                                       | Average Time | Iterations |      p50 |      p95 |      p99 |
| :---------------------------------------------- | -----------: | ---------: | -------: | -------: | -------: |
| Scanner Creation (Simple Rule)                  |     1.675 ms |        100 | 1.547 ms | 2.318 ms | 2.657 ms |
| Scanner Creation (Complex Rule)                 |     1.878 ms |        100 | 1.848 ms | 2.005 ms | 2.865 ms |
| Scanner Creation (Regex Rule)                   |     2.447 ms |        100 | 2.444 ms | 2.473 ms | 2.569 ms |
| Scanner Creation (Multiple Rules)               |     1.497 ms |        100 | 1.488 ms | 1.547 ms | 1.819 ms |
| Scanning Small Data (64 bytes, Simple Rule)     |     0.145 ms |       1000 | 0.143 ms | 0.156 ms | 0.169 ms |
| Scanning Medium Data (100KB, Simple Rule)       |     0.151 ms |        100 | 0.146 ms | 0.179 ms | 0.205 ms |
| Scanning Large Data (10MB, Simple Rule)         |     0.347 ms |         10 | 0.340 ms | 0.394 ms | 0.394 ms |
| Scanning Medium Data (100KB, Complex Rule)      |     0.219 ms |        100 | 0.215 ms | 0.254 ms | 0.269 ms |
| Scanning Medium Data (100KB, Regex Rule)        |     0.156 ms |        100 | 0.152 ms | 0.182 ms | 0.210 ms |
| Scanning Medium Data (100KB, Multiple Rules)    |     0.218 ms |        100 | 0.212 ms | 0.261 ms | 0.353 ms |
| Async Scanning Medium Data (100KB, Simple Rule) |     0.012 ms |        100 | 0.011 ms | 0.016 ms |  0.027ms |
| Scanning with Variables                         |     0.143 ms |       1000 | 0.140 ms | 0.155 ms | 0.166 ms |
| Scanning with Variables (Override at Scan Time) |     0.144 ms |       1000 | 0.142 ms | 0.158 ms | 0.175 ms |

# API Reference

### Functions

- `compile(ruleSource: string, options?: CompilerOptions)` - Compiles yara rules from a string.
- `compileToWasm(ruleSource: string, outputPath: string, options?: CompilerOptions)` - Compiles yara rules from a string to WASM file.
- `compileFileToWasm(rulesPath: string, outputPath: string, options?: CompilerOptions)` - Compiles yara rules from a file to WASM file.
- `validate(ruleSource: string, options?: CompilerOptions)` - Validates yara rules without executing them.
- `create(options?: CompilerOptions)` - Creates an empty rules scanner to add rules incrementally.
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

### Rule Validation

- `validate(rules: string, options?: CompilerOptions)` - Validate yara rules without executing them.

## Licenses

This project incorporates code under two distinct licenses:

- **MIT License:**
  - The node.js bindings and other code specific to this module are licensed under the MIT license.
  - See `LICENSE-MIT` for the full text.
- **BSD-3-Clause License:**
  - The included yara-x library is licensed under the BSD-3-Clause license.
  - See `LICENSE-BSD-3-Clause` for the full text.
