# node-yara-x

## Features

- High Performance: Built with napi-rs for maximum performance
- Async Support: First-class support for asynchronous scanning
- WASM Compilation: Compile rules to WebAssembly for portable execution
- Comprehensive API: Full access to YARA-X's powerful pattern matching capabilities
- Advanced Options: Fine-tune scanning with variables, compiler options, and more
- Zero Dependencies: No external runtime dependencies

## Installation

```bash
npm install node-yara-x
```

## Usage

### Basic Example

```javascript
import { YaraScanner } from "node-yara-x";

// Create a scanner with a YARA rule
const scanner = new YaraScanner(`
  rule test_rule {
    strings:
      $a = "hello world"
    condition:
      $a
  }
`);

// Scan a buffer
const buffer = Buffer.from("This is a test with hello world in it");
const matches = scanner.scan(buffer);

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
import { YaraScanner } from "node-yara-x";
import { readFileSync } from "fs";

// Load rules from a file
const scanner = YaraScanner.fromFile("./rules/malware_rules.yar");

try {
  // Scan a file directly
  const matches = scanner.scanFile("./samples/suspicious_file.exe");

  console.log(`Found ${matches.length} matching rules`);
} catch (error) {
  console.error(`Scanning error: ${error.message}`);
}
```

## Asynchronous Scanning

```javascript
import { YaraScanner } from "node-yara-x";

async function scanLargeFile() {
  const scanner = new YaraScanner(`     rule large_file_rule {
      strings:
        $a = "sensitive data"
      condition:
        $a
    }
  `);

  try {
    // Scan a file asynchronously
    const matches = await scanner.scanFileAsync("./samples/large_file.bin");
    console.log(`Found ${matches.length} matching rules`);
  } catch (error) {
    console.error(`Async scanning error: ${error.message}`);
  }
}

scanLargeFile();
```

## Variables

```javascript
import { YaraScanner } from "node-yara-x";

// Create a scanner with variables
const scanner = new YaraScanner(
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
let matches = scanner.scan(Buffer.from("test data"));
console.log(`Matches with default variables: ${matches.length}`);

// Override variables at scan time
matches = scanner.scan(Buffer.from("test data"), {
  string_var: "no secrets here",
  int_var: "5",
});
console.log(`Matches with overridden variables: ${matches.length}`);
```

## WASM Compilation

```javascript
import { YaraScanner } from "node-yara-x";

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
YaraScanner.compileToWasm(rule, "./output/rules.wasm");

// Or from an instance
const scanner = new YaraScanner(rule);
scanner.emitWasmFile("./output/instance_rules.wasm");

// Async compilation
await scanner.emitWasmFileAsync("./output/async_rules.wasm");
```

## Incremental Rule Building

```javascript
import { YaraScanner } from "node-yara-x";

// Create an empty scanner
const scanner = YaraScanner.createWithOptions();

// Add rules incrementally
scanner.addRuleSource(`
  rule first_rule {
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
import { validateYaraRules } from "node-yara-x";

// Validate rules without executing them
const result = validateYaraRules(`
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
import { YaraScanner } from "node-yara-x";

// Create a scanner with advanced options
const scanner = new YaraScanner(
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

    // Error on potentially slow patterns
    errorOnSlowPattern: true,

    // Error on potentially slow loops
    errorOnSlowLoop: true,
  },
);
```

## Error Handling

```javascript
import { YaraScanner } from "node-yara-x";

try {
  // This will throw an error due to invalid syntax
  const scanner = new YaraScanner(`
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
}
```

## Handling Scanning errors

```javascript
import { YaraScanner } from "node-yara-x";

const scanner = new YaraScanner(`
  rule test_rule {
    condition:
      true
  }
`);

try {
  // This will throw if the file doesn't exist
  scanner.scanFile("/path/to/nonexistent/file.bin");
} catch (error) {
  console.error(`Scanning error: ${error.message}`);
  // Output: Scanning error: Error reading file: No such file or directory (os error 2)
}
```

## Handling Async Errors

```javascript
import { YaraScanner } from "node-yara-x";

async function handleAsyncErrors() {
  const scanner = new YaraScanner(`
    rule test_rule {
      condition:
        true
    }
  `);

  try {
    await scanner.scanFileAsync("/path/to/nonexistent/file.bin");
  } catch (error) {
    console.error(`Async scanning error: ${error.message}`);
  }

  try {
    await scanner.emitWasmFileAsync("/invalid/path/rules.wasm");
  } catch (error) {
    console.error(`WASM compilation error: ${error.message}`);
  }
}

handleAsyncErrors();
```

## Compiler Warnings

```javascript
import { YaraScanner } from "node-yara-x";

// Create a scanner with a rule that generates warnings
const scanner = new YaraScanner(`
  rule warning_rule {
    strings:
      $a = "unused string"
    condition:
      true  // Warning: invariant expression
  }
`);

// Get and display warnings
const warnings = scanner.getWarnings();
if (warnings.length > 0) {
  console.log("Compiler warnings:");
  warnings.forEach((warning) => {
    console.log(`- ${warning.code}: ${warning.message}`);
  });
}
```

# Performance

On a MacBook Pro with an M3 Max / 36GB RAM

- Scanner creation: ~1.5ms
- Scanning small data (64 bytes): ~0.15ms
- Scanning medium data (100KB): ~0.15ms
- Scanning large data (10MB): ~0.34ms
- Complex rules with multiple conditions: ~0.22ms
- Regex pattern matching: ~0.16ms

# API Reference

## YaraScanner

### Constructor

- `new YaraScanner(rules: string, options?: ScannerOptions)` - Create a scanner with rules
- `YaraScanner.fromFile(filePath: string, options?: ScannerOptions)` - Create a scanner from a rule file
- `YaraScanner.createWithOptions(options?: ScannerOptions)` - Create an empty scanner with options

### Methods

- `scan(buffer: Buffer, variables?: Record<string, string>)` - Scan a buffer
- `scanFile(filePath: string, variables?: Record<string, string>)` - Scan a file
- `scanAsync(buffer: Buffer, variables?: Record<string, string>)` - Scan a buffer asynchronously
- `scanFileAsync(filePath: string, variables?: Record<string, string>)` - Scan a file asynchronously
- `addRuleSource(rules: string)` - Add rules from a string
- `addRuleFile(filePath: string)` - Add rules from a file
- `emitWasmFile(filePath: string)` - Compile rules to WASM
- `emitWasmFileAsync(filePath: string)` - Compile rules to WASM asynchronously
- `getWarnings()` - Get compiler warnings

### Static Methods

- `compileToWasm(rules: string, outputPath: string, options?: ScannerOptions)` - Compile rules to WASM
- `compileFileToWasm(rulesPath: string, outputPath: string, options?: ScannerOptions)` - Compile rule file to WASM

### validateYaraRules

- `validateYaraRules(rules: string, options?: ScannerOptions)` - Validate YARA rules without executing them

## Licenses

This project incorporates code under two distinct licenses:

- **MIT License:**
  - The node.js bindings and other code specific to this module are licensed under the MIT license.
  - See `LICENSE-MIT` for the full text.
- **BSD-3-Clause License:**
  - The included YARA-X library is licensed under the BSD-3-Clause license.
  - See `LICENSE-BSD-3-Clause` for the full text.
