/*! YARA-X bindings for Node.js using napi-rs

This library provides bindings for YARA-X, a powerful tool for malware research and detection.
It allows you to compile and scan YARA rules from Node.js using the napi-rs framework.

There are two main ways to use this library:

1. Compile and scan synchronously using the `compile` and `scan` functions.
2. Compile and scan asynchronously using the `scan_async` and `scan_file_async` functions.

# Usage

```javascript
const { compile, scan } = require('yara-x');
const { Buffer } = require('buffer');

// Compile YARA rules

const rules = compile('rule example { strings: $a = "example" condition: $a }');
console.log('Compiled rules:', rules);

// Scan data with compiled rules

const data = Buffer.from('This is an example data to scan.');
const matches = scan(rules, data);

console.log('Matches:', matches);

*/
#![deny(clippy::all)]

// Module declarations
mod compiler;
mod error;
mod scanner;
mod tasks;
mod types;
mod variables;

// Re-export public types
pub use scanner::YaraX;
pub use types::{
  BannedModule, CompileResult, CompilerError, CompilerOptions, CompilerWarning, MatchData,
  RuleMatch, ScanOptions,
};

// Internal imports
use compiler::apply_compiler_options;
use error::io_error_to_napi;
use napi::Result;
use napi_derive::napi;
use scanner::YaraX as YaraXImpl;
use std::path::Path;
use types::CompilerOptions as CompilerOptionsType;
use variables::{get_compiler_errors, get_compiler_warnings};
use yara_x::Compiler;

/// Compiles a YARA rule source string and returns any warnings or errors generated during the
/// compilation process.
///
/// This function validates YARA rules without creating a scanner instance.
///
/// # Arguments
///
/// * `rule_source` - The YARA rule source code
/// * `options` - Optional compiler options
///
/// # Returns
///
/// A CompileResult containing any warnings and errors
#[napi]
pub fn validate(
  rule_source: String,
  options: Option<CompilerOptionsType>,
) -> Result<CompileResult> {
  let mut compiler = Compiler::new();

  apply_compiler_options(&mut compiler, options.as_ref(), false)?;

  let _ = compiler.add_source(rule_source.as_str());

  let warnings = get_compiler_warnings(&compiler)?;
  let errors = get_compiler_errors(&compiler)?;

  Ok(CompileResult { warnings, errors })
}

/// Compiles a YARA rule source string and returns a YaraX instance with the compiled rules.
///
/// # Arguments
///
/// * `rule_source` - The YARA rule source code
/// * `options` - Optional compiler options
///
/// # Returns
///
/// A YaraX instance with compiled rules
#[napi]
pub fn compile(rule_source: String, options: Option<CompilerOptionsType>) -> Result<YaraXImpl> {
  let yarax = YaraXImpl::create_scanner_from_source(rule_source, options)?;
  Ok(yarax)
}

/// Creates a new YaraX instance with empty rules and no source code.
///
/// # Returns
///
/// A new YaraX instance with empty rules
#[napi]
pub fn create() -> YaraXImpl {
  use std::cell::RefCell;
  use std::sync::Arc;

  YaraXImpl {
    rules: Arc::new(Compiler::new().build()),
    source_code: Some(String::new()),
    warnings: Vec::new(),
    variables: None,
    cached_scanner: RefCell::new(None),
    max_matches_per_pattern: None,
    use_mmap: None,
  }
}

/// Creates a new YaraX instance from a file containing YARA rules.
///
/// # Arguments
///
/// * `rule_path` - Path to the file containing YARA rules
/// * `options` - Optional compiler options
///
/// # Returns
///
/// A YaraX instance with compiled rules from the file
#[napi]
pub fn from_file(rule_path: String, options: Option<CompilerOptionsType>) -> Result<YaraXImpl> {
  let file_content = std::fs::read_to_string(Path::new(&rule_path))
    .map_err(|e| io_error_to_napi(e, &format!("reading file {rule_path}")))?;

  YaraXImpl::create_scanner_from_source(file_content, options)
}

/// Compiles a YARA rule source string to a WASM file.
///
/// # Arguments
///
/// * `rule_source` - The YARA rule source code
/// * `output_path` - Path where the WASM file should be written
/// * `options` - Optional compiler options
///
/// # Returns
///
/// Ok(()) on success, or an error if compilation or emission fails
#[napi]
pub fn compile_to_wasm(
  rule_source: String,
  output_path: String,
  options: Option<CompilerOptionsType>,
) -> Result<()> {
  compiler::compile_source_to_wasm(&rule_source, &output_path, options.as_ref())
}

/// Compiles a YARA rule file to a WASM file.
///
/// # Arguments
///
/// * `rule_path` - Path to the file containing YARA rules
/// * `output_path` - Path where the WASM file should be written
/// * `options` - Optional compiler options
///
/// # Returns
///
/// Ok(()) on success, or an error if reading, compilation, or emission fails
#[napi]
pub fn compile_file_to_wasm(
  rule_path: String,
  output_path: String,
  options: Option<CompilerOptionsType>,
) -> Result<()> {
  let file_content = std::fs::read_to_string(Path::new(&rule_path))
    .map_err(|e| io_error_to_napi(e, &format!("reading file {rule_path}")))?;
  compiler::compile_source_to_wasm(&file_content, &output_path, options.as_ref())
}
