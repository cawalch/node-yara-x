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
mod batch;
mod binary;
mod compiler;
mod error;
mod scanner;
mod tasks;
mod types;
mod variables;

// Re-export public types
pub use batch::{BatchFileError, BatchFileMatch, BatchScanOptions, BatchScanResult};
pub use binary::{BinaryMatchView, BinaryScanCatalog, BinaryScanResult, RuleInfo};
pub use scanner::YaraX;
pub use types::{
  BannedModule, CompileResult, CompilerError, CompilerOptions, CompilerWarning, IgnoredRule,
  MatchData, RuleMatch,
};

// Internal imports
use compiler::{add_source_to_compiler, apply_compiler_options, ignored_module_warnings};
use error::io_error_to_napi;
use napi::bindgen_prelude::Buffer;
use napi::{Error, Result, Status};
use napi_derive::napi;
use std::sync::Arc;
use variables::{get_compiler_errors, get_compiler_warnings};
use yara_x::Compiler;

/// Magic header prepended to YARA-X serialized blobs.
const RULES_MAGIC: &[u8; 8] = b"YARA-X\0\0";

/// Version and build information for serialized rule blobs.
#[napi(object)]
pub struct RulesFormatInfo {
  /// Binary format version written into `serialize()` output.
  pub format_version: u32,
  /// YARA-X version this build links against.
  pub yara_x_version: String,
  /// `@litko/yara-x` package version.
  pub package_version: String,
}

/// Returns the serialized-rule format version and the versions that produce it.
///
/// Blob caches can key on `formatVersion`: blobs are only interchangeable
/// between builds that report the same value.
#[napi]
pub fn rules_format_info() -> Result<RulesFormatInfo> {
  Ok(RulesFormatInfo {
    format_version: rules_format_version()?,
    yara_x_version: yara_x::VERSION.to_string(),
    package_version: env!("NODE_YARA_X_VERSION").to_string(),
  })
}

/// Reads the format version that the linked YARA-X writes into blobs.
///
/// The constant is private upstream, so derive it once by serializing empty
/// rules and reading the header.
fn rules_format_version() -> Result<u32> {
  static FORMAT_VERSION: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

  if let Some(version) = FORMAT_VERSION.get() {
    return Ok(*version);
  }

  let bytes = Compiler::new().build().serialize().map_err(|e| {
    Error::new(
      Status::GenericFailure,
      format!("Failed to determine the serialized rules format version: {e}"),
    )
  })?;

  let version = bytes
    .get(RULES_MAGIC.len()..RULES_MAGIC.len() + 4)
    .and_then(|bytes| bytes.try_into().ok())
    .map(u32::from_le_bytes)
    .ok_or_else(|| {
      Error::new(
        Status::GenericFailure,
        "Serialized rules header is shorter than expected",
      )
    })?;

  let _ = FORMAT_VERSION.set(version);
  Ok(*FORMAT_VERSION.get().unwrap_or(&version))
}

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
/// A `CompileResult` containing any warnings and errors
#[napi]
pub fn validate(
  rule_source: String,
  options: Option<types::CompilerOptions>,
) -> Result<CompileResult> {
  let mut compiler = Compiler::new();

  apply_compiler_options(&mut compiler, options.as_ref(), false)?;
  let namespace = options.as_ref().and_then(|opts| opts.namespace.as_deref());

  let _ = add_source_to_compiler(&mut compiler, &rule_source, namespace, None);

  let mut warnings = get_compiler_warnings(&compiler);
  warnings.extend(ignored_module_warnings(&compiler::stored_options_from(
    options.as_ref(),
  )));
  let errors = get_compiler_errors(&compiler);

  Ok(CompileResult { warnings, errors })
}

/// Compiles a YARA rule source string and returns a `YaraX` instance with the compiled rules.
///
/// # Arguments
///
/// * `rule_source` - The YARA rule source code
/// * `options` - Optional compiler options
///
/// # Returns
///
/// A `YaraX` instance with compiled rules
#[napi]
pub fn compile(
  rule_source: String,
  options: Option<types::CompilerOptions>,
) -> Result<scanner::YaraX> {
  let yarax = scanner::YaraX::create_scanner_from_source(rule_source, options, None)?;
  Ok(yarax)
}

/// Creates a new `YaraX` instance with empty rules and no source code.
///
/// # Returns
///
/// A new `YaraX` instance with empty rules
#[napi]
pub fn create() -> scanner::YaraX {
  scanner::YaraX::new_empty(Arc::new(Compiler::new().build()), Some(String::new()))
}

/// Creates a new `YaraX` instance from a file containing YARA rules.
///
/// # Arguments
///
/// * `rule_path` - Path to the file containing YARA rules
/// * `options` - Optional compiler options
///
/// # Returns
///
/// A `YaraX` instance with compiled rules from the file
#[napi]
pub fn from_file(
  rule_path: String,
  options: Option<types::CompilerOptions>,
) -> Result<scanner::YaraX> {
  let file_content = std::fs::read_to_string(&rule_path)
    .map_err(|e| io_error_to_napi(e, &format!("reading file {rule_path}")))?;

  scanner::YaraX::create_scanner_from_source(file_content, options, Some(&rule_path))
}

/// Creates a new `YaraX` instance from a serialized rules blob.
///
/// The blob must have been produced by [`YaraX::serialize`] (or
/// `yara_x::Rules::serialize`) using the same YARA-X version. The rules are
/// restored with full scanning capability (including WASM condition
/// recompilation for the current platform) and can be used with `scan`,
/// `scan_file`, `scan_async`, and `scan_file_async`.
///
/// # Arguments
///
/// * `data` - Buffer containing the serialized rules
///
/// # Returns
///
/// A `YaraX` instance with the restored rules
#[napi]
pub fn deserialize(data: Buffer) -> Result<scanner::YaraX> {
  use yara_x::Rules;

  let bytes = data.as_ref();
  if bytes.len() < RULES_MAGIC.len() || &bytes[..RULES_MAGIC.len()] != RULES_MAGIC {
    return Err(Error::new(
      Status::InvalidArg,
      "Failed to deserialize rules: not a YARA-X compiled rules file (missing the YARA-X header)"
        .to_string(),
    ));
  }

  let rules = Rules::deserialize(bytes).map_err(|e| {
    let message = match &e {
      yara_x::errors::SerializationError::InvalidVersion { expected, actual } => format!(
        "Failed to deserialize rules: blob format version {actual} is not supported by this build (expects {expected}). This package is @litko/yara-x {} linked against YARA-X {}. Recompile the rules with the current version.",
        env!("NODE_YARA_X_VERSION"),
        yara_x::VERSION,
      ),
      _ => format!("Failed to deserialize rules: {e}"),
    };

    Error::new(Status::InvalidArg, message)
  })?;

  Ok(scanner::YaraX::new_empty(Arc::new(rules), None))
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
  options: Option<types::CompilerOptions>,
) -> Result<()> {
  compiler::compile_source_to_wasm(&rule_source, &output_path, options.as_ref(), None)
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
  options: Option<types::CompilerOptions>,
) -> Result<()> {
  let file_content = std::fs::read_to_string(&rule_path)
    .map_err(|e| io_error_to_napi(e, &format!("reading file {rule_path}")))?;
  compiler::compile_source_to_wasm(
    &file_content,
    &output_path,
    options.as_ref(),
    Some(&rule_path),
  )
}
