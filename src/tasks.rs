//! Async task implementations for YARA-X operations.
//!
//! This module provides async task implementations for scanning and WASM compilation,
//! allowing these operations to run in background threads without blocking the Node.js event loop.

use crate::error::{io_error_to_napi, scan_error_to_napi};
use crate::scanner::YaraX;
use crate::types::{RuleMatch, VariableMap};
use crate::variables::VariableHandler;
use napi::{Env, Error, Result, Status, Task};
use std::sync::Arc;
use yara_x::{Rules, Scanner};

/// Base task for YARA scanning operations.
///
/// This struct contains the common functionality shared by both
/// data scanning and file scanning tasks.
pub struct BaseYaraTask {
  rules: Arc<Rules>,
  variables: Option<VariableMap>,
}

impl BaseYaraTask {
  /// Creates a new base YARA task.
  ///
  /// # Arguments
  ///
  /// * `rules` - The compiled YARA rules
  /// * `variables` - Optional variables to apply during scanning
  pub fn new(rules: Arc<Rules>, variables: Option<VariableMap>) -> Self {
    Self { rules, variables }
  }

  /// Creates a new scanner with the compiled YARA rules and applies any defined variables.
  ///
  /// # Returns
  ///
  /// A configured scanner ready to scan data
  fn create_scanner(&self) -> Result<Scanner<'_>> {
    let mut scanner = Scanner::new(&self.rules);
    scanner.apply_variables_from_map(&self.variables)?;
    Ok(scanner)
  }

  /// Processes the scan results and returns a vector of RuleMatch.
  ///
  /// # Arguments
  ///
  /// * `env` - The N-API environment
  /// * `data` - The scanned data
  ///
  /// # Returns
  ///
  /// A vector of matching rules
  pub fn process_results<'a>(&self, env: Env, data: &[u8]) -> Result<Vec<RuleMatch<'a>>> {
    let mut scanner = self.create_scanner()?;
    let results = scanner.scan(data).map_err(scan_error_to_napi)?;
    YaraX::process_scan_results(results, data, env)
  }
}

/// Task for scanning data with YARA rules.
///
/// This task scans in-memory data asynchronously.
pub struct ScanTask {
  base: BaseYaraTask,
  data: Vec<u8>,
}

impl ScanTask {
  /// Creates a new scan task.
  ///
  /// # Arguments
  ///
  /// * `rules` - The compiled YARA rules
  /// * `data` - The data to scan
  /// * `variables` - Optional variables to apply during scanning
  pub fn new(rules: Arc<Rules>, data: Vec<u8>, variables: Option<VariableMap>) -> Self {
    Self {
      base: BaseYaraTask::new(rules, variables),
      data,
    }
  }
}

impl Task for ScanTask {
  type Output = Vec<u8>;
  type JsValue = Vec<RuleMatch<'static>>;

  fn compute(&mut self) -> Result<Self::Output> {
    Ok(std::mem::take(&mut self.data))
  }

  fn resolve(&mut self, env: napi::Env, data: Self::Output) -> Result<Self::JsValue> {
    self.base.process_results(env, &data)
  }
}

/// Task for scanning a file with YARA rules.
///
/// This task reads and scans a file asynchronously.
pub struct ScanFileTask {
  base: BaseYaraTask,
  file_path: String,
}

impl ScanFileTask {
  /// Creates a new file scan task.
  ///
  /// # Arguments
  ///
  /// * `rules` - The compiled YARA rules
  /// * `file_path` - Path to the file to scan
  /// * `variables` - Optional variables to apply during scanning
  pub fn new(rules: Arc<Rules>, file_path: String, variables: Option<VariableMap>) -> Self {
    Self {
      base: BaseYaraTask::new(rules, variables),
      file_path,
    }
  }
}

impl Task for ScanFileTask {
  type Output = Vec<u8>;
  type JsValue = Vec<RuleMatch<'static>>;

  fn compute(&mut self) -> Result<Self::Output> {
    std::fs::read(&self.file_path)
      .map_err(|e| io_error_to_napi(e, &format!("reading file {}", self.file_path)))
  }

  fn resolve(&mut self, env: napi::Env, data: Self::Output) -> Result<Self::JsValue> {
    self.base.process_results(env, &data)
  }
}

/// Task for emitting a WASM file from YARA rules.
///
/// This task compiles YARA rules to WebAssembly asynchronously.
pub struct EmitWasmFileTask {
  pub source_code: Option<String>,
  pub output_path: String,
}

impl Task for EmitWasmFileTask {
  type Output = ();
  type JsValue = ();

  fn compute(&mut self) -> Result<Self::Output> {
    let source = self.source_code.as_ref().ok_or_else(|| {
      Error::new(
        Status::InvalidArg,
        "Cannot emit WASM file: source code not available",
      )
    })?;

    crate::compiler::compile_source_to_wasm(source, &self.output_path, None)?;
    Ok(())
  }

  fn resolve(&mut self, _env: napi::Env, _output: Self::Output) -> Result<Self::JsValue> {
    Ok(())
  }
}
