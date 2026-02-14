//! Async task implementations for YARA-X operations.
//!
//! This module provides async task implementations for scanning and WASM compilation,
//! allowing these operations to run in background threads without blocking the Node.js event loop.
//!
//! Scanning is performed in `compute()` (worker thread) using thread-safe `RuleMatchData`,
//! then converted to N-API `RuleMatch` objects in `resolve()` (main thread).

use crate::error::{io_error_to_napi, scan_error_to_napi};
use crate::scanner::YaraX;
use crate::types::{RuleMatch, RuleMatchData, VariableMap};
use crate::variables::VariableHandler;
use napi::{Error, Result, Status, Task};
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
  pub fn new(rules: Arc<Rules>, variables: Option<VariableMap>) -> Self {
    Self { rules, variables }
  }

  /// Creates a new scanner with the compiled YARA rules and applies any defined variables.
  fn create_scanner(&self) -> Result<Scanner<'_>> {
    let mut scanner = Scanner::new(&self.rules);
    scanner.apply_variables_from_map(&self.variables)?;
    Ok(scanner)
  }

  /// Scans data on the current thread and returns thread-safe results.
  ///
  /// This is designed to be called from `compute()` (worker thread).
  pub fn scan_to_data(&self, data: &[u8]) -> Result<Vec<RuleMatchData>> {
    let mut scanner = self.create_scanner()?;
    let results = scanner.scan(data).map_err(scan_error_to_napi)?;
    Ok(YaraX::extract_scan_data(results, data))
  }
}

/// Task for scanning data with YARA rules.
///
/// Scanning runs on the worker thread in `compute()`.
pub struct ScanTask {
  base: BaseYaraTask,
  data: Vec<u8>,
}

impl ScanTask {
  /// Creates a new scan task.
  pub fn new(rules: Arc<Rules>, data: Vec<u8>, variables: Option<VariableMap>) -> Self {
    Self {
      base: BaseYaraTask::new(rules, variables),
      data,
    }
  }
}

impl Task for ScanTask {
  type Output = Vec<RuleMatchData>;
  type JsValue = Vec<RuleMatch<'static>>;

  fn compute(&mut self) -> Result<Self::Output> {
    let data = std::mem::take(&mut self.data);
    self.base.scan_to_data(&data)
  }

  fn resolve(&mut self, env: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    YaraX::convert_to_rule_matches(env, output)
  }
}

/// Task for scanning a file with YARA rules.
///
/// File I/O and scanning both run on the worker thread in `compute()`.
pub struct ScanFileTask {
  base: BaseYaraTask,
  file_path: String,
}

impl ScanFileTask {
  /// Creates a new file scan task.
  pub fn new(rules: Arc<Rules>, file_path: String, variables: Option<VariableMap>) -> Self {
    Self {
      base: BaseYaraTask::new(rules, variables),
      file_path,
    }
  }
}

impl Task for ScanFileTask {
  type Output = Vec<RuleMatchData>;
  type JsValue = Vec<RuleMatch<'static>>;

  fn compute(&mut self) -> Result<Self::Output> {
    let data = std::fs::read(&self.file_path)
      .map_err(|e| io_error_to_napi(e, &format!("reading file {}", self.file_path)))?;
    self.base.scan_to_data(&data)
  }

  fn resolve(&mut self, env: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    YaraX::convert_to_rule_matches(env, output)
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
