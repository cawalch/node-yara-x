//! Async task implementations for YARA-X operations.
//!
//! This module provides async task implementations for scanning and WASM compilation,
//! allowing these operations to run in background threads without blocking the Node.js event loop.
//!
//! Scanning is performed in `compute()` (worker thread) using thread-safe `RuleMatchData`,
//! then converted to N-API `RuleMatch` objects in `resolve()` (main thread).

use crate::cancel::CancelState;
use crate::compiler::{replay_sources_to_wasm, StoredCompilerOptions};
use crate::error::{scan_error_to_napi, stamped_abort};
use crate::scanner::YaraX;
use crate::types::{RuleMatch, RuleMatchData, RuleSource, VariableMap};
use crate::variables::VariableHandler;
use napi::{Env, Error, Result, Status, Task};
use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;
use yara_x::{Rules, Scanner};

/// Options passed to background scanning tasks.
#[derive(Default, Clone, PartialEq)]
pub struct TaskScanOptions {
  pub max_matches_per_pattern: Option<usize>,
  pub fast_scan: Option<bool>,
  pub use_mmap: Option<bool>,
  pub timeout_ms: Option<u32>,
  pub match_context_size: Option<usize>,
  pub max_scan_size: Option<usize>,
}

#[derive(Clone, PartialEq)]
struct WorkerScannerOptions {
  options: TaskScanOptions,
  variables: Option<VariableMap>,
}

impl WorkerScannerOptions {
  fn matches(&self, task: &BaseYaraTask) -> bool {
    self.options == task.options && self.variables == task.variables
  }
}

struct CachedWorkerScanner {
  // `scanner` must be declared before `rules`: fields drop in declaration
  // order, and the scanner borrows the rules allocation.
  scanner: Scanner<'static>,
  rules: Arc<Rules>,
  options: WorkerScannerOptions,
}

thread_local! {
  static WORKER_SCANNER: RefCell<Option<CachedWorkerScanner>> = const { RefCell::new(None) };
}

/// Base task for YARA scanning operations.
///
/// This struct contains the common functionality shared by both
/// data scanning and file scanning tasks.
pub struct BaseYaraTask {
  rules: Arc<Rules>,
  variables: Option<VariableMap>,
  options: TaskScanOptions,
}

impl BaseYaraTask {
  /// Creates a new base YARA task.
  pub fn new(rules: Arc<Rules>, variables: Option<VariableMap>, options: TaskScanOptions) -> Self {
    Self {
      rules,
      variables,
      options,
    }
  }

  /// Executes a scan operation with a thread-local cached scanner.
  ///
  /// Reuses the existing scanner on this worker thread if the rules pointer
  /// (`Arc::ptr_eq`) and scan options match. If rules or options differ, a new
  /// scanner is instantiated and cached.
  pub(crate) fn with_scanner<F, R>(&self, f: F) -> Result<R>
  where
    F: FnOnce(&mut Scanner<'_>) -> Result<R>,
  {
    WORKER_SCANNER.with(|cell| {
      let mut cache = cell.borrow_mut();

      let is_match = match cache.as_ref() {
        Some(cached) => Arc::ptr_eq(&cached.rules, &self.rules) && cached.options.matches(self),
        None => false,
      };

      if !is_match {
        let rules_clone = Arc::clone(&self.rules);
        // SAFETY: `CachedWorkerScanner` owns `rules_clone` and declares
        // `scanner` first, so the `Arc` outlives the borrow it backs.
        let rules_ref: &'static Rules =
          unsafe { std::mem::transmute::<&Rules, &'static Rules>(&*rules_clone) };

        let mut scanner = Scanner::new(rules_ref);
        if let Some(max_matches) = self.options.max_matches_per_pattern {
          scanner.max_matches_per_pattern(max_matches);
        }
        if let Some(fast_scan) = self.options.fast_scan {
          scanner.fast_scan(fast_scan);
        }
        if let Some(use_mmap) = self.options.use_mmap {
          scanner.use_mmap(use_mmap);
        }
        if let Some(timeout_ms) = self.options.timeout_ms {
          scanner.set_timeout(Duration::from_millis(timeout_ms as u64));
        }
        if let Some(match_context_size) = self.options.match_context_size {
          scanner.match_context_size(match_context_size);
        }
        if let Some(max_scan_size) = self.options.max_scan_size {
          scanner.max_scan_size(max_scan_size);
        }
        scanner.apply_variables_from_map(&self.variables)?;

        *cache = Some(CachedWorkerScanner {
          scanner,
          rules: rules_clone,
          options: WorkerScannerOptions {
            options: self.options.clone(),
            variables: self.variables.clone(),
          },
        });
      }

      let cached = cache.as_mut().unwrap();
      let res = f(&mut cached.scanner);
      if res.is_err() {
        // Discard scanner on scan error (e.g. timeout) to avoid reusing corrupted state
        *cache = None;
      }
      res
    })
  }

  /// Scans data on the current thread and returns thread-safe results.
  ///
  /// This is designed to be called from `compute()` (worker thread).
  pub fn scan_to_data(&self, data: &[u8]) -> Result<Vec<RuleMatchData>> {
    self.with_scanner(|scanner| {
      let results = scanner
        .scan(data)
        .map_err(|e| scan_error_to_napi(e, None))?;
      Ok(YaraX::extract_scan_data(results))
    })
  }

  /// Scans data on the current thread and returns whether any rule matched.
  ///
  /// This is designed to be called from `compute()` (worker thread).
  pub fn is_match(&self, data: &[u8]) -> Result<bool> {
    self.with_scanner(|scanner| {
      let results = scanner
        .scan(data)
        .map_err(|e| scan_error_to_napi(e, None))?;
      Ok(results.matching_rules().next().is_some())
    })
  }

  /// Scans a file on the current thread and returns thread-safe results.
  pub fn scan_file_to_data(&self, file_path: &str) -> Result<Vec<RuleMatchData>> {
    self.with_scanner(|scanner| {
      let results = scanner
        .scan_file(file_path)
        .map_err(|e| scan_error_to_napi(e, None))?;
      Ok(YaraX::extract_scan_data(results))
    })
  }

  /// Scans a file on the current thread and returns whether any rule matched.
  pub fn is_file_match(&self, file_path: &str) -> Result<bool> {
    self.with_scanner(|scanner| {
      let results = scanner
        .scan_file(file_path)
        .map_err(|e| scan_error_to_napi(e, None))?;
      Ok(results.matching_rules().next().is_some())
    })
  }
}

/// Target of an asynchronous scan operation (in-memory buffer or file on disk).
///
/// Buffers are owned by the task: the bytes are copied at dispatch time so the
/// worker never reads memory the caller can still mutate.
pub enum ScanTarget {
  Buffer(Vec<u8>),
  File(String),
}

impl ScanTarget {
  fn scan_to_data(&self, base: &BaseYaraTask) -> Result<Vec<RuleMatchData>> {
    match self {
      Self::Buffer(buf) => base.scan_to_data(buf.as_ref()),
      Self::File(path) => base.scan_file_to_data(path),
    }
  }

  fn is_match(&self, base: &BaseYaraTask) -> Result<bool> {
    match self {
      Self::Buffer(buf) => base.is_match(buf.as_ref()),
      Self::File(path) => base.is_file_match(path),
    }
  }
}

/// Task for scanning data or a file with YARA rules asynchronously.
///
/// Scanning runs on the worker thread in `compute()`.
pub struct ScanTask {
  base: BaseYaraTask,
  target: ScanTarget,
  cancel: CancelState,
}

impl ScanTask {
  /// Creates a new scan task.
  pub fn new(
    rules: Arc<Rules>,
    target: ScanTarget,
    variables: Option<VariableMap>,
    options: TaskScanOptions,
    cancel: CancelState,
  ) -> Self {
    Self {
      base: BaseYaraTask::new(rules, variables, options),
      target,
      cancel,
    }
  }
}

impl Task for ScanTask {
  type Output = Vec<RuleMatchData>;
  type JsValue = Vec<RuleMatch<'static>>;

  fn compute(&mut self) -> Result<Self::Output> {
    self.cancel.reject_if_cancelled()?;
    self.target.scan_to_data(&self.base)
  }

  fn reject(&mut self, env: Env, err: Error) -> Result<Self::JsValue> {
    Err(stamped_abort(&env, err))
  }

  fn resolve(&mut self, env: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    YaraX::convert_to_rule_matches(env, output)
  }

  fn finally(mut self, env: Env) -> Result<()> {
    self.cancel.release(&env);
    Ok(())
  }
}

/// Task for checking whether data or a file matches any rule asynchronously.
///
/// Scanning runs on the worker thread in `compute()`.
pub struct IsMatchTask {
  base: BaseYaraTask,
  target: ScanTarget,
  cancel: CancelState,
}

impl IsMatchTask {
  /// Creates a new boolean match task.
  pub fn new(
    rules: Arc<Rules>,
    target: ScanTarget,
    variables: Option<VariableMap>,
    options: TaskScanOptions,
    cancel: CancelState,
  ) -> Self {
    Self {
      base: BaseYaraTask::new(rules, variables, options),
      target,
      cancel,
    }
  }
}

impl Task for IsMatchTask {
  type Output = bool;
  type JsValue = bool;

  fn compute(&mut self) -> Result<Self::Output> {
    self.cancel.reject_if_cancelled()?;
    self.target.is_match(&self.base)
  }

  fn reject(&mut self, env: Env, err: Error) -> Result<Self::JsValue> {
    Err(stamped_abort(&env, err))
  }

  fn resolve(&mut self, _env: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }

  fn finally(mut self, env: Env) -> Result<()> {
    self.cancel.release(&env);
    Ok(())
  }
}

/// Task for emitting a WASM file from YARA rules.
///
/// This task compiles YARA rules to WebAssembly asynchronously.
pub struct EmitWasmFileTask {
  pub source_code: Option<String>,
  pub rule_sources: Vec<RuleSource>,
  /// Origin paths matching `rule_sources`, used for diagnostics and includes.
  pub source_origins: Vec<Option<String>>,
  pub output_path: String,
  /// The scanner's stored compiler options, replayed so the emitted module
  /// matches the scanner's compilation semantics.
  pub stored_options: StoredCompilerOptions,
  /// The scanner's stored global variables, applied before the sources.
  pub variables: Option<VariableMap>,
  /// Whether per-rule compilation errors are tolerated (skipped rules).
  pub ignore_invalid_rules: bool,
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

    let fallback_source;
    let fallback_origin;
    let (sources, origins): (&[RuleSource], &[Option<String>]) = if self.rule_sources.is_empty() {
      fallback_source = [RuleSource {
        source: source.clone(),
        namespace: None,
      }];
      fallback_origin = [None];
      (&fallback_source[..], &fallback_origin[..])
    } else {
      (&self.rule_sources[..], &self.source_origins[..])
    };

    replay_sources_to_wasm(
      sources,
      origins,
      &self.output_path,
      &self.stored_options,
      self.variables.as_ref(),
      self.ignore_invalid_rules,
    )?;
    Ok(())
  }

  fn resolve(&mut self, _env: napi::Env, _output: Self::Output) -> Result<Self::JsValue> {
    Ok(())
  }
}
