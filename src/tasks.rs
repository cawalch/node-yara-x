//! Async task implementations for YARA-X operations.
//!
//! This module provides async task implementations for scanning and WASM compilation,
//! allowing these operations to run in background threads without blocking the Node.js event loop.
//!
//! Scanning is performed in `compute()` (worker thread) using thread-safe `RuleMatchData`,
//! then converted to N-API `RuleMatch` objects in `resolve()` (main thread).

use crate::compiler::{replay_sources_to_wasm, StoredCompilerOptions};
use crate::error::scan_error_to_napi;
use crate::scanner::YaraX;
use crate::types::{RuleMatch, RuleMatchData, RuleSource, VariableMap};
use crate::variables::VariableHandler;
use napi::{Error, Result, Status, Task};
use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;
use yara_x::{Rules, Scanner};

#[derive(Clone, PartialEq)]
struct WorkerScannerOptions {
  max_matches_per_pattern: Option<usize>,
  use_mmap: Option<bool>,
  timeout_ms: Option<u32>,
  match_context_size: Option<usize>,
  variables: Option<VariableMap>,
}

impl WorkerScannerOptions {
  fn matches(&self, task: &BaseYaraTask) -> bool {
    self.max_matches_per_pattern == task.max_matches_per_pattern
      && self.use_mmap == task.use_mmap
      && self.timeout_ms == task.timeout_ms
      && self.match_context_size == task.match_context_size
      && self.variables == task.variables
  }
}

struct CachedWorkerScanner {
  // NOTE: `scanner` MUST be declared BEFORE `rules`.
  // In Rust, struct fields are dropped in declaration order.
  // By declaring `scanner` first, `scanner`'s destructor is run before
  // `rules` is dropped, guaranteeing that `Rules` outlives `Scanner`.
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
  max_matches_per_pattern: Option<usize>,
  use_mmap: Option<bool>,
  timeout_ms: Option<u32>,
  match_context_size: Option<usize>,
}

impl BaseYaraTask {
  /// Creates a new base YARA task.
  pub fn new(
    rules: Arc<Rules>,
    variables: Option<VariableMap>,
    max_matches_per_pattern: Option<usize>,
    use_mmap: Option<bool>,
    timeout_ms: Option<u32>,
    match_context_size: Option<usize>,
  ) -> Self {
    Self {
      rules,
      variables,
      max_matches_per_pattern,
      use_mmap,
      timeout_ms,
      match_context_size,
    }
  }

  /// Executes a scan operation with a thread-local cached scanner.
  ///
  /// Reuses the existing scanner on this worker thread if the rules pointer
  /// (`Arc::ptr_eq`) and scan options match. If rules or options differ, a new
  /// scanner is instantiated and cached.
  fn with_scanner<F, R>(&self, f: F) -> Result<R>
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
        // SAFETY: The transmute extends the borrow lifetime of `rules_clone` to `'static`.
        // This is sound because `CachedWorkerScanner` holds `rules_clone` (an `Arc<Rules>`),
        // which guarantees the `Rules` allocation remains alive on the heap for at least as
        // long as `CachedWorkerScanner`. In `CachedWorkerScanner`, `scanner` is declared before
        // `rules`, ensuring that when `CachedWorkerScanner` is dropped or replaced, `scanner`
        // is dropped before `rules`.
        let rules_ref: &'static Rules =
          unsafe { std::mem::transmute::<&Rules, &'static Rules>(&*rules_clone) };

        let mut scanner = Scanner::new(rules_ref);
        if let Some(max_matches) = self.max_matches_per_pattern {
          scanner.max_matches_per_pattern(max_matches);
        }
        if let Some(use_mmap) = self.use_mmap {
          scanner.use_mmap(use_mmap);
        }
        if let Some(timeout_ms) = self.timeout_ms {
          scanner.set_timeout(Duration::from_millis(timeout_ms as u64));
        }
        if let Some(match_context_size) = self.match_context_size {
          scanner.match_context_size(match_context_size);
        }
        scanner.apply_variables_from_map(&self.variables)?;

        *cache = Some(CachedWorkerScanner {
          scanner,
          rules: rules_clone,
          options: WorkerScannerOptions {
            max_matches_per_pattern: self.max_matches_per_pattern,
            use_mmap: self.use_mmap,
            timeout_ms: self.timeout_ms,
            match_context_size: self.match_context_size,
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
      let results = scanner.scan(data).map_err(scan_error_to_napi)?;
      Ok(YaraX::extract_scan_data(results))
    })
  }

  /// Scans data on the current thread and returns whether any rule matched.
  ///
  /// This is designed to be called from `compute()` (worker thread).
  pub fn is_match(&self, data: &[u8]) -> Result<bool> {
    self.with_scanner(|scanner| {
      let results = scanner.scan(data).map_err(scan_error_to_napi)?;
      Ok(results.matching_rules().next().is_some())
    })
  }

  /// Scans a file on the current thread and returns thread-safe results.
  pub fn scan_file_to_data(&self, file_path: &str) -> Result<Vec<RuleMatchData>> {
    self.with_scanner(|scanner| {
      let results = scanner.scan_file(file_path).map_err(scan_error_to_napi)?;
      Ok(YaraX::extract_scan_data(results))
    })
  }

  /// Scans a file on the current thread and returns whether any rule matched.
  pub fn is_file_match(&self, file_path: &str) -> Result<bool> {
    self.with_scanner(|scanner| {
      let results = scanner.scan_file(file_path).map_err(scan_error_to_napi)?;
      Ok(results.matching_rules().next().is_some())
    })
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
  pub fn new(
    rules: Arc<Rules>,
    data: Vec<u8>,
    variables: Option<VariableMap>,
    max_matches_per_pattern: Option<usize>,
    timeout_ms: Option<u32>,
    match_context_size: Option<usize>,
  ) -> Self {
    Self {
      base: BaseYaraTask::new(
        rules,
        variables,
        max_matches_per_pattern,
        None,
        timeout_ms,
        match_context_size,
      ),
      data,
    }
  }
}

impl Task for ScanTask {
  type Output = Vec<RuleMatchData>;
  type JsValue = Vec<RuleMatch<'static>>;

  fn compute(&mut self) -> Result<Self::Output> {
    self.base.scan_to_data(&self.data)
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
  pub fn new(
    rules: Arc<Rules>,
    file_path: String,
    variables: Option<VariableMap>,
    max_matches_per_pattern: Option<usize>,
    use_mmap: Option<bool>,
    timeout_ms: Option<u32>,
    match_context_size: Option<usize>,
  ) -> Self {
    Self {
      base: BaseYaraTask::new(
        rules,
        variables,
        max_matches_per_pattern,
        use_mmap,
        timeout_ms,
        match_context_size,
      ),
      file_path,
    }
  }
}

impl Task for ScanFileTask {
  type Output = Vec<RuleMatchData>;
  type JsValue = Vec<RuleMatch<'static>>;

  fn compute(&mut self) -> Result<Self::Output> {
    self.base.scan_file_to_data(&self.file_path)
  }

  fn resolve(&mut self, env: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    YaraX::convert_to_rule_matches(env, output)
  }
}

/// Task for checking whether data matches any compiled YARA rule asynchronously.
///
/// Scanning runs on the worker thread in `compute()`.
pub struct IsMatchTask {
  base: BaseYaraTask,
  data: Vec<u8>,
}

impl IsMatchTask {
  /// Creates a new boolean match task for data.
  pub fn new(
    rules: Arc<Rules>,
    data: Vec<u8>,
    variables: Option<VariableMap>,
    max_matches_per_pattern: Option<usize>,
    timeout_ms: Option<u32>,
    match_context_size: Option<usize>,
  ) -> Self {
    Self {
      base: BaseYaraTask::new(
        rules,
        variables,
        max_matches_per_pattern,
        None,
        timeout_ms,
        match_context_size,
      ),
      data,
    }
  }
}

impl Task for IsMatchTask {
  type Output = bool;
  type JsValue = bool;

  fn compute(&mut self) -> Result<Self::Output> {
    self.base.is_match(&self.data)
  }

  fn resolve(&mut self, _env: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}

/// Task for checking whether a file matches any compiled YARA rule asynchronously.
///
/// File I/O and scanning run on the worker thread in `compute()`.
pub struct IsFileMatchTask {
  base: BaseYaraTask,
  file_path: String,
}

impl IsFileMatchTask {
  /// Creates a new boolean match task for a file.
  pub fn new(
    rules: Arc<Rules>,
    file_path: String,
    variables: Option<VariableMap>,
    max_matches_per_pattern: Option<usize>,
    use_mmap: Option<bool>,
    timeout_ms: Option<u32>,
    match_context_size: Option<usize>,
  ) -> Self {
    Self {
      base: BaseYaraTask::new(
        rules,
        variables,
        max_matches_per_pattern,
        use_mmap,
        timeout_ms,
        match_context_size,
      ),
      file_path,
    }
  }
}

impl Task for IsFileMatchTask {
  type Output = bool;
  type JsValue = bool;

  fn compute(&mut self) -> Result<Self::Output> {
    self.base.is_file_match(&self.file_path)
  }

  fn resolve(&mut self, _env: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}

/// Task for emitting a WASM file from YARA rules.
///
/// This task compiles YARA rules to WebAssembly asynchronously.
pub struct EmitWasmFileTask {
  pub source_code: Option<String>,
  pub rule_sources: Vec<RuleSource>,
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
    let sources = if self.rule_sources.is_empty() {
      fallback_source = [RuleSource {
        source: source.clone(),
        namespace: None,
      }];
      &fallback_source[..]
    } else {
      &self.rule_sources[..]
    };

    replay_sources_to_wasm(
      sources,
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
