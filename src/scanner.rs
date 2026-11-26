//! YARA scanner implementation and utilities.
//!
//! This module contains the main YaraX struct and related functionality for
//! scanning data with compiled YARA rules, including scanner caching for performance.

use crate::batch::{
  collect_directory_files, convert_batch_result, execute_batch_scan, BatchScanOptions,
  BatchScanResult, BatchScanTarget, BatchScanTask, PathFilter,
};
use crate::binary::{extract_binary_scan_results, BinaryScanResult, BinaryScanTask, RuleInfo};
use crate::compiler::{
  add_source_to_compiler_tolerant, apply_compiler_options, apply_stored_compiler_options,
  collect_ignored_rules, ensure_no_uncovered_errors, ignored_module_warnings,
  replay_sources_to_wasm, stored_options_from, validate_sources_standalone, StoredCompilerOptions,
};
use crate::error::{io_error_to_napi, scan_error_to_napi};
use crate::types::{
  CompilerError, CompilerOptions, CompilerWarning, IgnoredRule, MatchData, RuleMatch, RuleMetadata,
  RuleSource, VariableValue,
};
use crate::variables::{
  convert_variables_to_map, get_compiler_errors, get_compiler_warnings,
  variable_value_from_unknown, VariableHandler,
};
use napi::bindgen_prelude::Unknown;
use napi::bindgen_prelude::{AsyncTask, Buffer, JsObjectValue, Object};
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi::{Env, Error, Result, Status};
use napi_derive::napi;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use yara_x::{Compiler, Rules, Scanner};

/// Cached scanner plus the `Arc<Rules>` backing its borrow.
///
/// `scanner` is declared first so it drops before the `Arc`, which keeps the
/// borrow valid independently of `YaraX`'s own field order.
pub(crate) struct CachedScanner {
  scanner: Scanner<'static>,
  #[allow(dead_code)]
  rules: Arc<Rules>,
}

/// The rule set and everything derived from compiling it.
///
/// All of it is a function of [`YaraX::rule_sources`] plus the stored options
/// and globals, so instead of being rebuilt on every mutation it is rebuilt on
/// demand by [`YaraX::ensure_compiled`] and held behind a `RefCell` so the
/// readers (`getRules()`, `serialize()`, a scan) can refresh it through
/// `&self`.
struct CompiledState {
  rules: Arc<Rules>,
  /// The concatenated sources, kept for WASM emission. `None` while no source
  /// is known (a scanner restored by `deserialize()`), which is what makes
  /// emission report that no source is available.
  source_code: Option<String>,
  warnings: Vec<CompilerWarning>,
  ignored_rules: Vec<IgnoredRule>,
  compilation_errors: Vec<CompilerError>,
}

/// A rule source together with the file it was read from, when there was one.
///
/// The origin is replayed on every incremental recompilation so diagnostics
/// keep naming the file and `include` statements keep resolving next to it.
#[derive(Debug, Clone)]
pub(crate) struct StoredRuleSource {
  pub source: RuleSource,
  pub origin: Option<String>,
}

/// The main YARA-X scanner struct.
///
/// This struct represents compiled YARA rules and provides methods for scanning
/// data and files. It includes performance optimizations like scanner caching.
#[napi]
pub struct YaraX {
  /// The compiled rule set and its reports; see [`CompiledState`].
  compiled: RefCell<CompiledState>,
  /// Whether `compiled` is behind `rule_sources`/`variables` and has to be
  /// rebuilt before it is read.
  ///
  /// Set by the incremental mutators (`addRuleSource()`, `addRuleFile()`,
  /// `defineVariable()`) instead of recompiling on the spot: a rebuild reads
  /// every source, so doing it per call costs O(n²) over n additions (see
  /// [`Self::ensure_compiled`]). A failed rebuild leaves this set, so the
  /// error is reported again by the next read rather than being lost.
  needs_rebuild: Cell<bool>,
  /// Full rule-set compilations performed since construction.
  ///
  /// Instrumentation for the test that pins the coalescing above; see
  /// [`Self::recompilations`].
  recompiles: Cell<u32>,
  /// The source code segments and namespaces used to compile the YARA rules.
  ///
  /// This is the committed truth the rebuild replays; an invalid source is
  /// rejected before it gets here, so a rejected addition leaves it untouched.
  pub(crate) rule_sources: Vec<StoredRuleSource>,
  /// The variables defined for the YARA rules.
  pub(crate) variables: Option<HashMap<String, VariableValue>>,
  /// Whether rule compilation errors are tolerated (rules skipped and
  /// reported via `ignored_rules`) instead of aborting compilation.
  pub(crate) ignore_invalid_rules: bool,
  /// The compiler options the rules were compiled with, minus the fields
  /// tracked separately (`namespace`, `define_variables`, and
  /// `ignore_invalid_rules`).
  ///
  /// Replayed on every incremental recompilation (`add_rule_source`,
  /// `add_rule_sources`, `define_variable`) and on WASM emission so the
  /// resulting rules behave exactly like a one-shot compilation of the same
  /// sources with the same options.
  pub(crate) stored_options: StoredCompilerOptions,
  /// Cached scanner for reuse (thread-local, not Send/Sync safe)
  pub(crate) cached_scanner: RefCell<Option<CachedScanner>>,
  // The scan options below are `Cell`s rather than plain fields so their
  // setters can take `&self`. N-API registers a native borrow for the receiver
  // of every generated method, and an `AsyncTask` keeps that borrow alive
  // until the task finalizes; an exclusive (`&mut self`) receiver requested
  // during an in-flight async scan is therefore rejected with `InvalidArg`.
  // Shared borrows do not conflict, so with `Cell` storage the setters keep
  // working while a scan runs.
  /// Maximum number of matches per pattern
  pub(crate) max_matches_per_pattern: Cell<Option<usize>>,
  /// Whether to use memory-mapped files for scanning
  pub(crate) use_mmap: Cell<Option<bool>>,
  /// Whether fast scan mode is enabled (stops pattern search at first match)
  pub(crate) fast_scan: Cell<Option<bool>>,
  /// Scan timeout in milliseconds
  pub(crate) timeout_ms: Cell<Option<u32>>,
  /// Match context size
  pub(crate) match_context_size: Cell<Option<usize>>,
  /// Maximum number of bytes to scan
  pub(crate) max_scan_size: Cell<Option<usize>>,
  /// Sink for messages emitted by rules through the `console` module. Held
  /// behind `Arc` because `ThreadsafeFunction` is not `Clone` and the scanner
  /// closure must own its handle for the `'static` scanner.
  pub(crate) console_log: Option<
    std::sync::Arc<ThreadsafeFunction<String, Unknown<'static>, String, Status, false, true>>,
  >,
}

impl YaraX {
  /// Creates a new, unconfigured YaraX instance with the given rules and optional source code.
  pub(crate) fn new_empty(rules: Arc<Rules>, source_code: Option<String>) -> Self {
    Self {
      compiled: RefCell::new(CompiledState {
        rules,
        source_code,
        warnings: Vec::new(),
        ignored_rules: Vec::new(),
        compilation_errors: Vec::new(),
      }),
      needs_rebuild: Cell::new(false),
      recompiles: Cell::new(0),
      rule_sources: Vec::new(),
      variables: None,
      ignore_invalid_rules: false,
      stored_options: StoredCompilerOptions::default(),
      cached_scanner: RefCell::new(None),
      max_matches_per_pattern: Cell::new(None),
      use_mmap: Cell::new(None),
      fast_scan: Cell::new(None),
      timeout_ms: Cell::new(None),
      match_context_size: Cell::new(None),
      max_scan_size: Cell::new(None),
      console_log: None,
    }
  }

  /// Creates a new YaraX instance from a source string.
  ///
  /// `env` decorates a rejected compilation with `ruleCode` and the diagnostic
  /// location; see [`compile_error_to_napi`](crate::error::compile_error_to_napi).
  pub fn create_scanner_from_source(
    env: Env,
    source: String,
    options: Option<CompilerOptions>,
    origin: Option<&str>,
  ) -> Result<Self> {
    let mut compiler = Compiler::new();

    let stored_options = stored_options_from(options.as_ref());
    let stored_variables = apply_compiler_options(&mut compiler, options.as_ref(), true)?;
    let namespace = options.as_ref().and_then(|opts| opts.namespace.as_deref());
    let ignore_invalid_rules = options
      .as_ref()
      .and_then(|opts| opts.ignore_invalid_rules)
      .unwrap_or(false);

    add_source_to_compiler_tolerant(
      &mut compiler,
      source.as_str(),
      namespace,
      origin,
      ignore_invalid_rules,
      Some(&env),
    )?;

    if ignore_invalid_rules {
      ensure_no_uncovered_errors(&compiler)?;
    }

    let mut warnings = get_compiler_warnings(&compiler);
    warnings.extend(ignored_module_warnings(&stored_options));
    // Rules can be skipped even without `ignore_invalid_rules` (e.g. when
    // they depend on ignored modules), so the report is collected
    // unconditionally. Compilation errors are only survivable in tolerant
    // mode (otherwise `add_source` aborts above), so collect them from the
    // compiler regardless and keep the ones that remain.
    let ignored_rules = collect_ignored_rules(&compiler);
    let compilation_errors = get_compiler_errors(&compiler);
    let rules = compiler.build();
    let rule_sources = vec![StoredRuleSource {
      source: RuleSource {
        source: source.clone(),
        namespace: namespace.map(str::to_string),
      },
      origin: origin.map(str::to_string),
    }];

    Ok(YaraX {
      compiled: RefCell::new(CompiledState {
        rules: Arc::new(rules),
        source_code: Some(source),
        warnings,
        ignored_rules,
        compilation_errors,
      }),
      needs_rebuild: Cell::new(false),
      recompiles: Cell::new(0),
      rule_sources,
      variables: stored_variables,
      ignore_invalid_rules,
      stored_options,
      cached_scanner: RefCell::new(None),
      max_matches_per_pattern: Cell::new(None),
      use_mmap: Cell::new(None),
      fast_scan: Cell::new(None),
      timeout_ms: Cell::new(None),
      match_context_size: Cell::new(None),
      max_scan_size: Cell::new(None),
      console_log: None,
    })
  }

  /// Extracts matches from a YARA rule.
  fn extract_matches(rule: &yara_x::Rule) -> Vec<MatchData> {
    let total_matches: usize = rule.patterns().map(|pattern| pattern.matches().len()).sum();

    let mut matches_vec = Vec::with_capacity(total_matches);

    for pattern in rule.patterns() {
      let pattern_matches = pattern.matches();
      if pattern_matches.len() == 0 {
        continue;
      }

      let pattern_id_str = pattern.identifier().to_string();

      for match_item in pattern_matches {
        let range = match_item.range();
        let offset = range.start;
        let length = range.end - range.start;

        let matched_data = String::from_utf8_lossy(match_item.data()).into_owned();

        let (context_data_slice, context_range) = match_item.data_with_context();
        let has_context = context_data_slice.len() > match_item.data().len();

        let (context_data, context_match_offset) = if has_context {
          (
            Some(String::from_utf8_lossy(context_data_slice).into_owned()),
            Some(context_range.start as i64),
          )
        } else {
          (None, None)
        };

        matches_vec.push(MatchData {
          offset: offset as i64,
          length: length as i64,
          data: matched_data,
          identifier: pattern_id_str.clone(),
          context_data,
          context_match_offset,
          xor_key: match_item.xor_key(),
          data_bytes: Some(Buffer::from(match_item.data())),
        });
      }
    }

    matches_vec
  }

  /// Applies this scanner's stored compiler options and global
  /// variables to a compiler, then adds all rule sources in order.
  ///
  /// Variables are applied **before** the sources — yara-x requires globals
  /// to be defined before compiling the rules that reference them — mirroring
  /// [`create_scanner_from_source`](Self::create_scanner_from_source).
  fn compile_all_sources_with_vars(
    &self,
    compiler: &mut Compiler<'_>,
    variables: Option<&HashMap<String, VariableValue>>,
    env: Option<&Env>,
  ) -> Result<()> {
    self.compile_sources_with_vars(&self.rule_sources, compiler, variables, env)
  }

  /// Compiles an explicit source list with this scanner's stored options and
  /// globals — the rebuild behind [`Self::ensure_compiled`].
  fn compile_sources_with_vars(
    &self,
    sources: &[StoredRuleSource],
    compiler: &mut Compiler<'_>,
    variables: Option<&HashMap<String, VariableValue>>,
    env: Option<&Env>,
  ) -> Result<()> {
    apply_stored_compiler_options(compiler, &self.stored_options)?;

    if let Some(vars) = variables {
      for (key, value) in vars {
        compiler.apply_variable_value(key, value)?;
      }
    }

    for source in sources {
      add_source_to_compiler_tolerant(
        compiler,
        &source.source.source,
        source.source.namespace.as_deref(),
        source.origin.as_deref(),
        self.ignore_invalid_rules,
        env,
      )?;
    }

    if sources.is_empty() {
      let source_code = self.compiled.borrow().source_code.clone();
      if let Some(source) = source_code.filter(|source| !source.is_empty()) {
        add_source_to_compiler_tolerant(
          compiler,
          &source,
          None,
          None,
          self.ignore_invalid_rules,
          env,
        )?;
      }
    }

    if self.ignore_invalid_rules {
      ensure_no_uncovered_errors(compiler)?;
    }

    Ok(())
  }

  /// Materializes the rule set if a recorded change has not been compiled yet.
  ///
  /// Every incremental mutator only records its change, so a batch of n
  /// additions costs one compilation instead of n (and O(total) work instead of
  /// O(total²)). The rebuild runs here, on the first read or scan that needs the
  /// compiled rules; `env` decorates a rejected rebuild the way
  /// `compile()` does (see
  /// [`compile_error_to_napi`](crate::error::compile_error_to_napi)).
  ///
  /// A rejected rebuild leaves the previous rule set in place and the pending
  /// flag set, so the caller meets the same error on every attempt until the
  /// rules are fixed — nothing is silently dropped.
  fn ensure_compiled(&self, env: Option<&Env>) -> Result<()> {
    if !self.needs_rebuild.get() {
      return Ok(());
    }

    let mut compiler = Compiler::new();
    self.compile_all_sources_with_vars(&mut compiler, self.variables.as_ref(), env)?;
    self.refresh_compilation_state(compiler);

    Ok(())
  }

  /// The compiled rules, rebuilding them first if anything is pending.
  ///
  /// Hands back the `Arc` rather than a borrow into `compiled`, so callers can
  /// keep it across a scan or hand it to a background task without holding the
  /// `RefCell` open.
  fn current_rules(&self, env: Option<&Env>) -> Result<Arc<Rules>> {
    self.ensure_compiled(env)?;
    Ok(self.compiled.borrow().rules.clone())
  }

  /// Consumes the compiler produced by a rebuild, publishing the rules and the
  /// reports derived from them, and clearing the pending flag.
  fn refresh_compilation_state(&self, compiler: Compiler<'_>) {
    let mut warnings = get_compiler_warnings(&compiler);
    warnings.extend(ignored_module_warnings(&self.stored_options));
    let ignored_rules = collect_ignored_rules(&compiler);
    let compilation_errors = get_compiler_errors(&compiler);
    let rules = Arc::new(compiler.build());

    let mut compiled = self.compiled.borrow_mut();
    compiled.rules = rules;
    compiled.warnings = warnings;
    compiled.ignored_rules = ignored_rules;
    compiled.compilation_errors = compilation_errors;

    // Keep the concatenated source in sync for WASM emission. A scanner that
    // has never been given a source (restored by `deserialize()`) keeps
    // `None`, so emission still says no source is available.
    if !self.rule_sources.is_empty() {
      let mut combined = String::new();
      for (i, stored) in self.rule_sources.iter().enumerate() {
        if i > 0 {
          combined.push('\n');
        }
        combined.push_str(&stored.source.source);
      }
      compiled.source_code = Some(combined);
    }
    drop(compiled);

    self.needs_rebuild.set(false);
    self.recompiles.set(self.recompiles.get() + 1);
    self.invalidate_scanner_cache();
  }

  /// Gets or creates a cached scanner for reuse.
  ///
  /// This is a performance optimization that reuses scanner instances. Any
  /// pending rule change is materialized first, which is what makes
  /// `addRuleSource()` followed by `scan()` see the new rules.
  fn get_or_create_scanner(
    &self,
    env: Option<&Env>,
  ) -> Result<std::cell::RefMut<'_, Scanner<'static>>> {
    // Kept outside the `cached_scanner` borrow: a rejected rebuild must not
    // leave that borrow open, and the successful one closes it via
    // `invalidate_scanner_cache`.
    self.ensure_compiled(env)?;

    let mut cached = self.cached_scanner.borrow_mut();

    let needs_new_scanner = cached.is_none();

    if needs_new_scanner {
      // SAFETY: `rules` (below) is cloned into the cache beside the scanner, so
      // the borrow outlives every use of the `'static` reference.
      let rules = self.compiled.borrow().rules.clone();
      let mut scanner = Scanner::new(unsafe {
        std::mem::transmute::<&yara_x::Rules, &'static yara_x::Rules>(&*rules)
      });

      // Apply scan options
      if let Some(max_matches) = self.max_matches_per_pattern.get() {
        scanner.max_matches_per_pattern(max_matches);
      }

      if let Some(use_mmap) = self.use_mmap.get() {
        scanner.use_mmap(use_mmap);
      }

      if let Some(fast_scan) = self.fast_scan.get() {
        scanner.fast_scan(fast_scan);
      }

      if let Some(timeout_ms) = self.timeout_ms.get() {
        scanner.set_timeout(Duration::from_millis(timeout_ms as u64));
      }

      if let Some(match_context_size) = self.match_context_size.get() {
        scanner.match_context_size(match_context_size);
      }

      if let Some(max_scan_size) = self.max_scan_size.get() {
        scanner.max_scan_size(max_scan_size);
      }

      if let Some(console_log) = &self.console_log {
        let console_log = std::sync::Arc::clone(console_log);
        scanner.console_log(move |message: String| {
          let _ = console_log.call(message, ThreadsafeFunctionCallMode::NonBlocking);
        });
      }

      *cached = Some(CachedScanner { scanner, rules });
    }

    Ok(std::cell::RefMut::map(cached, |opt| {
      &mut opt.as_mut().unwrap().scanner
    }))
  }

  /// Invalidates the cached scanner, forcing recreation on next use.
  fn invalidate_scanner_cache(&self) {
    *self.cached_scanner.borrow_mut() = None;
  }

  /// Processes the scan results and returns a vector of RuleMatch.
  pub fn process_scan_results<'a>(
    results: yara_x::ScanResults,
    env: napi::Env,
  ) -> Result<Vec<RuleMatch<'a>>> {
    Self::convert_to_rule_matches(env, Self::extract_scan_data(results))
  }

  /// Extracts scan results into thread-safe `RuleMatchData` structs.
  pub fn extract_scan_data(results: yara_x::ScanResults) -> Vec<crate::types::RuleMatchData> {
    use crate::types::{MetaValueData, RuleMatchData};

    let matching_rules = results.matching_rules();
    let rule_count = matching_rules.len();

    if rule_count == 0 {
      return Vec::new();
    }

    let mut rule_matches = Vec::with_capacity(rule_count);

    for rule in matching_rules {
      let matches_vec = Self::extract_matches(&rule);

      let tags: Vec<String> = rule
        .tags()
        .map(|tag| tag.identifier().to_string())
        .collect();

      let meta: Vec<(String, MetaValueData)> = rule
        .metadata()
        .map(|(key, value)| (key.to_string(), MetaValueData::from(value)))
        .collect();

      rule_matches.push(RuleMatchData {
        rule_identifier: rule.identifier().to_string(),
        namespace: rule.namespace().to_string(),
        meta,
        tags,
        matches: matches_vec,
      });
    }

    rule_matches
  }

  /// Converts thread-safe `RuleMatchData` into N-API `RuleMatch` objects.
  ///
  /// This should be called on the main thread (in `resolve()`).
  pub fn convert_to_rule_matches<'a>(
    env: napi::Env,
    data: Vec<crate::types::RuleMatchData>,
  ) -> Result<Vec<RuleMatch<'a>>> {
    use crate::types::MetaValueData;

    let mut rule_matches = Vec::with_capacity(data.len());

    for item in data {
      let mut meta_obj = Object::new(&env)?;

      for (key, value) in &item.meta {
        match value {
          MetaValueData::Integer(i) => meta_obj.set_named_property(key, *i)?,
          MetaValueData::Float(f) => meta_obj.set_named_property(key, *f)?,
          MetaValueData::String(s) => meta_obj.set_named_property(key, s.as_str())?,
          MetaValueData::Bool(b) => meta_obj.set_named_property(key, *b)?,
        }
      }

      rule_matches.push(RuleMatch {
        rule_identifier: item.rule_identifier,
        namespace: item.namespace,
        meta: meta_obj,
        tags: item.tags,
        matches: item.matches,
      });
    }

    Ok(rule_matches)
  }

  /// Helper to combine stored scanner variables and scan-time variables for async tasks.
  pub(crate) fn combine_variables(
    &self,
    variables: Option<Object>,
  ) -> Result<Option<HashMap<String, VariableValue>>> {
    let scan_vars = convert_variables_to_map(variables)?;
    Ok(match (&self.variables, scan_vars) {
      (None, None) => None,
      (Some(stored), None) => Some(stored.clone()),
      (None, Some(vars)) => Some(vars),
      (Some(stored), Some(vars)) => {
        let mut map = stored.clone();
        map.extend(vars);
        Some(map)
      }
    })
  }
}

#[napi]
impl YaraX {
  /// Returns the compiler warnings generated during the compilation process.
  ///
  /// Includes a rule source added since the last read: the rule set is
  /// materialized here rather than the report being one addition behind.
  #[napi]
  pub fn get_warnings(&self, env: Env) -> Result<Vec<CompilerWarning>> {
    self.ensure_compiled(Some(&env))?;
    Ok(self.compiled.borrow().warnings.clone())
  }

  /// Gets the rules that were skipped during compilation, if any.
  ///
  /// Rules are skipped when they depend on an ignored module (see
  /// `ignoreModules`), or when `ignore_invalid_rules: true` (see
  /// `CompilerOptions`) and they failed to compile. Each entry reports the
  /// rule name, the reason it was skipped (`ignored_module`, `ignored_rule`,
  /// or `compile_error`), and a detail string.
  ///
  /// A vector of `IgnoredRule` objects (empty when nothing was skipped)
  #[napi]
  pub fn get_ignored_rules(&self, env: Env) -> Result<Vec<IgnoredRule>> {
    self.ensure_compiled(Some(&env))?;
    Ok(self.compiled.borrow().ignored_rules.clone())
  }

  /// Gets the errors generated while compiling the rules, when compilation
  /// was performed with `ignore_invalid_rules: true`.
  ///
  /// In tolerant mode, per-rule failures are reported by
  /// [`get_ignored_rules`](Self::get_ignored_rules) (where the same error
  /// also appears in the entry's `detail`) and the remaining rules are
  /// compiled. Every error the compiler generated is collected here,
  /// including source-level errors that cannot be attributed to a single
  /// skipped rule (syntax errors, invalid UTF-8, banned or unknown module
  /// imports, include failures) — in strict mode those abort compilation
  /// instead. Mirrors the upstream Python binding's `Compiler.errors()`.
  ///
  /// A vector of `CompilerError` objects (empty when no errors occurred)
  #[napi]
  pub fn get_compilation_errors(&self, env: Env) -> Result<Vec<CompilerError>> {
    self.ensure_compiled(Some(&env))?;
    Ok(self.compiled.borrow().compilation_errors.clone())
  }

  /// Sets the maximum number of matches per pattern.
  ///
  /// Applies to scans started after the call, and is safe to call while a
  /// scan is in flight.
  #[napi]
  pub fn set_max_matches_per_pattern(&self, max_matches: u32) {
    self.max_matches_per_pattern.set(Some(max_matches as usize));
    self.invalidate_scanner_cache();
  }

  /// Sets whether to use memory-mapped files for scanning.
  ///
  /// Applies to scans started after the call, and is safe to call while a
  /// scan is in flight.
  #[napi]
  pub fn set_use_mmap(&self, use_mmap: bool) {
    self.use_mmap.set(Some(use_mmap));
    self.invalidate_scanner_cache();
  }

  /// Sets whether to use fast scan mode (stops searching for a pattern as soon as the first match is found).
  ///
  /// Applies to scans started after the call, and is safe to call while a
  /// scan is in flight.
  #[napi]
  pub fn set_fast_scan(&self, fast_scan: bool) {
    self.fast_scan.set(Some(fast_scan));
    self.invalidate_scanner_cache();
  }

  /// Sets the scan timeout in milliseconds; `0` disables it.
  ///
  /// Best-effort: YARA-X checks the deadline between work units, so a scan can
  /// overrun it. Use `setMaxScanSize()` for a hard bound.
  ///
  /// Applies to scans started after the call, and is safe to call while a
  /// scan is in flight.
  #[napi]
  pub fn set_timeout(&self, timeout_ms: u32) {
    self.timeout_ms.set((timeout_ms > 0).then_some(timeout_ms));
    self.invalidate_scanner_cache();
  }

  /// Sets the match context size.
  ///
  /// Applies to scans started after the call, and is safe to call while a
  /// scan is in flight.
  #[napi]
  pub fn set_match_context_size(&self, size: u32) {
    self.match_context_size.set(Some(size as usize));
    self.invalidate_scanner_cache();
  }

  /// Returns the slowest rules seen by this scanner, fastest to slowest
  /// excluded: only rules that accumulated more than 100 ms are reported, and
  /// timings cover synchronous scans since the last `clearProfilingData()`.
  #[napi]
  pub fn get_slowest_rules(&self, env: Env, n: u32) -> Result<Vec<crate::types::RuleProfile>> {
    let scanner = self.get_or_create_scanner(Some(&env))?;

    Ok(
      scanner
        .slowest_rules(n as usize)
        .into_iter()
        .map(|data| crate::types::RuleProfile {
          namespace: data.namespace.to_string(),
          identifier: data.rule.to_string(),
          pattern_matching_ms: data.pattern_matching_time.as_secs_f64() * 1000.0,
          condition_ms: data.condition_exec_time.as_secs_f64() * 1000.0,
        })
        .collect(),
    )
  }

  /// Discards the timing data behind `getSlowestRules()`.
  #[napi]
  pub fn clear_profiling_data(&self, env: Env) -> Result<()> {
    self
      .get_or_create_scanner(Some(&env))?
      .clear_profiling_data();
    Ok(())
  }

  /// Routes messages logged by rules through the `console` module to a callback.
  ///
  /// Messages arrive on the event loop, so a synchronous scan returns before
  /// the callback runs. Pass nothing to stop receiving them.
  ///
  /// The handle is weak, so it does not keep the process alive; messages still
  /// queued at exit may be dropped.
  #[napi]
  pub fn set_console_log(
    &mut self,
    callback: Option<ThreadsafeFunction<String, Unknown<'static>, String, Status, false, true>>,
  ) {
    self.console_log = callback.map(std::sync::Arc::new);
    self.invalidate_scanner_cache();
  }

  /// Sets the maximum number of bytes to scan.
  ///
  /// Any data or file exceeding this size will only have its initial
  /// bytes scanned up to this limit. Passing 0 or a negative number clears the limit.
  ///
  /// Applies to scans started after the call, and is safe to call while a
  /// scan is in flight.
  #[napi]
  pub fn set_max_scan_size(&self, max_bytes: i64) {
    self.max_scan_size.set(if max_bytes > 0 {
      Some(max_bytes as usize)
    } else {
      None
    });
    self.invalidate_scanner_cache();
  }

  /// Number of Rayon scan pools built since process start.
  ///
  /// A `concurrency` value reuses its pool, so repeated calls at one size must
  /// not raise this. Instrumentation for the batch test that pins #277; not
  /// consumer API, so it is deliberately absent from `index.d.ts` while
  /// remaining reachable on the exported class.
  #[napi(skip_typescript)]
  pub fn thread_pool_builds(&self) -> u32 {
    crate::batch::pool_build_count()
  }

  /// Number of full rule-set compilations this scanner has performed.
  ///
  /// `0` for a scanner built by `compile()`/`fromFile()`/`deserialize()`, whose
  /// rules arrive ready; `+1` per rebuild that a recorded change forced. One
  /// batch of additions therefore reads as exactly one rebuild, which is what
  /// the coalescing test asserts instead of timing. Instrumentation, not
  /// consumer API, so it stays out of `index.d.ts` while remaining reachable on
  /// the exported class.
  #[napi(skip_typescript)]
  pub fn recompilations(&self) -> u32 {
    self.recompiles.get()
  }

  /// Total number of compiled rules.
  #[napi(getter)]
  pub fn rule_count(&self, env: Env) -> Result<u32> {
    self.ensure_compiled(Some(&env))?;
    Ok(self.compiled.borrow().rules.iter().len() as u32)
  }

  /// Returns the names of all modules imported by the compiled rules (e.g. "pe", "elf", "hash").
  #[napi]
  pub fn get_imports(&self, env: Env) -> Result<Vec<String>> {
    self.ensure_compiled(Some(&env))?;
    Ok(
      self
        .compiled
        .borrow()
        .rules
        .imports()
        .map(str::to_string)
        .collect(),
    )
  }

  /// Returns metadata for all compiled rules including identifier, namespace, tags, and patterns.
  ///
  /// Materializes a pending addition first, so this is also where a rule that is
  /// only wrong in combination with the rest of the set reports — put it in the
  /// same `try` as the additions to have every rejection land there.
  #[napi]
  pub fn get_rules(&self, env: Env) -> Result<Vec<RuleInfo>> {
    let rules = self.current_rules(Some(&env))?;
    Ok(
      rules
        .iter()
        .map(|rule| RuleInfo {
          identifier: rule.identifier().to_string(),
          namespace: rule.namespace().to_string(),
          tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
          patterns: rule
            .patterns()
            .map(|p| p.identifier().to_string())
            .collect(),
          meta: RuleMetadata::from_rule(&rule),
        })
        .collect(),
    )
  }

  /// Helper to execute a synchronous scan closure with scanner caching and variable application.
  fn with_sync_scanner<F, R>(&self, env: Env, variables: &Option<Object>, op: F) -> Result<R>
  where
    F: FnOnce(&mut Scanner<'_>) -> Result<R>,
  {
    let mut scanner = self.get_or_create_scanner(Some(&env))?;
    scanner.apply_variables_from_map(&self.variables)?;
    scanner.apply_variables_from_object(variables)?;
    let res = op(&mut scanner);
    if res.is_err() {
      drop(scanner);
      self.invalidate_scanner_cache();
    }
    res
  }

  /// Scans the provided data using the compiled YARA rules.
  #[napi(
    ts_args_type = "data: Buffer, variables?: Record<string, string | number | boolean | bigint>"
  )]
  pub fn scan<'a>(
    &self,
    env: Env,
    data: Buffer,
    variables: Option<Object>,
  ) -> Result<Vec<RuleMatch<'a>>> {
    self.with_sync_scanner(env, &variables, |scanner| {
      let results = scanner
        .scan(data.as_ref())
        .map_err(|e| scan_error_to_napi(e, Some(&env)))?;
      Self::process_scan_results(results, env)
    })
  }

  /// Scans a file using the compiled YARA rules.
  #[napi(
    ts_args_type = "filePath: string, variables?: Record<string, string | number | boolean | bigint>"
  )]
  pub fn scan_file<'a>(
    &self,
    env: Env,
    file_path: String,
    variables: Option<Object>,
  ) -> Result<Vec<RuleMatch<'a>>> {
    self.with_sync_scanner(env, &variables, |scanner| {
      let results = scanner
        .scan_file(Path::new(&file_path))
        .map_err(|e| scan_error_to_napi(e, Some(&env)))?;
      Self::process_scan_results(results, env)
    })
  }

  /// Checks whether the provided data matches any compiled YARA rule.
  ///
  /// This method is a fast-path boolean check that returns true as soon as any rule matches,
  /// without allocating or constructing match objects, tags, or metadata.
  ///
  /// `true` if any rule matches, `false` otherwise
  #[napi(
    ts_args_type = "data: Buffer, variables?: Record<string, string | number | boolean | bigint>"
  )]
  pub fn is_match(&self, env: Env, data: Buffer, variables: Option<Object>) -> Result<bool> {
    self.with_sync_scanner(env, &variables, |scanner| {
      let results = scanner
        .scan(data.as_ref())
        .map_err(|e| scan_error_to_napi(e, Some(&env)))?;
      Ok(results.matching_rules().next().is_some())
    })
  }

  /// Checks whether a file matches any compiled YARA rule.
  ///
  /// This method is a fast-path boolean check that returns true as soon as any rule matches,
  /// without allocating or constructing match objects, tags, or metadata.
  ///
  /// `true` if any rule matches, `false` otherwise
  #[napi(
    ts_args_type = "filePath: string, variables?: Record<string, string | number | boolean | bigint>"
  )]
  pub fn is_file_match(
    &self,
    env: Env,
    file_path: String,
    variables: Option<Object>,
  ) -> Result<bool> {
    self.with_sync_scanner(env, &variables, |scanner| {
      let results = scanner
        .scan_file(Path::new(&file_path))
        .map_err(|e| scan_error_to_napi(e, Some(&env)))?;
      Ok(results.matching_rules().next().is_some())
    })
  }

  /// Scans the provided data returning a flat binary match record buffer and metadata catalog.
  ///
  /// This method is an ultra-fast path for high-density match reporting.
  /// It packs matches into a contiguous 24-byte record buffer, avoiding per-match
  /// V8 object and string allocations.
  #[napi(
    ts_args_type = "data: Buffer, variables?: Record<string, string | number | boolean | bigint>"
  )]
  pub fn scan_binary(
    &self,
    env: Env,
    data: Buffer,
    variables: Option<Object>,
  ) -> Result<BinaryScanResult> {
    self.with_sync_scanner(env, &variables, |scanner| {
      let results = scanner
        .scan(data.as_ref())
        .map_err(|e| scan_error_to_napi(e, Some(&env)))?;
      let (bytes, match_count, catalog) = extract_binary_scan_results(results);
      Ok(BinaryScanResult {
        buffer: Buffer::from(bytes),
        match_count,
        catalog,
      })
    })
  }

  /// Scans a file returning a flat binary match record buffer and metadata catalog.
  ///
  /// This method is an ultra-fast path for high-density match reporting.
  /// It packs matches into a contiguous 24-byte record buffer, avoiding per-match
  /// V8 object and string allocations.
  #[napi(
    ts_args_type = "filePath: string, variables?: Record<string, string | number | boolean | bigint>"
  )]
  pub fn scan_file_binary(
    &self,
    env: Env,
    file_path: String,
    variables: Option<Object>,
  ) -> Result<BinaryScanResult> {
    self.with_sync_scanner(env, &variables, |scanner| {
      let results = scanner
        .scan_file(Path::new(&file_path))
        .map_err(|e| scan_error_to_napi(e, Some(&env)))?;
      let (bytes, match_count, catalog) = extract_binary_scan_results(results);
      Ok(BinaryScanResult {
        buffer: Buffer::from(bytes),
        match_count,
        catalog,
      })
    })
  }

  /// Emits a WASM file from the compiled YARA rules.
  ///
  /// Ok(()) on success, or an error if emission fails
  #[napi]
  pub fn emit_wasm_file(&self, env: Env, output_path: String) -> Result<()> {
    // Materialize first: emission replays the sources, so a pending change has
    // to be in them, and a rejected rule set must not emit a module.
    self.ensure_compiled(Some(&env))?;

    let source = self.compiled.borrow().source_code.clone().ok_or_else(|| {
      Error::new(
        Status::InvalidArg,
        "Cannot emit WASM file: source code not available",
      )
    })?;

    let fallback_source;
    let fallback_origin;
    let owned_sources;
    let owned_origins;
    let (sources, origins): (&[RuleSource], &[Option<String>]) = if self.rule_sources.is_empty() {
      fallback_source = [RuleSource {
        source: source.clone(),
        namespace: None,
      }];
      fallback_origin = [None];
      (&fallback_source[..], &fallback_origin[..])
    } else {
      owned_sources = self
        .rule_sources
        .iter()
        .map(|entry| entry.source.clone())
        .collect::<Vec<_>>();
      owned_origins = self
        .rule_sources
        .iter()
        .map(|entry| entry.origin.clone())
        .collect::<Vec<_>>();
      (&owned_sources[..], &owned_origins[..])
    };

    // Replay the stored options and variables so the emitted module matches
    // the scanner's compilation semantics (including `ignore_invalid_rules`).
    replay_sources_to_wasm(
      sources,
      origins,
      &output_path,
      &self.stored_options,
      self.variables.as_ref(),
      self.ignore_invalid_rules,
    )
  }

  /// Serializes the compiled YARA rules to a portable binary blob.
  ///
  /// The serialized blob is self-contained (patterns, regex data, globals, and
  /// the compiled WASM conditions) and can be restored on any platform with
  /// the [`deserialize`](crate::deserialize) function, provided the same
  /// YARA-X version is used on both sides.
  #[napi]
  pub fn serialize(&self, env: Env) -> Result<Buffer> {
    let rules = self.current_rules(Some(&env))?;
    let bytes = rules.serialize().map_err(|e| {
      Error::new(
        Status::GenericFailure,
        format!("Failed to serialize rules: {e}"),
      )
    })?;

    Ok(Buffer::from(bytes))
  }

  /// Scans the provided data asynchronously using the compiled YARA rules.
  ///
  /// The input buffer is copied when this method is called, so mutating the
  /// buffer afterwards does not change the scan result. The synchronous
  /// [`scan`](Self::scan) reads the buffer directly and stays zero-copy.
  #[napi(
    ts_args_type = "data: Buffer, variables?: Record<string, string | number | boolean | bigint>",
    ts_return_type = "Promise<Array<RuleMatch>>"
  )]
  pub fn scan_async(
    &self,
    env: Env,
    data: Buffer,
    variables: Option<Object>,
  ) -> Result<AsyncTask<crate::tasks::ScanTask>> {
    let vars_map = self.combine_variables(variables)?;
    let rules = self.current_rules(Some(&env))?;

    Ok(AsyncTask::new(crate::tasks::ScanTask::new(
      rules,
      crate::tasks::ScanTarget::Buffer(data.to_vec()),
      vars_map,
      self.task_scan_options(false),
    )))
  }

  /// Scans a file asynchronously using the compiled YARA rules.
  #[napi(
    ts_args_type = "filePath: string, variables?: Record<string, string | number | boolean | bigint>",
    ts_return_type = "Promise<Array<RuleMatch>>"
  )]
  pub fn scan_file_async(
    &self,
    env: Env,
    file_path: String,
    variables: Option<Object>,
  ) -> Result<AsyncTask<crate::tasks::ScanTask>> {
    let vars_map = self.combine_variables(variables)?;
    let rules = self.current_rules(Some(&env))?;

    Ok(AsyncTask::new(crate::tasks::ScanTask::new(
      rules,
      crate::tasks::ScanTarget::File(file_path),
      vars_map,
      self.task_scan_options(true),
    )))
  }

  /// Checks whether the provided data matches any compiled YARA rule asynchronously.
  ///
  /// This method is a fast-path boolean check that returns true as soon as any rule matches,
  /// without allocating or constructing match objects, tags, or metadata.
  ///
  /// The input buffer is copied when this method is called, so mutating the
  /// buffer afterwards does not change the result.
  #[napi(
    ts_args_type = "data: Buffer, variables?: Record<string, string | number | boolean | bigint>",
    ts_return_type = "Promise<boolean>"
  )]
  pub fn is_match_async(
    &self,
    env: Env,
    data: Buffer,
    variables: Option<Object>,
  ) -> Result<AsyncTask<crate::tasks::IsMatchTask>> {
    let vars_map = self.combine_variables(variables)?;
    let rules = self.current_rules(Some(&env))?;

    Ok(AsyncTask::new(crate::tasks::IsMatchTask::new(
      rules,
      crate::tasks::ScanTarget::Buffer(data.to_vec()),
      vars_map,
      self.task_scan_options(false),
    )))
  }

  /// Checks whether a file matches any compiled YARA rule asynchronously.
  ///
  /// This method is a fast-path boolean check that returns true as soon as any rule matches,
  /// without allocating or constructing match objects, tags, or metadata.
  #[napi(
    ts_args_type = "filePath: string, variables?: Record<string, string | number | boolean | bigint>",
    ts_return_type = "Promise<boolean>"
  )]
  pub fn is_file_match_async(
    &self,
    env: Env,
    file_path: String,
    variables: Option<Object>,
  ) -> Result<AsyncTask<crate::tasks::IsMatchTask>> {
    let vars_map = self.combine_variables(variables)?;
    let rules = self.current_rules(Some(&env))?;

    Ok(AsyncTask::new(crate::tasks::IsMatchTask::new(
      rules,
      crate::tasks::ScanTarget::File(file_path),
      vars_map,
      self.task_scan_options(true),
    )))
  }

  /// Scans the provided data asynchronously returning a flat binary match buffer and catalog.
  ///
  /// The input buffer is copied when this method is called, so mutating the
  /// buffer afterwards does not change the result.
  #[napi(
    ts_args_type = "data: Buffer, variables?: Record<string, string | number | boolean | bigint>",
    ts_return_type = "Promise<BinaryScanResult>"
  )]
  pub fn scan_binary_async(
    &self,
    env: Env,
    data: Buffer,
    variables: Option<Object>,
  ) -> Result<AsyncTask<BinaryScanTask>> {
    let vars_map = self.combine_variables(variables)?;
    let rules = self.current_rules(Some(&env))?;

    Ok(AsyncTask::new(BinaryScanTask::new(
      rules,
      crate::tasks::ScanTarget::Buffer(data.to_vec()),
      vars_map,
      self.task_scan_options(false),
    )))
  }

  /// Scans a file asynchronously returning a flat binary match buffer and catalog.
  #[napi(
    ts_args_type = "filePath: string, variables?: Record<string, string | number | boolean | bigint>",
    ts_return_type = "Promise<BinaryScanResult>"
  )]
  pub fn scan_file_binary_async(
    &self,
    env: Env,
    file_path: String,
    variables: Option<Object>,
  ) -> Result<AsyncTask<BinaryScanTask>> {
    let vars_map = self.combine_variables(variables)?;
    let rules = self.current_rules(Some(&env))?;

    Ok(AsyncTask::new(BinaryScanTask::new(
      rules,
      crate::tasks::ScanTarget::File(file_path),
      vars_map,
      self.task_scan_options(true),
    )))
  }

  /// Helper to build TaskScanOptions for background tasks.
  fn task_scan_options(&self, include_mmap: bool) -> crate::tasks::TaskScanOptions {
    crate::tasks::TaskScanOptions {
      max_matches_per_pattern: self.max_matches_per_pattern.get(),
      fast_scan: self.fast_scan.get(),
      use_mmap: if include_mmap {
        self.use_mmap.get()
      } else {
        None
      },
      timeout_ms: self.timeout_ms.get(),
      match_context_size: self.match_context_size.get(),
      max_scan_size: self.max_scan_size.get(),
    }
  }

  /// Emits a WASM file asynchronously from the compiled YARA rules.
  #[napi(ts_return_type = "Promise<void>")]
  pub fn emit_wasm_file_async(
    &self,
    env: Env,
    output_path: String,
  ) -> Result<AsyncTask<crate::tasks::EmitWasmFileTask>> {
    // Same reason as `emit_wasm_file`: the snapshot handed to the task has to
    // include a pending change, and a rejected rule set must not emit.
    self.ensure_compiled(Some(&env))?;

    Ok(AsyncTask::new(crate::tasks::EmitWasmFileTask {
      source_code: self.compiled.borrow().source_code.clone(),
      rule_sources: self
        .rule_sources
        .iter()
        .map(|entry| entry.source.clone())
        .collect(),
      source_origins: self
        .rule_sources
        .iter()
        .map(|entry| entry.origin.clone())
        .collect(),
      output_path,
      stored_options: self.stored_options.clone(),
      variables: self.variables.clone(),
      ignore_invalid_rules: self.ignore_invalid_rules,
    }))
  }

  /// Adds a rule source to the YARA compiler.
  ///
  /// # Performance
  ///
  /// The source is checked on its own and the rule set is rebuilt once, when it
  /// is next read or scanned, so n additions cost one compilation rather than n
  /// — adding 120 rule files costs one rebuild instead of 120.
  ///
  /// A rule that is only wrong in combination with the rest of the set — it
  /// references a rule or global the other sources do not define, reuses one of
  /// their names, or clashes with an identifier one of them brings in — is
  /// checked by that rebuild, so it throws from the next
  /// `getRules()`/`serialize()`/`scan()` instead of here. Call `getRules()`
  /// after the additions to keep the strict timing; use `ignoreInvalidRules` to
  /// skip and report such a rule instead, since a strict scanner has nothing
  /// that can skip it and will report it on every read.
  #[napi]
  pub fn add_rule_source(
    &mut self,
    env: Env,
    rule_source: String,
    namespace: Option<String>,
  ) -> Result<()> {
    self.add_rule_sources(
      env,
      vec![RuleSource {
        source: rule_source,
        namespace,
      }],
    )
  }

  /// Adds multiple rule sources to the YARA compiler.
  ///
  /// The batch is checked as a unit, so a source in it may reference a rule or
  /// tag defined by another source in the same batch. It costs the same single
  /// deferred rebuild as the same number of `addRuleSource()` calls; prefer it
  /// when the sources are already at hand.
  #[napi]
  pub fn add_rule_sources(&mut self, env: Env, rule_sources: Vec<RuleSource>) -> Result<()> {
    let entries = rule_sources
      .into_iter()
      .map(|source| StoredRuleSource {
        source,
        origin: None,
      })
      .collect();
    self.add_rule_sources_internal(env, entries)
  }

  /// Adds sources that may carry a file origin, deferring the rebuild.
  fn add_rule_sources_internal(
    &mut self,
    env: Env,
    rule_sources: Vec<StoredRuleSource>,
  ) -> Result<()> {
    if rule_sources.is_empty() {
      return Ok(());
    }

    // Reject a broken source before recording it: the caller still meets it in
    // this call, and a rejected source cannot poison later additions. The check
    // reads only the new sources, which is what keeps a loop of additions
    // linear; see `ensure_compiled` for the deferred rebuild.
    let sources = rule_sources
      .iter()
      .map(|entry| entry.source.clone())
      .collect::<Vec<_>>();
    let origins = rule_sources
      .iter()
      .map(|entry| entry.origin.clone())
      .collect::<Vec<_>>();

    validate_sources_standalone(
      &self.stored_options,
      self.variables.as_ref(),
      self.ignore_invalid_rules,
      &sources,
      &origins,
      Some(&env),
    )?;

    self.rule_sources.extend(rule_sources);
    self.needs_rebuild.set(true);

    Ok(())
  }

  /// Adds a rule file to the YARA compiler.
  ///
  /// `include` statements resolve next to this file, and diagnostics name it.
  /// Like `addRuleSource()`, the addition is cheap: the rebuild happens when the
  /// rule set is next read or scanned.
  ///
  /// Ok(()) on success, or an error if reading or compilation fails
  #[napi]
  pub fn add_rule_file(
    &mut self,
    env: Env,
    file_path: String,
    namespace: Option<String>,
  ) -> Result<()> {
    let file_content = std::fs::read_to_string(&file_path)
      .map_err(|e| io_error_to_napi(e, &format!("reading file {file_path}"), Some(&env)))?;
    self.add_rule_sources_internal(
      env,
      vec![StoredRuleSource {
        source: RuleSource {
          source: file_content,
          namespace,
        },
        origin: Some(file_path),
      }],
    )
  }

  /// Defines a variable for the YARA compiler.
  ///
  /// The definition is checked here — the name must be one YARA-X accepts —
  /// rather than by the deferred rebuild: a global cannot be removed or renamed
  /// afterwards, so recording a name the compiler rejects would leave every
  /// later read meeting `invalid identifier` with nothing left to undo. A
  /// rejected call leaves the globals as they were, like a rejected addition.
  ///
  /// What is left to the rebuild is how the existing rules read the value, and
  /// that is recoverable: a type conflict reports `E003` on the next read, and
  /// redefining the same name with a matching type fixes the rule set.
  #[napi(ts_args_type = "name: string, value: string | number | boolean | bigint")]
  pub fn define_variable(&mut self, env: Env, name: String, value: Unknown) -> Result<()> {
    let value = variable_value_from_unknown(value, &name)?;

    // Staged so a rejected definition commits nothing. With no sources to add,
    // `validate_sources_standalone` applies the stored options and this
    // candidate global set and nothing else, which is where YARA-X rejects an
    // invalid identifier.
    let mut variables = self.variables.clone().unwrap_or_default();
    variables.insert(name, value);

    validate_sources_standalone(
      &self.stored_options,
      Some(&variables),
      self.ignore_invalid_rules,
      &[],
      &[],
      Some(&env),
    )?;

    self.variables = Some(variables);
    self.needs_rebuild.set(true);

    Ok(())
  }

  /// Scans multiple files concurrently across a Rayon worker thread pool.
  #[napi(
    ts_args_type = "filePaths: Array<string>, options?: BatchScanOptions | undefined | null, variables?: Record<string, string | number | boolean | bigint> | undefined | null",
    ts_return_type = "Promise<BatchScanResult>"
  )]
  pub fn scan_files(
    &self,
    env: Env,
    file_paths: Vec<String>,
    options: Option<BatchScanOptions>,
    variables: Option<Object>,
  ) -> Result<AsyncTask<BatchScanTask>> {
    let combined_vars = self.combine_variables(variables)?;
    let rules = self.current_rules(Some(&env))?;
    let scan_opts = self.task_scan_options(true);
    let batch_opts = options.unwrap_or_default();

    Ok(AsyncTask::new(BatchScanTask::new(
      rules,
      BatchScanTarget::Files(file_paths),
      scan_opts,
      combined_vars,
      batch_opts,
    )))
  }

  /// Scans multiple files synchronously across a Rayon worker thread pool.
  #[napi(
    ts_args_type = "filePaths: Array<string>, options?: BatchScanOptions | undefined | null, variables?: Record<string, string | number | boolean | bigint> | undefined | null"
  )]
  pub fn scan_files_sync(
    &self,
    env: Env,
    file_paths: Vec<String>,
    options: Option<BatchScanOptions>,
    variables: Option<Object>,
  ) -> Result<BatchScanResult<'static>> {
    let combined_vars = self.combine_variables(variables)?;
    let scan_opts = self.task_scan_options(true);
    let batch_opts = options.unwrap_or_default();
    let rules = self.current_rules(Some(&env))?;

    let output = execute_batch_scan(
      rules,
      file_paths,
      0,
      Vec::new(),
      scan_opts,
      combined_vars,
      batch_opts,
    )?;

    convert_batch_result(env, output)
  }

  /// Recursively scans a directory across a Rayon worker thread pool.
  #[napi(
    ts_args_type = "dirPath: string, options?: BatchScanOptions | undefined | null, variables?: Record<string, string | number | boolean | bigint> | undefined | null",
    ts_return_type = "Promise<BatchScanResult>"
  )]
  pub fn scan_directory(
    &self,
    env: Env,
    dir_path: String,
    options: Option<BatchScanOptions>,
    variables: Option<Object>,
  ) -> Result<AsyncTask<BatchScanTask>> {
    let combined_vars = self.combine_variables(variables)?;
    let rules = self.current_rules(Some(&env))?;
    let scan_opts = self.task_scan_options(true);
    let batch_opts = options.unwrap_or_default();

    Ok(AsyncTask::new(BatchScanTask::new(
      rules,
      BatchScanTarget::Directory(dir_path),
      scan_opts,
      combined_vars,
      batch_opts,
    )))
  }

  /// Recursively scans a directory synchronously across a Rayon worker thread pool.
  #[napi(
    ts_args_type = "dirPath: string, options?: BatchScanOptions | undefined | null, variables?: Record<string, string | number | boolean | bigint> | undefined | null"
  )]
  pub fn scan_directory_sync(
    &self,
    env: Env,
    dir_path: String,
    options: Option<BatchScanOptions>,
    variables: Option<Object>,
  ) -> Result<BatchScanResult<'static>> {
    let combined_vars = self.combine_variables(variables)?;
    let scan_opts = self.task_scan_options(true);
    let batch_opts = options.unwrap_or_default();

    let filter = PathFilter::new(
      batch_opts.include_patterns.as_deref(),
      batch_opts.exclude_patterns.as_deref(),
    )?;

    let (files, traversal_errors, filtered_files) = collect_directory_files(
      &dir_path,
      batch_opts.max_depth,
      batch_opts.follow_symlinks,
      batch_opts.min_file_size,
      batch_opts.max_file_size,
      &filter,
    )?;

    let rules = self.current_rules(Some(&env))?;

    let output = execute_batch_scan(
      rules,
      files,
      filtered_files,
      traversal_errors,
      scan_opts,
      combined_vars,
      batch_opts,
    )?;

    convert_batch_result(env, output)
  }
}
