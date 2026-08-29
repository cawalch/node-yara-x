//! YARA scanner implementation and utilities.
//!
//! This module contains the main YaraX struct and related functionality for
//! scanning data with compiled YARA rules, including scanner caching for performance.

use crate::compiler::{
  add_source_to_compiler_tolerant, apply_compiler_options, apply_stored_compiler_options,
  collect_ignored_rules, replay_sources_to_wasm, stored_options_from, StoredCompilerOptions,
};
use crate::error::{io_error_to_napi, scan_error_to_napi};
use crate::types::{
  CompilerError, CompilerOptions, CompilerWarning, IgnoredRule, MatchData, RuleMatch, RuleSource,
  VariableValue,
};
use crate::variables::{
  convert_variables_to_map, get_compiler_errors, get_compiler_warnings, VariableHandler,
};
use napi::bindgen_prelude::{AsyncTask, Buffer, JsObjectValue, Object};
use napi::{Env, Error, Result, Status};
use napi_derive::napi;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use yara_x::{Compiler, Rules, Scanner};

/// The main YARA-X scanner struct.
///
/// This struct represents compiled YARA rules and provides methods for scanning
/// data and files. It includes performance optimizations like scanner caching.
#[napi]
pub struct YaraX {
  /// The compiled YARA rules.
  pub(crate) rules: Arc<Rules>,
  /// The source code used to compile the YARA rules.
  pub(crate) source_code: Option<String>,
  /// The source code segments and namespaces used to compile the YARA rules.
  pub(crate) rule_sources: Vec<RuleSource>,
  /// Any warnings generated during the compilation process.
  pub(crate) warnings: Vec<CompilerWarning>,
  /// The variables defined for the YARA rules.
  pub(crate) variables: Option<HashMap<String, VariableValue>>,
  /// Rules that were skipped during compilation, with the reason for each.
  ///
  /// Populated when rules were skipped: either because `ignore_invalid_rules`
  /// was enabled and some rules failed to compile, or because rules depend on
  /// ignored modules.
  pub(crate) ignored_rules: Vec<IgnoredRule>,
  /// Whether rule compilation errors are tolerated (rules skipped and
  /// reported via `ignored_rules`) instead of aborting compilation.
  pub(crate) ignore_invalid_rules: bool,
  /// Errors generated while compiling the rules that could not be attributed
  /// to a single skipped rule (syntax errors, invalid UTF-8, banned or
  /// unknown module imports, include failures).
  ///
  /// Populated when compilation ran with `ignore_invalid_rules`; the errors
  /// are otherwise surfaced by aborting compilation. Mirrors the upstream
  /// Python binding's `Compiler.errors()`.
  pub(crate) compilation_errors: Vec<CompilerError>,
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
  pub(crate) cached_scanner: RefCell<Option<Scanner<'static>>>,
  /// Maximum number of matches per pattern
  pub(crate) max_matches_per_pattern: Option<usize>,
  /// Whether to use memory-mapped files for scanning
  pub(crate) use_mmap: Option<bool>,
  /// Scan timeout in milliseconds
  pub(crate) timeout_ms: Option<u32>,
  /// Match context size
  pub(crate) match_context_size: Option<usize>,
}

impl YaraX {
  /// Creates a new YaraX instance from a source string.
  ///
  /// # Arguments
  ///
  /// * `source` - The YARA rule source code
  /// * `options` - Optional compiler options
  ///
  /// # Returns
  ///
  /// A new YaraX instance with compiled rules
  pub fn create_scanner_from_source(
    source: String,
    options: Option<CompilerOptions>,
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
      ignore_invalid_rules,
    )?;

    let warnings = get_compiler_warnings(&compiler)?;
    // Rules can be skipped even without `ignore_invalid_rules` (e.g. when
    // they depend on ignored modules), so the report is collected
    // unconditionally. Compilation errors are only survivable in tolerant
    // mode (otherwise `add_source` aborts above), so collect them from the
    // compiler regardless and keep the ones that remain.
    let ignored_rules = collect_ignored_rules(&compiler);
    let compilation_errors = get_compiler_errors(&compiler)?;
    let rules = compiler.build();
    let rule_sources = vec![RuleSource {
      source: source.clone(),
      namespace: namespace.map(str::to_string),
    }];

    Ok(YaraX {
      rules: Arc::new(rules),
      source_code: Some(source),
      rule_sources,
      warnings,
      variables: stored_variables,
      ignored_rules,
      ignore_invalid_rules,
      compilation_errors,
      stored_options,
      cached_scanner: RefCell::new(None),
      max_matches_per_pattern: None,
      use_mmap: None,
      timeout_ms: None,
      match_context_size: None,
    })
  }

  /// Creates a meta object from a YARA rule.
  ///
  /// # Arguments
  ///
  /// * `env` - The N-API environment
  /// * `rule` - The YARA rule
  ///
  /// # Returns
  ///
  /// A JavaScript object containing the rule's metadata
  fn create_meta_object<'a>(env: napi::Env, rule: &yara_x::Rule) -> Result<Object<'a>> {
    let mut meta_obj = Object::new(&env)?;

    for (key, value) in rule.metadata() {
      let key_string = key.to_string();

      match value {
        yara_x::MetaValue::Integer(i) => {
          meta_obj.set_named_property(&key_string, i)?;
        }
        yara_x::MetaValue::Float(f) => {
          let float_val = f;
          meta_obj.set_named_property(&key_string, float_val)?;
        }
        yara_x::MetaValue::String(s) => {
          let string_val = s.to_string();
          meta_obj.set_named_property(&key_string, string_val)?;
        }
        yara_x::MetaValue::Bool(b) => {
          meta_obj.set_named_property(&key_string, b)?;
        }
        _ => {
          meta_obj.set_named_property(&key_string, "unknown")?;
        }
      }
    }

    Ok(meta_obj)
  }

  /// Extracts matches from a YARA rule.
  ///
  /// # Arguments
  ///
  /// * `rule` - The YARA rule
  /// # Returns
  ///
  /// A vector of MatchData structs
  fn extract_matches(rule: &yara_x::Rule) -> Vec<MatchData> {
    let total_matches: usize = rule.patterns().map(|pattern| pattern.matches().len()).sum();

    let mut matches_vec = Vec::with_capacity(total_matches);

    for pattern in rule.patterns() {
      let pattern_matches = pattern.matches();
      if pattern_matches.len() == 0 {
        continue;
      }

      let pattern_id = pattern.identifier().to_string();

      for match_item in pattern_matches {
        let range = match_item.range();
        let offset = range.start;
        let length = range.end - range.start;

        let matched_data = String::from_utf8_lossy(match_item.data()).into_owned();

        let (context_data_slice, context_range) = match_item.data_with_context();
        let has_context = context_data_slice.len() > match_item.data().len();

        let context_data = if has_context {
          Some(String::from_utf8_lossy(context_data_slice).into_owned())
        } else {
          None
        };

        let context_match_offset = if has_context {
          Some(context_range.start as u32)
        } else {
          None
        };

        matches_vec.push(MatchData {
          offset: offset as u32,
          length: length as u32,
          data: matched_data,
          identifier: pattern_id.clone(),
          context_data,
          context_match_offset,
        });
      }
    }

    matches_vec
  }

  /// Applies this scanner's stored compiler options and stored global
  /// variables to a compiler, then adds all rule sources in order.
  ///
  /// Variables are applied **before** the sources — yara-x requires globals
  /// to be defined before compiling the rules that reference them — mirroring
  /// [`create_scanner_from_source`](Self::create_scanner_from_source).
  fn compile_all_sources(&self, compiler: &mut Compiler<'_>) -> Result<()> {
    apply_stored_compiler_options(compiler, &self.stored_options)?;

    if let Some(vars) = &self.variables {
      for (key, value) in vars {
        compiler.apply_variable_value(key, value)?;
      }
    }

    for source in &self.rule_sources {
      add_source_to_compiler_tolerant(
        compiler,
        &source.source,
        source.namespace.as_deref(),
        self.ignore_invalid_rules,
      )?;
    }

    if self.rule_sources.is_empty() {
      let source = self.source_code.as_deref().unwrap_or_default();
      if !source.is_empty() {
        add_source_to_compiler_tolerant(compiler, source, None, self.ignore_invalid_rules)?;
      }
    }

    Ok(())
  }

  /// Consumes the compiler produced by a recompilation, refreshing the
  /// warnings, ignored-rules report and compilation errors, and publishing
  /// the rebuilt rules.
  fn refresh_compilation_state(&mut self, compiler: Compiler<'_>) -> Result<()> {
    self.warnings = get_compiler_warnings(&compiler)?;
    self.ignored_rules = collect_ignored_rules(&compiler);
    self.compilation_errors = get_compiler_errors(&compiler)?;
    self.rules = Arc::new(compiler.build());
    self.invalidate_scanner_cache();
    Ok(())
  }

  /// Rebuilds `source_code` from the current rule sources (used by WASM
  /// emission when replaying a concatenated source).
  fn rebuild_source_code(&mut self) {
    self.source_code = Some(
      self
        .rule_sources
        .iter()
        .map(|s| s.source.as_str())
        .collect::<Vec<_>>()
        .join("\n"),
    );
  }

  /// Returns the rule sources to compile, or falls back to `source_code` for
  /// scanners built incrementally without any recorded sources.
  fn sources_for_emit(&self) -> Vec<RuleSource> {
    if self.rule_sources.is_empty() {
      vec![RuleSource {
        source: self.source_code.clone().unwrap_or_default(),
        namespace: None,
      }]
    } else {
      self.rule_sources.clone()
    }
  }

  /// Gets or creates a cached scanner for reuse.
  ///
  /// This is a performance optimization that reuses scanner instances.
  ///
  /// # Returns
  ///
  /// A mutable reference to the cached scanner
  fn get_or_create_scanner(&self) -> Result<std::cell::RefMut<'_, Scanner<'static>>> {
    let mut cached = self.cached_scanner.borrow_mut();

    let needs_new_scanner = cached.is_none();

    if needs_new_scanner {
      // SAFETY: The transmute extends the borrow lifetime of `self.rules` to `'static`.
      // This is sound because `self.rules` is an `Arc<Rules>` that outlives the cached
      // scanner, and `invalidate_scanner_cache()` is called whenever `self.rules` is
      // replaced (in `add_rule_source`, `define_variable`, and option setters).
      let mut scanner = Scanner::new(unsafe {
        std::mem::transmute::<&yara_x::Rules, &yara_x::Rules>(&*self.rules)
      });

      // Apply scan options
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

      *cached = Some(scanner);
    }

    Ok(std::cell::RefMut::map(cached, |opt| opt.as_mut().unwrap()))
  }

  /// Invalidates the cached scanner, forcing recreation on next use.
  fn invalidate_scanner_cache(&self) {
    *self.cached_scanner.borrow_mut() = None;
  }

  /// Processes the scan results and returns a vector of RuleMatch.
  ///
  /// # Arguments
  ///
  /// * `results` - The scan results from YARA-X
  /// * `data` - The scanned data
  /// * `env` - The N-API environment
  ///
  /// # Returns
  ///
  /// A vector of RuleMatch structs
  pub fn process_scan_results<'a>(
    results: yara_x::ScanResults,
    env: napi::Env,
  ) -> Result<Vec<RuleMatch<'a>>> {
    let matching_rules = results.matching_rules();
    let rule_count = matching_rules.len();

    if rule_count == 0 {
      return Ok(Vec::new());
    }

    let mut rule_matches = Vec::with_capacity(rule_count);

    for rule in matching_rules {
      let matches_vec = Self::extract_matches(&rule);

      let tags: Vec<String> = rule
        .tags()
        .map(|tag| tag.identifier().to_string())
        .collect();

      let meta_obj = Self::create_meta_object(env, &rule)?;

      rule_matches.push(RuleMatch {
        rule_identifier: rule.identifier().to_string(),
        namespace: rule.namespace().to_string(),
        meta: meta_obj,
        tags,
        matches: matches_vec,
      });
    }

    Ok(rule_matches)
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
        .map(|(key, value)| {
          let v = match value {
            yara_x::MetaValue::Integer(i) => MetaValueData::Integer(i),
            yara_x::MetaValue::Float(f) => MetaValueData::Float(f),
            yara_x::MetaValue::String(s) => MetaValueData::String(s.to_string()),
            yara_x::MetaValue::Bool(b) => MetaValueData::Bool(b),
            _ => MetaValueData::String("unknown".to_string()),
          };
          (key.to_string(), v)
        })
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
          MetaValueData::String(s) => meta_obj.set_named_property(key, s.clone())?,
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
}

#[napi]
impl YaraX {
  /// Returns the compiler warnings generated during the compilation process.
  #[napi]
  pub fn get_warnings(&self) -> Vec<CompilerWarning> {
    self.warnings.clone()
  }

  /// Gets the rules that were skipped during compilation, if any.
  ///
  /// Rules are skipped when they depend on an ignored module (see
  /// `ignoreModules`), or when `ignore_invalid_rules: true` (see
  /// `CompilerOptions`) and they failed to compile. Each entry reports the
  /// rule name, the reason it was skipped (`ignored_module`, `ignored_rule`,
  /// or `compile_error`), and a detail string.
  ///
  /// # Returns
  ///
  /// A vector of `IgnoredRule` objects (empty when nothing was skipped)
  #[napi]
  pub fn get_ignored_rules(&self) -> Vec<IgnoredRule> {
    self.ignored_rules.clone()
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
  /// # Returns
  ///
  /// A vector of `CompilerError` objects (empty when no errors occurred)
  #[napi]
  pub fn get_compilation_errors(&self) -> Vec<CompilerError> {
    self.compilation_errors.clone()
  }

  /// Sets the maximum number of matches per pattern.
  ///
  /// # Arguments
  ///
  /// * `max_matches` - The maximum number of matches per pattern
  #[napi]
  pub fn set_max_matches_per_pattern(&mut self, max_matches: u32) {
    self.max_matches_per_pattern = Some(max_matches as usize);
    self.invalidate_scanner_cache();
  }

  /// Sets whether to use memory-mapped files for scanning.
  ///
  /// # Arguments
  ///
  /// * `use_mmap` - Whether to use memory-mapped files
  #[napi]
  pub fn set_use_mmap(&mut self, use_mmap: bool) {
    self.use_mmap = Some(use_mmap);
    self.invalidate_scanner_cache();
  }

  /// Sets the scan timeout in milliseconds.
  #[napi]
  pub fn set_timeout(&mut self, timeout_ms: u32) {
    self.timeout_ms = Some(timeout_ms);
    self.invalidate_scanner_cache();
  }

  /// Sets the match context size.
  #[napi]
  pub fn set_match_context_size(&mut self, size: u32) {
    self.match_context_size = Some(size as usize);
    self.invalidate_scanner_cache();
  }

  /// Scans the provided data using the compiled YARA rules.
  ///
  /// # Arguments
  ///
  /// * `env` - The N-API environment
  /// * `data` - The data to scan
  /// * `variables` - Optional variables to set for this scan
  ///
  /// # Returns
  ///
  /// A vector of matching rules
  #[napi(ts_args_type = "data: Buffer, variables?: Record<string, string | number | boolean>")]
  pub fn scan<'a>(
    &self,
    env: Env,
    data: Buffer,
    variables: Option<Object>,
  ) -> Result<Vec<RuleMatch<'a>>> {
    let mut scanner = self.get_or_create_scanner()?;

    scanner.apply_variables_from_map(&self.variables)?;
    scanner.apply_variables_from_object(&variables)?;

    let results = match scanner.scan(data.as_ref()) {
      Ok(r) => r,
      Err(e) => {
        drop(scanner);
        self.invalidate_scanner_cache();
        return Err(scan_error_to_napi(e));
      }
    };

    Self::process_scan_results(results, env)
  }

  /// Scans a file using the compiled YARA rules.
  ///
  /// # Arguments
  ///
  /// * `env` - The N-API environment
  /// * `file_path` - Path to the file to scan
  /// * `variables` - Optional variables to set for this scan
  ///
  /// # Returns
  ///
  /// A vector of matching rules
  #[napi(ts_args_type = "filePath: string, variables?: Record<string, string | number | boolean>")]
  pub fn scan_file<'a>(
    &self,
    env: Env,
    file_path: String,
    variables: Option<Object>,
  ) -> Result<Vec<RuleMatch<'a>>> {
    let mut scanner = self.get_or_create_scanner()?;

    scanner.apply_variables_from_map(&self.variables)?;
    scanner.apply_variables_from_object(&variables)?;

    let results = match scanner.scan_file(Path::new(&file_path)) {
      Ok(r) => r,
      Err(e) => {
        drop(scanner);
        self.invalidate_scanner_cache();
        return Err(scan_error_to_napi(e));
      }
    };

    Self::process_scan_results(results, env)
  }

  /// Emits a WASM file from the compiled YARA rules.
  ///
  /// # Arguments
  ///
  /// * `output_path` - Path where the WASM file should be written
  ///
  /// # Returns
  ///
  /// Ok(()) on success, or an error if emission fails
  #[napi]
  pub fn emit_wasm_file(&self, output_path: String) -> Result<()> {
    if self.source_code.is_none() {
      return Err(Error::new(
        Status::InvalidArg,
        "Cannot emit WASM file: source code not available",
      ));
    }

    let sources = self.sources_for_emit();

    // Replay the stored options and variables so the emitted module matches
    // the scanner's compilation semantics (including `ignore_invalid_rules`).
    replay_sources_to_wasm(
      &sources,
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
  ///
  /// # Returns
  ///
  /// A Buffer containing the serialized rules
  #[napi]
  pub fn serialize(&self) -> Result<Buffer> {
    let bytes = self.rules.serialize().map_err(|e| {
      Error::new(
        Status::GenericFailure,
        format!("Failed to serialize rules: {e}"),
      )
    })?;

    Ok(Buffer::from(bytes))
  }

  /// Scans the provided data asynchronously using the compiled YARA rules.
  ///
  /// # Arguments
  ///
  /// * `data` - The data to scan
  /// * `variables` - Optional variables to set for this scan
  ///
  /// # Returns
  ///
  /// An async task that resolves to a vector of matching rules
  #[napi(ts_return_type = "Promise<Array<RuleMatch>>")]
  pub fn scan_async(
    &self,
    data: Buffer,
    variables: Option<Object>,
  ) -> Result<AsyncTask<crate::tasks::ScanTask>> {
    let data_vec = data.to_vec();
    let vars_map = convert_variables_to_map(variables)?;

    Ok(AsyncTask::new(crate::tasks::ScanTask::new(
      self.rules.clone(),
      data_vec,
      vars_map,
      self.max_matches_per_pattern,
      self.timeout_ms,
      self.match_context_size,
    )))
  }

  /// Scans a file asynchronously using the compiled YARA rules.
  ///
  /// # Arguments
  ///
  /// * `file_path` - Path to the file to scan
  /// * `variables` - Optional variables to set for this scan
  ///
  /// # Returns
  ///
  /// An async task that resolves to a vector of matching rules
  #[napi(ts_return_type = "Promise<Array<RuleMatch>>")]
  pub fn scan_file_async(
    &self,
    file_path: String,
    variables: Option<Object>,
  ) -> Result<AsyncTask<crate::tasks::ScanFileTask>> {
    let vars_map = convert_variables_to_map(variables)?;

    Ok(AsyncTask::new(crate::tasks::ScanFileTask::new(
      self.rules.clone(),
      file_path,
      vars_map,
      self.max_matches_per_pattern,
      self.use_mmap,
      self.timeout_ms,
      self.match_context_size,
    )))
  }

  /// Emits a WASM file asynchronously from the compiled YARA rules.
  ///
  /// # Arguments
  ///
  /// * `output_path` - Path where the WASM file should be written
  ///
  /// # Returns
  ///
  /// An async task that completes when the WASM file is written
  #[napi]
  pub fn emit_wasm_file_async(
    &self,
    output_path: String,
  ) -> Result<AsyncTask<crate::tasks::EmitWasmFileTask>> {
    Ok(AsyncTask::new(crate::tasks::EmitWasmFileTask {
      source_code: self.source_code.clone(),
      rule_sources: self.rule_sources.clone(),
      output_path,
      stored_options: self.stored_options.clone(),
      variables: self.variables.clone(),
      ignore_invalid_rules: self.ignore_invalid_rules,
    }))
  }

  /// Adds a rule source to the YARA compiler.
  ///
  /// # Arguments
  ///
  /// * `rule_source` - The YARA rule source code to add
  ///
  /// # Returns
  ///
  /// Ok(()) on success, or an error if compilation fails
  ///
  /// # Performance Note
  ///
  /// This method recompiles all rules (existing + new) on each call, resulting
  /// in O(n) time per call and O(n²) total for n incremental additions.
  /// For better performance with many rules, use `compile()` with all sources
  /// at once, or use `add_rule_sources()` for batch addition.
  #[napi]
  pub fn add_rule_source(&mut self, rule_source: String, namespace: Option<String>) -> Result<()> {
    // Push directly to avoid cloning the entire rule_sources vector
    self.rule_sources.push(RuleSource {
      source: rule_source.clone(),
      namespace: namespace.clone(),
    });

    let mut compiler = Compiler::new();
    // Replay the stored options and variables (in the same order as the
    // original compilation) and recompile all sources in a single pass.
    self.compile_all_sources(&mut compiler)?;

    self.refresh_compilation_state(compiler)?;

    // Keep source_code in sync for WASM emission
    self.rebuild_source_code();

    Ok(())
  }

  /// Adds multiple rule sources to the YARA compiler in a single compilation pass.
  ///
  /// This is more efficient than calling `add_rule_source()` multiple times,
  /// as it compiles all sources in a single pass instead of recompiling
  /// existing rules for each addition.
  ///
  /// # Arguments
  ///
  /// * `rule_sources` - Vector of rule sources to add
  ///
  /// # Returns
  ///
  /// Ok(()) on success, or an error if compilation fails
  ///
  /// # Performance
  ///
  /// O(n + m) where n = existing rules, m = new rules (single compilation pass).
  /// Compared to calling `add_rule_source()` m times: O(n × m + m²).
  #[napi]
  pub fn add_rule_sources(&mut self, rule_sources: Vec<RuleSource>) -> Result<()> {
    if rule_sources.is_empty() {
      return Ok(());
    }

    // Extend our sources list with the new ones
    self.rule_sources.extend(rule_sources);

    let mut compiler = Compiler::new();
    // Replay the stored options and variables and recompile all sources in a
    // single pass.
    self.compile_all_sources(&mut compiler)?;

    self.refresh_compilation_state(compiler)?;

    // Keep source_code in sync for WASM emission
    self.rebuild_source_code();

    Ok(())
  }

  /// Adds a rule file to the YARA compiler.
  ///
  /// # Arguments
  ///
  /// * `file_path` - Path to the file containing YARA rules
  ///
  /// # Returns
  ///
  /// Ok(()) on success, or an error if reading or compilation fails
  #[napi]
  pub fn add_rule_file(&mut self, file_path: String, namespace: Option<String>) -> Result<()> {
    let file_content = std::fs::read_to_string(Path::new(&file_path))
      .map_err(|e| io_error_to_napi(e, &format!("reading file {file_path}")))?;
    self.add_rule_source(file_content, namespace)
  }

  /// Defines a variable for the YARA compiler.
  ///
  /// # Arguments
  ///
  /// * `name` - The variable name
  /// * `value` - The variable value
  ///
  /// # Returns
  ///
  /// Ok(()) on success, or an error if compilation fails
  #[napi]
  pub fn define_variable(&mut self, name: String, value: String) -> Result<()> {
    // Stage the variable in a local copy so `self.variables` is only updated
    // once the recompilation succeeds (the rules that reference the variable
    // must be compiled with it defined).
    let mut variables = self.variables.clone().unwrap_or_default();
    variables.insert(name.clone(), VariableValue::String(value.clone()));

    let mut compiler = Compiler::new();
    apply_stored_compiler_options(&mut compiler, &self.stored_options)?;

    for (key, value) in &variables {
      compiler.apply_variable_value(key, value)?;
    }

    for source in &self.rule_sources {
      add_source_to_compiler_tolerant(
        &mut compiler,
        &source.source,
        source.namespace.as_deref(),
        self.ignore_invalid_rules,
      )?;
    }

    if self.rule_sources.is_empty() {
      let source = self.source_code.as_deref().unwrap_or_default();
      if !source.is_empty() {
        add_source_to_compiler_tolerant(&mut compiler, source, None, self.ignore_invalid_rules)?;
      }
    }

    self.refresh_compilation_state(compiler)?;
    self.variables = Some(variables);

    Ok(())
  }
}
