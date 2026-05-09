//! YARA scanner implementation and utilities.
//!
//! This module contains the main YaraX struct and related functionality for
//! scanning data with compiled YARA rules, including scanner caching for performance.

use crate::compiler::{add_source_to_compiler, apply_compiler_options};
use crate::error::{io_error_to_napi, scan_error_to_napi};
use crate::types::{
  CompilerOptions, CompilerWarning, MatchData, RuleMatch, RuleSource, VariableValue,
};
use crate::variables::{convert_variables_to_map, get_compiler_warnings, VariableHandler};
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

    let stored_variables = apply_compiler_options(&mut compiler, options.as_ref(), true)?;
    let namespace = options.as_ref().and_then(|opts| opts.namespace.as_deref());

    add_source_to_compiler(&mut compiler, source.as_str(), namespace)?;

    let warnings = get_compiler_warnings(&compiler)?;
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
  pub fn extract_scan_data(
    results: yara_x::ScanResults,
  ) -> Vec<crate::types::RuleMatchData> {
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
    let source = self.source_code.as_ref().ok_or_else(|| {
      Error::new(
        Status::InvalidArg,
        "Cannot emit WASM file: source code not available",
      )
    })?;

    if self.rule_sources.is_empty() {
      crate::compiler::compile_source_to_wasm(source, &output_path, None)
    } else {
      crate::compiler::compile_sources_to_wasm(&self.rule_sources, &output_path, None)
    }
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
  #[napi]
  pub fn add_rule_source(&mut self, rule_source: String, namespace: Option<String>) -> Result<()> {
    let mut compiler = Compiler::new();

    let mut rule_sources = self.rule_sources.clone();
    rule_sources.push(RuleSource {
      source: rule_source.clone(),
      namespace: namespace.clone(),
    });

    if rule_sources.is_empty() {
      add_source_to_compiler(&mut compiler, rule_source.as_str(), namespace.as_deref())?;
    } else {
      for source in &rule_sources {
        add_source_to_compiler(&mut compiler, &source.source, source.namespace.as_deref())?;
      }
    }

    if let Some(vars) = &self.variables {
      for (key, value) in vars {
        compiler.apply_variable_value(key, value)?;
      }
    }

    self.rules = Arc::new(compiler.build());
    self.rule_sources = rule_sources;

    if let Some(source) = &mut self.source_code {
      source.reserve(rule_source.len() + 1);
      source.push('\n');
      source.push_str(&rule_source);
    } else {
      self.source_code = Some(rule_source);
    }

    self.invalidate_scanner_cache();

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
    let mut compiler = Compiler::new();

    for source in &self.rule_sources {
      add_source_to_compiler(&mut compiler, &source.source, source.namespace.as_deref())?;
    }

    if self.rule_sources.is_empty() {
      if let Some(source) = &self.source_code {
        if !source.is_empty() {
          add_source_to_compiler(&mut compiler, source.as_str(), None)?;
        }
      }
    }

    compiler.apply_variable(&name, &value)?;

    if let Some(vars) = &mut self.variables {
      vars.insert(name, VariableValue::String(value));
    } else {
      let mut vars = HashMap::new();
      vars.insert(name, VariableValue::String(value));
      self.variables = Some(vars);
    }

    let rules = compiler.build();
    self.rules = Arc::new(rules);

    self.invalidate_scanner_cache();

    Ok(())
  }
}
