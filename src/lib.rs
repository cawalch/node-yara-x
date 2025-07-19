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
pub use napi::bindgen_prelude::{AsyncTask, Buffer, JsObjectValue, Object};
use napi::{Env, Error, Result, Status, Task};
use napi_derive::napi;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Display;
use std::path::Path;
use std::sync::Arc;
use std::cell::RefCell;
use yara_x::errors::CompileError;
use yara_x::{Compiler, Rules, Scanner};

// A map of variable names to their values.
type VariableMap = HashMap<String, String>;

trait VariableHandler {
  fn apply_variable(&mut self, name: &str, value: &str) -> Result<()>;

  /// Applies variables from a map to the handler.
  fn apply_variables_from_map(&mut self, variables: &Option<VariableMap>) -> Result<()> {
    if let Some(vars) = variables {
      for (key, value) in vars {
        self.apply_variable(key, value)?;
      }
    }
    Ok(())
  }

  /// Takes an optional object of variables and applies each variable to the handler.
  fn apply_variables_from_object(&mut self, variables: &Option<Object>) -> Result<()> {
    if let Some(vars) = variables {
      let property_names = Object::keys(vars)?;

      for key in &property_names {
        if let Ok(value) = vars.get_named_property::<String>(key) {
          self.apply_variable(key, &value)?;
        }
      }
    }
    Ok(())
  }
}

impl<'a> VariableHandler for Scanner<'a> {
  /// Applies a variable to the scanner.
  fn apply_variable(&mut self, name: &str, value: &str) -> Result<()> {
    let result = if value.eq_ignore_ascii_case("true") {
      self.set_global(name, true)
    } else if value.eq_ignore_ascii_case("false") {
      self.set_global(name, false)
    } else if let Ok(num) = value.parse::<i64>() {
      self.set_global(name, num)
    } else {
      self.set_global(name, value)
    };

    result.map(|_| ()).map_err(to_napi_err)
  }
}

impl<'a> VariableHandler for Compiler<'a> {
  /// Applies a variable to the compiler.
  fn apply_variable(&mut self, name: &str, value: &str) -> Result<()> {
    let result = if value.eq_ignore_ascii_case("true") {
      self.define_global(name, true)
    } else if value.eq_ignore_ascii_case("false") {
      self.define_global(name, false)
    } else if let Ok(num) = value.parse::<i64>() {
      self.define_global(name, num)
    } else {
      self.define_global(name, value)
    };

    result.map(|_| ()).map_err(to_napi_err)
  }
}

/// Error conversion functions
fn compile_error_to_napi(error: &CompileError) -> Error {
  Error::new(
    Status::GenericFailure,
    format!("Compilation error ({}): {}", error.code(), error),
  )
}

/// Converts a YARA scan error to a napi::Error
fn scan_error_to_napi(error: yara_x::ScanError) -> Error {
  match &error {
    yara_x::ScanError::Timeout => Error::new(Status::Cancelled, "Scan timed out"),
    yara_x::ScanError::OpenError { path, err } => Error::new(
      Status::GenericFailure,
      format!("Failed to open file '{}': {}", path.display(), err),
    ),
    yara_x::ScanError::MapError { path, err } => Error::new(
      Status::GenericFailure,
      format!("Failed to map file '{}': {}", path.display(), err),
    ),
    yara_x::ScanError::ProtoError { module, err } => Error::new(
      Status::GenericFailure,
      format!("Protobuf error in module '{module}': {err}"),
    ),
    yara_x::ScanError::UnknownModule { module } => Error::new(
      Status::GenericFailure,
      format!("Unknown module: '{module}'"),
    ),
    _ => Error::new(
      Status::GenericFailure,
      format!("Unknown scan error: {error:?}"),
    ),
  }
}

/// Converts an I/O error to a napi::Error
fn io_error_to_napi(error: std::io::Error, context: &str) -> Error {
  Error::new(
    Status::GenericFailure,
    format!("I/O error ({context}): {error}"),
  )
}

/// Converts a generic error message to a napi::Error
fn to_napi_err<E: std::fmt::Display>(err: E) -> Error {
  Error::new(Status::GenericFailure, err.to_string())
}

/// Converts a list of compiler messages to a vector of CompilerWarning or CompilerError
fn convert_compiler_messages<T, U>(messages: &[T], to_output: impl Fn(&T) -> U) -> Vec<U>
where
  T: Display,
{
  let mut result = Vec::with_capacity(messages.len());
  for msg in messages {
    result.push(to_output(msg));
  }
  result
}

/// MatchData struct represents a match found by a YARA rule.
#[napi(object)]
pub struct MatchData {
  /// The offset of the match in the scanned data.
  pub offset: u32,
  /// The length of the matched data.
  pub length: u32,
  /// The matched data as a string.
  pub data: String,
  /// The identifier of the pattern that matched.
  pub identifier: String,
}

/// RuleMatch struct represents a matching rule found during scanning.
#[napi(object)]
pub struct RuleMatch<'a> {
  /// The identifier of the rule that matched.
  pub rule_identifier: String,
  /// The namespace of the rule that matched.
  pub namespace: String,
  /// The metadata associated with the rule that matched.
  pub meta: Object<'a>,
  /// The tags associated with the rule that matched.
  pub tags: Vec<String>,
  /// The matches found by the rule.
  pub matches: Vec<MatchData>,
}

/// CompilerOptions struct represents the options for the YARA compiler.
#[napi(object)]
pub struct CompilerOptions<'a> {
  /// Defines global variables for the YARA rules.
  pub define_variables: Option<Object<'a>>,
  /// A list of module names to ignore during compilation.
  pub ignore_modules: Option<Vec<String>>,
  /// A list of banned modules that cannot be used in the YARA rules.
  pub banned_modules: Option<Vec<BannedModule>>,
  /// A list of features to enable for the YARA rules.
  pub features: Option<Vec<String>>,
  /// Whether to use relaxed regular expression syntax.
  pub relaxed_re_syntax: Option<bool>,
  /// Whether to optimize conditions in the YARA rules.
  pub condition_optimization: Option<bool>,
  /// Whether to raise an error on slow patterns.
  pub error_on_slow_pattern: Option<bool>,
  /// Whether to raise an error on slow loops.
  pub error_on_slow_loop: Option<bool>,
}

/// BannedModule struct represents a module that is banned from being used in YARA rules.
#[napi(object)]
pub struct BannedModule {
  /// The name of the banned module.
  pub name: String,
  /// The title of the error message if the module is used.
  pub error_title: String,
  /// The error message if the module is used.
  pub error_message: String,
}

/// CompilerWarning struct represents a warning generated by the YARA compiler.
#[napi(object)]
#[derive(Serialize, Deserialize, Clone)]
pub struct CompilerWarning {
  /// The code of the warning.
  pub code: String,
  /// The message of the warning.
  pub message: String,
  /// The source of the warning, if available.
  pub source: Option<String>,
  /// The line number where the warning occurred, if available.
  pub line: Option<u32>,
  /// The column number where the warning occurred, if available.
  pub column: Option<u32>,
}

/// CompilerError struct represents an error generated by the YARA compiler.
#[napi(object)]
#[derive(Serialize, Deserialize, Clone)]
pub struct CompilerError {
  /// The code of the error.
  pub code: String,
  /// The message of the error.
  pub message: String,
  /// The source of the error, if available.
  pub source: Option<String>,
  /// The line number where the error occurred, if available.
  pub line: Option<u32>,
  /// The column number where the error occurred, if available.
  pub column: Option<u32>,
}

/// CompileResult struct represents the result of compiling YARA rules.
#[napi(object)]
#[derive(Serialize, Deserialize, Clone)]
pub struct CompileResult {
  /// Any warnings generated during the compilation process.
  pub warnings: Vec<CompilerWarning>,
  /// Any errors generated during the compilation process.
  pub errors: Vec<CompilerError>,
}

/// YaraX struct represents the YARA rules and their associated data.
#[napi]
pub struct YaraX {
  /// The compiled YARA rules.
  rules: Arc<Rules>,
  /// The source code used to compile the YARA rules.
  source_code: Option<String>,
  /// Any warnings generated during the compilation process.
  warnings: Vec<CompilerWarning>,
  /// The variables defined for the YARA rules.
  variables: Option<HashMap<String, String>>,
  /// Cached scanner for reuse (thread-local, not Send/Sync safe)
  cached_scanner: RefCell<Option<Scanner<'static>>>,
}

impl YaraX {
  /// Applies compiler options to the YARA compiler.
  fn apply_compiler_options(
    compiler: &mut Compiler<'_>,
    options: Option<&CompilerOptions>,
    store_variables: bool,
  ) -> Result<Option<VariableMap>> {
    let mut stored_variables = None;

    if let Some(opts) = options {
      if let Some(ignored_modules) = &opts.ignore_modules {
        for module in ignored_modules {
          let _ = compiler.ignore_module(module);
        }
      }

      if let Some(banned_modules) = &opts.banned_modules {
        for banned in banned_modules {
          let _ = compiler.ban_module(&banned.name, &banned.error_title, &banned.error_message);
        }
      }

      if let Some(features) = &opts.features {
        for feature in features {
          let _ = compiler.enable_feature(feature);
        }
      }

      compiler
        .relaxed_re_syntax(opts.relaxed_re_syntax.unwrap_or(false))
        .condition_optimization(opts.condition_optimization.unwrap_or(false))
        .error_on_slow_pattern(opts.error_on_slow_pattern.unwrap_or(false))
        .error_on_slow_loop(opts.error_on_slow_loop.unwrap_or(false));

      if let Some(vars) = &opts.define_variables {
        let property_names = Object::keys(vars)?;
        if property_names.is_empty() {
          return Ok(stored_variables);
        }

        if store_variables {
          stored_variables = Some(HashMap::with_capacity(property_names.len()));
        }

        for key in &property_names {
          if let Ok(value) = vars.get_named_property::<String>(key) {
            compiler.apply_variable(key, &value)?;

            if let Some(var_map) = &mut stored_variables {
              var_map.insert(key.clone(), value);
            }
          }
        }
      }
    }

    Ok(stored_variables)
  }

  /// Creates a meta object from a YARA rule.
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
        _ => {
          meta_obj.set_named_property(&key_string, "unknown")?;
        }
      }
    }

    Ok(meta_obj)
  }

  /// Converts an optional object of variables to a VariableMap.
  fn convert_variables_to_map(variables: Option<Object>) -> Result<Option<VariableMap>> {
    let vars = match variables {
      Some(vars) => vars,
      None => return Ok(None),
    };

    let property_names = Object::keys(&vars)?;
    if property_names.is_empty() {
      return Ok(None);
    }

    let mut map = HashMap::with_capacity(property_names.len());

    let mut valid_entries = 0;
    for key in &property_names {
      if let Ok(value) = vars.get_named_property::<String>(key) {
        map.insert(key.clone(), value);
        valid_entries += 1;
      }
    }

    if valid_entries == 0 {
      Ok(None)
    } else {
      if valid_entries < property_names.len() / 2 {
        map.shrink_to_fit();
      }
      Ok(Some(map))
    }
  }

  /// Creates a new YaraX instance from a source string.
  fn create_scanner_from_source(source: String, options: Option<CompilerOptions>) -> Result<Self> {
    let mut compiler = Compiler::new();

    let stored_variables = Self::apply_compiler_options(&mut compiler, options.as_ref(), true)?;

    compiler
      .add_source(source.as_str())
      .map_err(|e| compile_error_to_napi(&e))?;

    let warnings = YaraX::get_compiler_warnings(&compiler)?;
    let rules = compiler.build();

    Ok(YaraX {
      rules: Arc::new(rules),
      source_code: Some(source),
      warnings,
      variables: stored_variables,
      cached_scanner: RefCell::new(None),
    })
  }

  /// Extracts matches from a YARA rule.
  fn extract_matches(rule: &yara_x::Rule, data: &[u8]) -> Vec<MatchData> {
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

        if let Some(matched_bytes) = data.get(offset..offset + length) {
          let matched_data = if matched_bytes.is_ascii() {
            unsafe { String::from_utf8_unchecked(matched_bytes.to_vec()) }
          } else {
            String::from_utf8_lossy(matched_bytes).into_owned()
          };

          matches_vec.push(MatchData {
            offset: offset as u32,
            length: length as u32,
            data: matched_data,
            identifier: pattern_id.clone(),
          });
        }
      }
    }

    matches_vec
  }

  /// Gets or creates a cached scanner for reuse.
  fn get_or_create_scanner(&self) -> Result<std::cell::RefMut<Scanner<'static>>> {
    let mut cached = self.cached_scanner.borrow_mut();

    let needs_new_scanner = cached.is_none();

    if needs_new_scanner {
      let scanner = Scanner::new(unsafe { std::mem::transmute::<&yara_x::Rules, &yara_x::Rules>(&*self.rules) });
      *cached = Some(scanner);
    }

    Ok(std::cell::RefMut::map(cached, |opt| opt.as_mut().unwrap()))
  }

  /// Invalidates the cached scanner, forcing recreation on next use.
  fn invalidate_scanner_cache(&self) {
    *self.cached_scanner.borrow_mut() = None;
  }



  /// Processes the scan results and returns a vector of RuleMatch.
  fn process_scan_results<'a>(
    results: yara_x::ScanResults,
    data: &[u8],
    env: napi::Env,
  ) -> Result<Vec<RuleMatch<'a>>> {
    let matching_rules = results.matching_rules();
    let rule_count = matching_rules.len();

    if rule_count == 0 {
      return Ok(Vec::new());
    }

    let mut rule_matches = Vec::with_capacity(rule_count);

    for rule in matching_rules {
      let matches_vec = Self::extract_matches(&rule, data);

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
}

#[napi]
impl YaraX {
  /// Returns the compiler errors generated during the compilation process.
  fn get_compiler_errors(compiler: &Compiler) -> Result<Vec<CompilerError>> {
    let errors = compiler.errors();

    let result = convert_compiler_messages(errors, |e| CompilerError {
      code: e.code().to_string(),
      message: e.to_string(),
      source: None,
      line: None,
      column: None,
    });

    Ok(result)
  }

  /// Returns the compiler warnings generated during the compilation process.
  fn get_compiler_warnings(compiler: &Compiler) -> Result<Vec<CompilerWarning>> {
    let warnings = compiler.warnings();

    let result = convert_compiler_messages(warnings, |w| CompilerWarning {
      code: w.code().to_string(),
      message: w.to_string(),
      source: None,
      line: None,
      column: None,
    });

    Ok(result)
  }

  #[napi]
  pub fn get_warnings(&self) -> Vec<CompilerWarning> {
    self.warnings.clone()
  }

  /// Scans the provided data using the compiled YARA rules.
  #[napi(ts_args_type = "data: Buffer, variables?: Record<string, string | number>")]
  pub fn scan<'a>(
    &self,
    env: Env,
    data: Buffer,
    variables: Option<Object>,
  ) -> Result<Vec<RuleMatch<'a>>> {
    let mut scanner = self.get_or_create_scanner()?;

    scanner.apply_variables_from_map(&self.variables)?;
    scanner.apply_variables_from_object(&variables)?;

    let results = scanner.scan(data.as_ref()).map_err(|e| {
      self.invalidate_scanner_cache();
      scan_error_to_napi(e)
    })?;

    Self::process_scan_results(results, data.as_ref(), env)
  }

  /// Scans a file using the compiled YARA rules.
  #[napi(ts_args_type = "filePath: string, variables?: Record<string, string | number>")]
  pub fn scan_file<'a>(
    &self,
    env: Env,
    file_path: String,
    variables: Option<Object>,
  ) -> Result<Vec<RuleMatch<'a>>> {
    let file_data = std::fs::read(&file_path)
      .map_err(|e| io_error_to_napi(e, &format!("reading file {file_path}")))?;

    let mut scanner = self.get_or_create_scanner()?;

    scanner.apply_variables_from_map(&self.variables)?;
    scanner.apply_variables_from_object(&variables)?;

    let results = scanner.scan(&file_data).map_err(|e| {
      self.invalidate_scanner_cache();
      scan_error_to_napi(e)
    })?;

    Self::process_scan_results(results, &file_data, env)
  }



  /// Emits a WASM file from the compiled YARA rules.
  #[napi]
  pub fn emit_wasm_file(&self, output_path: String) -> Result<()> {
    let source = self.source_code.as_ref().ok_or_else(|| {
      Error::new(
        Status::InvalidArg,
        "Cannot emit WASM file: source code not available",
      )
    })?;

    YaraX::compile_source_to_wasm(source, &output_path, None)
  }

  /// Compiles a source string to a WASM file.
  fn compile_source_to_wasm(
    source: &str,
    output_path: &str,
    options: Option<&CompilerOptions>,
  ) -> Result<()> {
    let mut compiler = Compiler::new();

    Self::apply_compiler_options(&mut compiler, options, false)?;

    compiler
      .add_source(source)
      .map_err(|e| compile_error_to_napi(&e))?;

    compiler
      .emit_wasm_file(Path::new(output_path))
      .map_err(|e| {
        Error::new(
          Status::GenericFailure,
          format!("Failed to emit WASM to {output_path}: {e}"),
        )
      })?;

    Ok(())
  }

  /// Scans the provided data asynchronously using the compiled YARA rules.
  #[napi]
  pub fn scan_async(&self, data: Buffer, variables: Option<Object>) -> Result<AsyncTask<ScanTask>> {
    let data_vec = data.to_vec();
    let vars_map = Self::convert_variables_to_map(variables)?;

    Ok(AsyncTask::new(ScanTask::new(
      self.rules.clone(),
      data_vec,
      vars_map,
    )))
  }

  /// Scans a file asynchronously using the compiled YARA rules.
  #[napi]
  pub fn scan_file_async(
    &self,
    file_path: String,
    variables: Option<Object>,
  ) -> Result<AsyncTask<ScanFileTask>> {
    let vars_map = Self::convert_variables_to_map(variables)?;

    Ok(AsyncTask::new(ScanFileTask::new(
      self.rules.clone(),
      file_path,
      vars_map,
    )))
  }

  /// Emits a WASM file asynchronously from the compiled YARA rules.
  #[napi]
  pub fn emit_wasm_file_async(&self, output_path: String) -> Result<AsyncTask<EmitWasmFileTask>> {
    Ok(AsyncTask::new(EmitWasmFileTask {
      source_code: self.source_code.clone(),
      output_path,
    }))
  }

  /// Adds a rule source to the YARA compiler.
  #[napi]
  pub fn add_rule_source(&mut self, rule_source: String) -> Result<()> {
    let mut compiler = Compiler::new();

    compiler
      .add_source(rule_source.as_str())
      .map_err(|e| compile_error_to_napi(&e))?;

    if let Some(existing_source) = &self.source_code {
      compiler
        .add_source(existing_source.as_str())
        .map_err(|e| compile_error_to_napi(&e))?;
    }

    if let Some(vars) = &self.variables {
      for (key, value) in vars {
        compiler.apply_variable(key, value)?;
      }
    }

    self.rules = Arc::new(compiler.build());

    if let Some(source) = &mut self.source_code {
      let new_capacity = source.len() + rule_source.len() + 1;
      source.reserve(new_capacity);
      source.push('\n');
      source.push_str(&rule_source);
    } else {
      self.source_code = Some(rule_source);
    }

    self.invalidate_scanner_cache();

    Ok(())
  }

  /// Adds a rule file to the YARA compiler.
  #[napi]
  pub fn add_rule_file(&mut self, file_path: String) -> Result<()> {
    let file_content = std::fs::read_to_string(Path::new(&file_path))
      .map_err(|e| io_error_to_napi(e, &format!("reading file {file_path}")))?;
    self.add_rule_source(file_content)
  }

  /// Defines a variable for the YARA compiler.
  #[napi]
  pub fn define_variable(&mut self, name: String, value: String) -> Result<()> {
    let mut compiler = Compiler::new();

    if let Some(source) = &self.source_code {
      if !source.is_empty() {
        compiler
          .add_source(source.as_str())
          .map_err(|e| compile_error_to_napi(&e))?;
      }
    }

    compiler.apply_variable(&name, &value)?;

    if let Some(vars) = &mut self.variables {
      vars.insert(name, value);
    } else {
      let mut vars = HashMap::new();
      vars.insert(name, value);
      self.variables = Some(vars);
    }

    let rules = compiler.build();
    self.rules = Arc::new(rules);

    self.invalidate_scanner_cache();

    Ok(())
  }
}

/// BaseYaraTask struct represents a base task for YARA scanning.
struct BaseYaraTask {
  rules: Arc<Rules>,
  variables: Option<VariableMap>,
}

impl BaseYaraTask {
  fn new(rules: Arc<Rules>, variables: Option<VariableMap>) -> Self {
    Self { rules, variables }
  }

  /// Creates a new scanner with the compiled YARA rules and applies any defined variables.
  fn create_scanner(&self) -> Result<Scanner> {
    let mut scanner = Scanner::new(&self.rules);
    scanner.apply_variables_from_map(&self.variables)?;
    Ok(scanner)
  }

  /// Processes the scan results and returns a vector of RuleMatch.
  fn process_results<'a>(&self, env: Env, data: &[u8]) -> Result<Vec<RuleMatch<'a>>> {
    let mut scanner = self.create_scanner()?;
    let results = scanner.scan(data).map_err(scan_error_to_napi)?;
    YaraX::process_scan_results(results, data, env)
  }
}

/// ScanTask struct represents a task for scanning data with YARA rules.
pub struct ScanTask {
  base: BaseYaraTask,
  data: Vec<u8>,
}

impl ScanTask {
  fn new(rules: Arc<Rules>, data: Vec<u8>, variables: Option<VariableMap>) -> Self {
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

/// ScanFileTask struct represents a task for scanning a file with YARA rules.
pub struct ScanFileTask {
  base: BaseYaraTask,
  file_path: String,
}

impl ScanFileTask {
  fn new(rules: Arc<Rules>, file_path: String, variables: Option<VariableMap>) -> Self {
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

/// EmitWasmFileTask struct represents a task for emitting a WASM file from YARA rules.
pub struct EmitWasmFileTask {
  source_code: Option<String>,
  output_path: String,
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

    YaraX::compile_source_to_wasm(source, &self.output_path, None)?;
    Ok(())
  }

  fn resolve(&mut self, _env: napi::Env, _output: Self::Output) -> Result<Self::JsValue> {
    Ok(())
  }
}

/// Compiles a YARA rule source string and returns any warnings or errors generated during the
/// compilation process.
#[napi]
pub fn validate(rule_source: String, options: Option<CompilerOptions>) -> Result<CompileResult> {
  let mut compiler = Compiler::new();

  YaraX::apply_compiler_options(&mut compiler, options.as_ref(), false)?;

  let _ = compiler.add_source(rule_source.as_str());

  let warnings = YaraX::get_compiler_warnings(&compiler)?;
  let errors = YaraX::get_compiler_errors(&compiler)?;

  Ok(CompileResult { warnings, errors })
}

/// Compiles a YARA rule source string and returns a YaraX instance with the compiled rules.
#[napi]
pub fn compile(rule_source: String, options: Option<CompilerOptions>) -> Result<YaraX> {
  let yarax = YaraX::create_scanner_from_source(rule_source, options)?;
  Ok(yarax)
}

/// Creates a new YaraX instance with empty rules and no source code.
#[napi]
pub fn create() -> YaraX {
  YaraX {
    rules: Arc::new(Compiler::new().build()),
    source_code: Some(String::new()),
    warnings: Vec::new(),
    variables: None,
    cached_scanner: RefCell::new(None),
  }
}

/// Creates a new YaraX instance from a file containing YARA rules.
#[napi]
pub fn from_file(rule_path: String, options: Option<CompilerOptions>) -> Result<YaraX> {
  let file_content = std::fs::read_to_string(Path::new(&rule_path))
    .map_err(|e| io_error_to_napi(e, &format!("reading file {rule_path}")))?;

  YaraX::create_scanner_from_source(file_content, options)
}

/// Compiles a YARA rule source string to a WASM file.
#[napi]
pub fn compile_to_wasm(
  rule_source: String,
  output_path: String,
  options: Option<CompilerOptions>,
) -> Result<()> {
  YaraX::compile_source_to_wasm(&rule_source, &output_path, options.as_ref())
}

/// Compiles a YARA rule file to a WASM file.
#[napi]
pub fn compile_file_to_wasm(
  rule_path: String,
  output_path: String,
  options: Option<CompilerOptions>,
) -> Result<()> {
  let file_content = std::fs::read_to_string(Path::new(&rule_path))
    .map_err(|e| io_error_to_napi(e, &format!("reading file {rule_path}")))?;
  YaraX::compile_source_to_wasm(&file_content, &output_path, options.as_ref())
}
