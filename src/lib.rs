#![deny(clippy::all)]
use napi::bindgen_prelude::{AsyncTask, Buffer, Object};
use napi::{Env, Error, Result, Status, Task};
use napi_derive::napi;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Display;
use std::path::Path;
use std::sync::Arc;
use yara_x::errors::CompileError;
use yara_x::{Compiler, Rules, Scanner};

type VariableMap = HashMap<String, String>;

trait VariableHandler {
  fn apply_variable(&mut self, name: &str, value: &str) -> Result<()>;

  fn apply_variables_from_map(&mut self, variables: &Option<VariableMap>) -> Result<()> {
    if let Some(vars) = variables {
      for (key, value) in vars {
        self.apply_variable(key, value)?;
      }
    }
    Ok(())
  }

  fn apply_variables_from_object(&mut self, variables: &Option<Object>) -> Result<()> {
    if let Some(vars) = variables {
      let property_names = Object::keys(vars)?;

      let mut values = HashMap::with_capacity(property_names.len());

      for key in &property_names {
        if let Ok(value) = vars.get_named_property::<String>(key) {
          values.insert(key.clone(), value);
        }
      }

      for (key, value) in values {
        self.apply_variable(&key, &value)?;
      }
    }
    Ok(())
  }
}

impl<'a> VariableHandler for Scanner<'a> {
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

fn compile_error_to_napi(error: &CompileError) -> Error {
  Error::new(
    Status::GenericFailure,
    format!("Compilation error ({}): {}", error.code(), error),
  )
}

fn scan_error_to_napi(error: yara_x::ScanError) -> Error {
  match &error {
    yara_x::ScanError::Timeout => Error::new(Status::Cancelled, "Scan timed out"),
    yara_x::ScanError::OpenError { path, source } => Error::new(
      Status::GenericFailure,
      format!("Failed to open file '{}': {}", path.display(), source),
    ),
    yara_x::ScanError::MapError { path, source } => Error::new(
      Status::GenericFailure,
      format!("Failed to map file '{}': {}", path.display(), source),
    ),
    yara_x::ScanError::ProtoError { module, err } => Error::new(
      Status::GenericFailure,
      format!("Protobuf error in module '{}': {}", module, err),
    ),
    yara_x::ScanError::UnknownModule { module } => Error::new(
      Status::GenericFailure,
      format!("Unknown module: '{}'", module),
    ),
  }
}

fn io_error_to_napi(error: std::io::Error, context: &str) -> Error {
  Error::new(
    Status::GenericFailure,
    format!("I/O error ({}): {}", context, error),
  )
}

fn to_napi_err<E: std::fmt::Display>(err: E) -> Error {
  Error::new(Status::GenericFailure, err.to_string())
}

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

#[napi(object)]
pub struct MatchData {
  pub offset: u32,
  pub length: u32,
  pub data: String,
  pub identifier: String,
}

#[napi(object)]
pub struct RuleMatch {
  pub rule_identifier: String,
  pub namespace: String,
  pub meta: Object,
  pub tags: Vec<String>,
  pub matches: Vec<MatchData>,
}

#[napi(object)]
pub struct CompilerOptions {
  pub define_variables: Option<Object>,
  pub ignore_modules: Option<Vec<String>>,
  pub banned_modules: Option<Vec<BannedModule>>,
  pub features: Option<Vec<String>>,
  pub relaxed_re_syntax: Option<bool>,
  pub condition_optimization: Option<bool>,
  pub error_on_slow_pattern: Option<bool>,
  pub error_on_slow_loop: Option<bool>,
}

#[napi(object)]
pub struct BannedModule {
  pub name: String,
  pub error_title: String,
  pub error_message: String,
}

#[napi(object)]
#[derive(Serialize, Deserialize, Clone)]
pub struct CompilerWarning {
  pub code: String,
  pub message: String,
  pub source: Option<String>,
  pub line: Option<u32>,
  pub column: Option<u32>,
}

#[napi(object)]
#[derive(Serialize, Deserialize, Clone)]
pub struct CompilerError {
  pub code: String,
  pub message: String,
  pub source: Option<String>,
  pub line: Option<u32>,
  pub column: Option<u32>,
}

#[napi(object)]
#[derive(Serialize, Deserialize, Clone)]
pub struct CompileResult {
  pub warnings: Vec<CompilerWarning>,
  pub errors: Vec<CompilerError>,
}

#[napi]
pub struct YaraX {
  rules: Arc<Rules>,
  source_code: Option<String>,
  warnings: Vec<CompilerWarning>,
  variables: Option<HashMap<String, String>>,
}

impl YaraX {
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
        if !property_names.is_empty() && store_variables {
          stored_variables = Some(HashMap::with_capacity(property_names.len()));
        }

        for key in property_names {
          if let Ok(value) = vars.get_named_property::<String>(&key) {
            compiler.apply_variable(&key, &value)?;

            if let Some(var_map) = &mut stored_variables {
              var_map.insert(key, value);
            }
          }
        }
      }
    }

    Ok(stored_variables)
  }

  fn create_meta_object(env: napi::Env, rule: &yara_x::Rule) -> Result<Object> {
    let mut meta_obj = env.create_object()?;

    for (key, value) in rule.metadata() {
      let key_string = key.to_string();

      match value {
        yara_x::MetaValue::Integer(i) => {
          let int_val = i;
          meta_obj.set_named_property(&key_string, int_val)?;
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

  fn convert_variables_to_map(variables: Option<Object>) -> Result<Option<VariableMap>> {
    match variables {
      Some(vars) => {
        let property_names = Object::keys(&vars)?;
        if property_names.is_empty() {
          return Ok(None);
        }

        let mut map = HashMap::with_capacity(property_names.len());

        for key in property_names {
          if let Ok(value) = vars.get_named_property::<String>(&key) {
            map.insert(key, value);
          }
        }

        if map.is_empty() {
          Ok(None)
        } else {
          Ok(Some(map))
        }
      }
      None => Ok(None),
    }
  }

  fn create_scanner_from_source(source: String, options: Option<CompilerOptions>) -> Result<Self> {
    let mut compiler = Compiler::new();

    let stored_variables = Self::apply_compiler_options(&mut compiler, options.as_ref(), true)?;

    compiler
      .add_source(source.as_str())
      .map_err(|e| compile_error_to_napi(&e))?;

    let warnings = Self::get_compiler_warnings(&compiler)?;
    let rules = compiler.build();

    Ok(YaraX {
      rules: Arc::new(rules),
      source_code: Some(source),
      warnings,
      variables: stored_variables,
    })
  }

  fn extract_matches(rule: &yara_x::Rule, data: &[u8]) -> Vec<MatchData> {
    let mut total_matches = 0;
    for pattern in rule.patterns() {
      total_matches += pattern.matches().len();
    }

    let mut matches_vec = Vec::with_capacity(total_matches);

    for pattern in rule.patterns() {
      let pattern_matches = pattern.matches();
      if pattern_matches.len() == 0 {
        continue;
      }

      let pattern_id = pattern.identifier().to_string();

      for match_item in pattern_matches {
        let range = match_item.range();
        let offset = range.start as usize;
        let length = (range.end - range.start) as usize;

        if offset + length <= data.len() {
          let matched_bytes = &data[offset..offset + length];

          let matched_data = if matched_bytes.is_ascii() {
            unsafe { String::from_utf8_unchecked(matched_bytes.to_vec()) }
          } else {
            String::from_utf8_lossy(matched_bytes).to_string()
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

  fn process_scan_results(
    results: yara_x::ScanResults,
    data: &[u8],
    env: napi::Env,
  ) -> Result<Vec<RuleMatch>> {
    let matching_rules = results.matching_rules();
    let rule_count = matching_rules.len();

    let mut rule_matches = Vec::with_capacity(rule_count);

    for rule in matching_rules {
      let matches_vec = Self::extract_matches(&rule, data);

      let tag_count = rule.tags().len();
      let mut tags = Vec::with_capacity(tag_count);
      for tag in rule.tags() {
        tags.push(tag.identifier().to_string());
      }

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

  #[napi(ts_args_type = "data: Buffer, variables?: Record<string, string | number>")]
  pub fn scan(&self, env: Env, data: Buffer, variables: Option<Object>) -> Result<Vec<RuleMatch>> {
    let mut scanner = Scanner::new(&self.rules);

    scanner.apply_variables_from_map(&self.variables)?;

    scanner.apply_variables_from_object(&variables)?;

    let results = scanner.scan(data.as_ref()).map_err(scan_error_to_napi)?;

    Self::process_scan_results(results, data.as_ref(), env)
  }

  #[napi(ts_args_type = "filePath: string, variables?: Record<string, string | number>")]
  pub fn scan_file(
    &self,
    env: Env,
    file_path: String,
    variables: Option<Object>,
  ) -> Result<Vec<RuleMatch>> {
    let file_data = std::fs::read(&file_path)
      .map_err(|e| io_error_to_napi(e, &format!("reading file {}", file_path)))?;

    let mut scanner = Scanner::new(&self.rules);

    scanner.apply_variables_from_map(&self.variables)?;

    scanner.apply_variables_from_object(&variables)?;

    let results = scanner.scan(&file_data).map_err(scan_error_to_napi)?;

    Self::process_scan_results(results, &file_data, env)
  }

  #[napi]
  pub fn emit_wasm_file(&self, output_path: String) -> Result<()> {
    let source = self.source_code.as_ref().ok_or_else(|| {
      Error::new(
        Status::InvalidArg,
        "Cannot emit WASM file: source code not available",
      )
    })?;

    Self::compile_source_to_wasm(source, &output_path, None)
  }

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
          format!("Failed to emit WASM to {}: {}", output_path, e),
        )
      })?;

    Ok(())
  }

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

  #[napi]
  pub fn emit_wasm_file_async(&self, output_path: String) -> Result<AsyncTask<EmitWasmFileTask>> {
    Ok(AsyncTask::new(EmitWasmFileTask {
      source_code: self.source_code.clone(),
      output_path,
    }))
  }

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
      source.reserve(rule_source.len() + 1);
      source.push('\n');
      source.push_str(&rule_source);
    } else {
      self.source_code = Some(rule_source);
    }

    Ok(())
  }

  #[napi]
  pub fn add_rule_file(&mut self, file_path: String) -> Result<()> {
    let file_content = std::fs::read_to_string(Path::new(&file_path))
      .map_err(|e| io_error_to_napi(e, &format!("reading file {}", file_path)))?;
    self.add_rule_source(file_content)
  }

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

    Ok(())
  }
}

struct BaseYaraTask {
  rules: Arc<Rules>,
  variables: Option<VariableMap>,
}

impl BaseYaraTask {
  fn new(rules: Arc<Rules>, variables: Option<VariableMap>) -> Self {
    Self { rules, variables }
  }

  fn create_scanner(&self) -> Result<Scanner> {
    let mut scanner = Scanner::new(&self.rules);
    scanner.apply_variables_from_map(&self.variables)?;
    Ok(scanner)
  }

  fn process_results(&self, env: Env, data: &[u8]) -> Result<Vec<RuleMatch>> {
    let mut scanner = self.create_scanner()?;
    let results = scanner.scan(data).map_err(scan_error_to_napi)?;
    YaraX::process_scan_results(results, data, env)
  }
}

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
  type JsValue = Vec<RuleMatch>;

  fn compute(&mut self) -> Result<Self::Output> {
    Ok(std::mem::take(&mut self.data))
  }

  fn resolve(&mut self, env: napi::Env, data: Self::Output) -> Result<Self::JsValue> {
    self.base.process_results(env, &data)
  }
}

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
  type JsValue = Vec<RuleMatch>;

  fn compute(&mut self) -> Result<Self::Output> {
    std::fs::read(&self.file_path)
      .map_err(|e| io_error_to_napi(e, &format!("reading file {}", self.file_path)))
  }

  fn resolve(&mut self, env: napi::Env, data: Self::Output) -> Result<Self::JsValue> {
    self.base.process_results(env, &data)
  }
}

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

#[napi]
pub fn validate(rule_source: String, options: Option<CompilerOptions>) -> Result<CompileResult> {
  let mut compiler = Compiler::new();

  YaraX::apply_compiler_options(&mut compiler, options.as_ref(), false)?;

  let _ = compiler.add_source(rule_source.as_str());

  let warnings = YaraX::get_compiler_warnings(&compiler)?;
  let errors = YaraX::get_compiler_errors(&compiler)?;

  Ok(CompileResult { warnings, errors })
}

#[napi]
pub fn compile(rule_source: String, options: Option<CompilerOptions>) -> Result<YaraX> {
  let yarax = YaraX::create_scanner_from_source(rule_source, options)?;
  Ok(yarax)
}

#[napi]
pub fn create() -> YaraX {
  YaraX {
    rules: Arc::new(Compiler::new().build()),
    source_code: Some(String::new()),
    warnings: Vec::new(),
    variables: None,
  }
}

#[napi]
pub fn from_file(rule_path: String, options: Option<CompilerOptions>) -> Result<YaraX> {
  let file_content = std::fs::read_to_string(Path::new(&rule_path))
    .map_err(|e| io_error_to_napi(e, &format!("reading file {}", rule_path)))?;

  YaraX::create_scanner_from_source(file_content, options)
}

#[napi]
pub fn compile_to_wasm(
  rule_source: String,
  output_path: String,
  options: Option<CompilerOptions>,
) -> Result<()> {
  YaraX::compile_source_to_wasm(&rule_source, &output_path, options.as_ref())
}

#[napi]
pub fn compile_file_to_wasm(
  rule_path: String,
  output_path: String,
  options: Option<CompilerOptions>,
) -> Result<()> {
  let file_content = std::fs::read_to_string(Path::new(&rule_path))
    .map_err(|e| io_error_to_napi(e, &format!("reading file {}", rule_path)))?;
  YaraX::compile_source_to_wasm(&file_content, &output_path, options.as_ref())
}
