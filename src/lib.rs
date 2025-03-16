#![deny(clippy::all)]

use napi::bindgen_prelude::{AsyncTask, Buffer, Object};
use napi::{Error, Result, Status, Task};
use napi_derive::napi;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use yara_x::{Compiler, Rules, Scanner};

type VariableMap = HashMap<String, String>;

fn to_napi_err<E: std::fmt::Display>(err: E) -> Error {
  Error::new(Status::GenericFailure, err.to_string())
}

#[napi(object)]
pub struct MatchData {
  pub offset: u32,
  pub length: u32,
  pub data: String,
}

#[napi(object)]
pub struct RuleMatch {
  pub rule_identifier: String,
  pub matches: Vec<MatchData>,
}

#[napi(object)]
pub struct CompilerOptions {
  pub define_variables: Option<Object>,
}

#[napi]
pub struct YaraScanner {
  rules: Arc<Rules>,
  source_code: Option<String>,
}

impl YaraScanner {
  fn apply_compiler_options(
    compiler: &mut Compiler,
    options: Option<&CompilerOptions>,
  ) -> Result<()> {
    if let Some(opts) = options {
      if let Some(variables) = &opts.define_variables {
        Self::apply_variables_to_compiler(compiler, variables)?;
      }
    }
    Ok(())
  }

  fn apply_variables_to_compiler(compiler: &mut Compiler, variables: &Object) -> Result<()> {
    let property_names = Object::keys(variables)?;
    for key in property_names {
      let value: String = variables.get_named_property(&key)?;

      if let Ok(num) = value.parse::<i64>() {
        compiler.define_global(&key, num).map_err(to_napi_err)?;
      } else {
        compiler
          .define_global(&key, value.as_str())
          .map_err(to_napi_err)?;
      }
    }
    Ok(())
  }

  fn apply_variables_to_scanner(scanner: &mut Scanner, variables: &Object) -> Result<()> {
    let property_names = Object::keys(variables)?;
    for key in property_names {
      let value: String = variables.get_named_property(&key)?;

      if let Ok(num) = value.parse::<i64>() {
        scanner.set_global(&key, num).map_err(to_napi_err)?;
      } else {
        scanner
          .set_global(&key, value.as_str())
          .map_err(to_napi_err)?;
      }
    }
    Ok(())
  }

  fn convert_variables_to_map(variables: Option<Object>) -> Result<Option<VariableMap>> {
    if let Some(vars) = variables {
      let mut map = HashMap::new();
      let property_names = Object::keys(&vars).unwrap_or_default();

      for key in property_names {
        if let Ok(value) = vars.get_named_property::<String>(&key) {
          map.insert(key, value);
        }
      }

      Ok(Some(map))
    } else {
      Ok(None)
    }
  }

  fn extract_matches(rule: &yara_x::Rule, data: &[u8]) -> Vec<MatchData> {
    let mut matches_vec = Vec::new();

    for pattern in rule.patterns() {
      for match_item in pattern.matches() {
        let range = match_item.range();
        let offset = range.start as usize;
        let length = (range.end - range.start) as usize;

        if offset + length <= data.len() {
          let matched_bytes = &data[offset..offset + length];
          let matched_data = String::from_utf8_lossy(matched_bytes).to_string();

          matches_vec.push(MatchData {
            offset: offset as u32,
            length: length as u32,
            data: matched_data,
          });
        }
      }
    }

    matches_vec
  }

  fn process_scan_results(results: yara_x::ScanResults, data: &[u8]) -> Vec<RuleMatch> {
    let mut rule_matches = Vec::new();

    for rule in results.matching_rules() {
      let matches_vec = Self::extract_matches(&rule, data);

      rule_matches.push(RuleMatch {
        rule_identifier: rule.identifier().to_string(),
        matches: matches_vec,
      });
    }

    rule_matches
  }
}

#[napi]
impl YaraScanner {
  #[napi(constructor)]
  pub fn new(rule_source: String, options: Option<CompilerOptions>) -> Result<Self> {
    let mut compiler = Compiler::new();

    Self::apply_compiler_options(&mut compiler, options.as_ref())?;

    compiler
      .add_source(rule_source.as_str())
      .map_err(to_napi_err)?;

    let rules = compiler.build();

    Ok(YaraScanner {
      rules: Arc::new(rules),
      source_code: Some(rule_source),
    })
  }

  #[napi]
  pub fn from_file(rule_path: String, options: Option<CompilerOptions>) -> Result<Self> {
    let mut compiler = Compiler::new();

    Self::apply_compiler_options(&mut compiler, options.as_ref())?;

    let file_content = std::fs::read_to_string(Path::new(&rule_path)).map_err(to_napi_err)?;

    compiler
      .add_source(file_content.as_str())
      .map_err(to_napi_err)?;

    let rules = compiler.build();

    Ok(YaraScanner {
      rules: Arc::new(rules),
      source_code: Some(file_content),
    })
  }

  #[napi]
  pub fn scan(&self, data: Buffer, variables: Option<Object>) -> Result<Vec<RuleMatch>> {
    let mut scanner = Scanner::new(&self.rules);

    if let Some(vars) = &variables {
      Self::apply_variables_to_scanner(&mut scanner, vars)?;
    }

    let results = scanner.scan(data.as_ref()).map_err(to_napi_err)?;

    Ok(Self::process_scan_results(results, data.as_ref()))
  }

  #[napi]
  pub fn scan_file(&self, file_path: String) -> Result<Vec<RuleMatch>> {
    let file_data = std::fs::read(&file_path).map_err(to_napi_err)?;
    let mut scanner = Scanner::new(&self.rules);

    let results = scanner.scan(&file_data).map_err(to_napi_err)?;

    Ok(Self::process_scan_results(results, &file_data))
  }

  #[napi]
  pub fn emit_wasm_file(&self, output_path: String) -> Result<()> {
    let source = self.source_code.as_ref().ok_or_else(|| {
      Error::new(
        Status::GenericFailure,
        "Cannot emit WASM file: source code not available",
      )
    })?;

    let mut compiler = Compiler::new();

    compiler.add_source(source.as_str()).map_err(to_napi_err)?;
    compiler
      .emit_wasm_file(Path::new(&output_path))
      .map_err(to_napi_err)?;

    Ok(())
  }

  #[napi]
  pub fn compile_to_wasm(
    rule_source: String,
    output_path: String,
    options: Option<CompilerOptions>,
  ) -> Result<()> {
    let mut compiler = Compiler::new();

    Self::apply_compiler_options(&mut compiler, options.as_ref())?;

    compiler
      .add_source(rule_source.as_str())
      .map_err(to_napi_err)?;
    compiler
      .emit_wasm_file(Path::new(&output_path))
      .map_err(to_napi_err)?;

    Ok(())
  }

  #[napi]
  pub fn compile_file_to_wasm(
    rule_path: String,
    output_path: String,
    options: Option<CompilerOptions>,
  ) -> Result<()> {
    let mut compiler = Compiler::new();

    Self::apply_compiler_options(&mut compiler, options.as_ref())?;

    let file_content = std::fs::read_to_string(Path::new(&rule_path)).map_err(to_napi_err)?;

    compiler
      .add_source(file_content.as_str())
      .map_err(to_napi_err)?;
    compiler
      .emit_wasm_file(Path::new(&output_path))
      .map_err(to_napi_err)?;

    Ok(())
  }

  #[napi]
  pub fn scan_async(&self, data: Buffer, variables: Option<Object>) -> Result<AsyncTask<ScanTask>> {
    let data_vec = data.as_ref().to_vec();
    let vars_map = Self::convert_variables_to_map(variables)?;

    Ok(AsyncTask::new(ScanTask {
      rules: self.rules.clone(),
      data: data_vec,
      variables: vars_map,
    }))
  }

  #[napi]
  pub fn scan_file_async(
    &self,
    file_path: String,
    variables: Option<Object>,
  ) -> Result<AsyncTask<ScanFileTask>> {
    let vars_map = Self::convert_variables_to_map(variables)?;

    Ok(AsyncTask::new(ScanFileTask {
      rules: self.rules.clone(),
      file_path,
      variables: vars_map,
    }))
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
      .map_err(to_napi_err)?;

    if let Some(existing_source) = &self.source_code {
      compiler
        .add_source(existing_source.as_str())
        .map_err(to_napi_err)?;
    }

    let rules = compiler.build();

    self.rules = Arc::new(rules);

    match &mut self.source_code {
      Some(source) => {
        source.push_str("\n");
        source.push_str(&rule_source);
      }
      None => {
        self.source_code = Some(rule_source);
      }
    }

    Ok(())
  }

  #[napi]
  pub fn add_rule_file(&mut self, file_path: String) -> Result<()> {
    let file_content = std::fs::read_to_string(Path::new(&file_path)).map_err(to_napi_err)?;

    self.add_rule_source(file_content)
  }

  #[napi]
  pub fn create_with_options() -> Self {
    YaraScanner {
      rules: Arc::new(Compiler::new().build()),
      source_code: Some(String::new()),
    }
  }

  #[napi]
  pub fn define_variable(&mut self, name: String, value: String) -> Result<()> {
    let mut compiler = Compiler::new();

    if let Some(source) = &self.source_code {
      if !source.is_empty() {
        compiler.add_source(source.as_str()).map_err(to_napi_err)?;
      }
    }

    if let Ok(num) = value.parse::<i64>() {
      compiler.define_global(&name, num).map_err(to_napi_err)?;
    } else {
      compiler
        .define_global(&name, value.as_str())
        .map_err(to_napi_err)?;
    }

    let rules = compiler.build();

    self.rules = Arc::new(rules);

    Ok(())
  }
}

trait ApplyVariables {
  fn apply_variables(&mut self, variables: &Option<VariableMap>) -> Result<()>;
}

impl ApplyVariables for Scanner<'_> {
  fn apply_variables(&mut self, variables: &Option<VariableMap>) -> Result<()> {
    if let Some(vars) = variables {
      for (key, value) in vars {
        if let Ok(num) = value.parse::<i64>() {
          self.set_global(key, num).map_err(to_napi_err)?;
        } else {
          self.set_global(key, value.as_str()).map_err(to_napi_err)?;
        }
      }
    }
    Ok(())
  }
}

pub struct ScanTask {
  rules: Arc<Rules>,
  data: Vec<u8>,
  variables: Option<VariableMap>,
}

impl Task for ScanTask {
  type Output = Vec<RuleMatch>;
  type JsValue = Vec<RuleMatch>;

  fn compute(&mut self) -> Result<Self::Output> {
    let mut scanner = Scanner::new(&self.rules);
    scanner.apply_variables(&self.variables)?;

    let results = scanner.scan(&self.data).map_err(to_napi_err)?;

    Ok(YaraScanner::process_scan_results(results, &self.data))
  }

  fn resolve(&mut self, _env: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}

pub struct ScanFileTask {
  rules: Arc<Rules>,
  file_path: String,
  variables: Option<VariableMap>,
}

impl Task for ScanFileTask {
  type Output = Vec<RuleMatch>;
  type JsValue = Vec<RuleMatch>;

  fn compute(&mut self) -> Result<Self::Output> {
    let file_data = std::fs::read(&self.file_path).map_err(to_napi_err)?;

    let mut scanner = Scanner::new(&self.rules);
    scanner.apply_variables(&self.variables)?;

    let results = scanner.scan(&file_data).map_err(to_napi_err)?;

    Ok(YaraScanner::process_scan_results(results, &file_data))
  }

  fn resolve(&mut self, _env: napi::Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
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
        Status::GenericFailure,
        "Cannot emit WASM file: source code not available",
      )
    })?;

    let mut compiler = Compiler::new();

    compiler.add_source(source.as_str()).map_err(to_napi_err)?;
    compiler
      .emit_wasm_file(Path::new(&self.output_path))
      .map_err(to_napi_err)?;

    Ok(())
  }

  fn resolve(&mut self, _env: napi::Env, _output: Self::Output) -> Result<Self::JsValue> {
    Ok(())
  }
}
