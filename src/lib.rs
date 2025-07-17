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

// A map of variable names to their values.
type VariableMap = HashMap<String, String>;

trait VariableHandler {
  fn apply_variable(&mut self, name: &str, value: &str) -> Result<()>;

  /// Applies variables from a map to the handler.
  /// This function takes an optional map of variables and applies each variable to the handler.
  fn apply_variables_from_map(&mut self, variables: &Option<VariableMap>) -> Result<()> {
    if let Some(vars) = variables {
      for (key, value) in vars {
        self.apply_variable(key, value)?;
      }
    }
    Ok(())
  }

  /// Takes an optional object of variables and applies each variable to the handler.
  /// This function is useful for applying variables defined in JavaScript to the YARA compiler or
  /// scanner.
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
  /// This function takes a variable name and value, and sets the variable in the scanner.
  fn apply_variable(&mut self, name: &str, value: &str) -> Result<()> {
    // This allows for flexible variable types to be used in YARA rules.
    // For example, you can use boolean values, numbers, or strings as variables in your YARA
    // rules.
    // This is useful for defining dynamic variables that can change based on the data being
    // scanned
    // or the context of the scan.
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
  /// This function takes a variable name and value, and sets the variable in the compiler.
  fn apply_variable(&mut self, name: &str, value: &str) -> Result<()> {
    // This allows for flexible variable types to be used in YARA rules.
    // For example, you can use boolean values, numbers, or strings as variables in your YARA
    // Note the difference in the function name: `set_global` vs `define_global`.
    // This is because we want to define the variable in the compiler, not just set it for
    // scanning.
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
/// These functions convert various error types to napi::Error for consistent error handling in the
/// library.
fn compile_error_to_napi(error: &CompileError) -> Error {
  Error::new(
    Status::GenericFailure,
    format!("Compilation error ({}): {}", error.code(), error),
  )
}

/// Converts a YARA scan error to a napi::Error
/// This function takes a YARA scan error and converts it to a napi::Error for consistent error
/// handling in the library.
fn scan_error_to_napi(error: yara_x::ScanError) -> Error {
  // Match the error type and create a corresponding napi::Error
  // This allows for consistent error handling and reporting in the library.
  // For example, if a file fails to open, it will return a GenericFailure error with a message
  // indicating the file could not be opened.
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
      format!("Protobuf error in module '{}': {}", module, err),
    ),
    yara_x::ScanError::UnknownModule { module } => Error::new(
      Status::GenericFailure,
      format!("Unknown module: '{}'", module),
    ),
    _ => Error::new(
      Status::GenericFailure,
      format!("Unknown scan error: {:?}", error),
    ),
  }
}

/// Converts an I/O error to a napi::Error
/// This function takes an I/O error and a context string, and converts it to a napi::Error for
/// consistent error handling in the library.
/// The context string provides additional information about where the error occurred.
/// This allows for better debugging and understanding of the error.
fn io_error_to_napi(error: std::io::Error, context: &str) -> Error {
  Error::new(
    Status::GenericFailure,
    format!("I/O error ({}): {}", context, error),
  )
}

/// Converts a generic error message to a napi::Error
/// This function takes a generic error message and converts it to a napi::Error for consistent
/// error handling in the library.
/// This is useful for converting any error message to a napi::Error.
/// For example, if an unexpected error occurs, it will return a GenericFailure error with the
/// error message.
///
/// ```rust
/// let err = "An unexpected error occurred";
/// let napi_err = to_napi_err(err);
/// ```
/// This will create a napi::Error with the message "An unexpected error occurred".
fn to_napi_err<E: std::fmt::Display>(err: E) -> Error {
  Error::new(Status::GenericFailure, err.to_string())
}

/// Converts a list of compiler messages to a vector of CompilerWarning or CompilerError
/// This function takes a list of compiler messages and a function to convert each message to a
/// CompilerWarning or CompilerError.
///
/// # Example
///
/// ```rust
/// let warnings = convert_compiler_messages(compiler.warnings(), |w| CompilerWarning {
///	  code: w.code().to_string(),
///	  message: w.to_string(),
///	  source: None,
///	  line: None,
///	  column: None,
///	  });
///	let errors = convert_compiler_messages(compiler.errors(), |e| CompilerError {
///	  code: e.code().to_string(),
///	  message: e.to_string(),
///	  source: None,
///	  line: None,
///	  column: None,
///	});
///	```
///	This will create a vector of CompilerWarning or CompilerError from the compiler messages.
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
///
/// See [yara_::Match](https://docs.rs/yara-x/latest/yara_x/struct.Match.html) for more details.
#[napi(object)]
pub struct RuleMatch {
  /// The identifier of the rule that matched.
  pub rule_identifier: String,
  /// The namespace of the rule that matched.
  pub namespace: String,
  /// The metadata associated with the rule that matched.
  pub meta: Object,
  /// The tags associated with the rule that matched.
  pub tags: Vec<String>,
  /// The matches found by the rule.
  pub matches: Vec<MatchData>,
}

/// CompilerOptions struct represents the options for the YARA compiler.
///
/// See [yara_x::Compiler](https://docs.rs/yara-x/latest/yara_x/struct.Compiler.html) for more
/// details.
#[napi(object)]
pub struct CompilerOptions {
  /// Defines global variables for the YARA rules.
  pub define_variables: Option<Object>,
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
///
/// See [yara_x::CompilerWarning](https://docs.rs/yara-x/latest/yara_x/warnings/enum.Warning.html)
/// for more details.
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
///
/// See
/// [yara_x::CompileError](https://docs.rs/yara-x/latest/yara_x/errors/enum.CompileError.html)
/// for more details.
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
/// It contains any warnings or errors generated during the compilation process.
#[napi(object)]
#[derive(Serialize, Deserialize, Clone)]
pub struct CompileResult {
  /// Any warnings generated during the compilation process.
  pub warnings: Vec<CompilerWarning>,
  /// Any errors generated during the compilation process.
  pub errors: Vec<CompilerError>,
}

/// YaraX struct represents the YARA rules and their associated data.
/// It contains the compiled rules, source code, warnings, and variables.
///
/// See [yara_x::Rules](https://docs.rs/yara-x/latest/yara_x/struct.Rules.html) for more details.
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
}

/// Implementations for YaraX
///
/// This implementation provides methods for applying compiler options,
/// creating meta objects, extracting matches, and processing scan results.
impl YaraX {
  /// Applies compiler options to the YARA compiler.
  /// This function takes a mutable reference to a Compiler and an optional CompilerOptions.
  fn apply_compiler_options(
    compiler: &mut Compiler<'_>,
    options: Option<&CompilerOptions>,
    store_variables: bool,
  ) -> Result<Option<VariableMap>> {
    let mut stored_variables = None;

    // Check if options are provided
    if let Some(opts) = options {
      if let Some(ignored_modules) = &opts.ignore_modules {
        for module in ignored_modules {
          let _ = compiler.ignore_module(module);
        }
      }

      // Check if there are any banned modules
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

      // Set compiler options based on the provided options
      // This allows for customization of the compilation process based on user-defined options.
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
  ///
  /// This function takes a YARA rule and creates a meta object containing the metadata associated
  /// with the rule.
  fn create_meta_object(env: napi::Env, rule: &yara_x::Rule) -> Result<Object> {
    let mut meta_obj = env.create_object()?;

    // Iterate over the metadata of the rule
    // This allows for dynamic creation of metadata objects based on the rule's properties.
    for (key, value) in rule.metadata() {
      let key_string = key.to_string();

      // Set the metadata property based on the type of value
      // This allows for flexible handling of different data types in the metadata.
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
  ///
  /// This function takes an optional object of variables and converts it to a VariableMap.
  /// This is useful for applying variables defined in JavaScript to the YARA compiler or scanner.
  /// Returns None if the object is empty or None.
  fn convert_variables_to_map(variables: Option<Object>) -> Result<Option<VariableMap>> {
    let vars = match variables {
      Some(vars) => vars,
      None => return Ok(None),
    };

    let property_names = Object::keys(&vars)?;
    if property_names.is_empty() {
      return Ok(None);
    }

    // Pre-allocate HashMap with exact capacity and reserve additional space
    // to avoid rehashing during insertion
    let mut map = HashMap::with_capacity(property_names.len());

    // Use iterator to reduce temporary allocations
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
      // shrink HashMap if significantly under-utilized to save memory
      if valid_entries < property_names.len() / 2 {
        map.shrink_to_fit();
      }
      Ok(Some(map))
    }
  }

  /// Creates a new YaraX instance from a source string.
  /// This function takes a source string and optional compiler options,
  /// compiles the source, and returns a YaraX instance.
  ///
  /// Example
  ///
  /// ```rust
  /// let yarax = YaraX::create_scanner_from_source("rule example { strings: $a = "example"
  /// condition: $a }".to_string(), None)?;
  /// ```
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

  /// Extracts matches from a YARA rule.
  /// This function takes a YARA rule and the scanned data,
  /// and returns a vector of MatchData representing the matches found by the rule.
  /// This allows for extracting detailed information about each match found by the rule.
  ///
  /// Example
  ///
  /// ```rust
  /// let matches = Self::extract_matches(&rule, data);
  /// for match_data in matches {
  ///	 println!("Match found: {:?}", match_data);
  /// }
  /// // Output:
  /// // Match found: MatchData { offset: 10, length: 7, data: "example", identifier: "$a" }
  /// ```
  fn extract_matches(rule: &yara_x::Rule, data: &[u8]) -> Vec<MatchData> {
    let total_matches: usize = rule.patterns()
      .map(|pattern| pattern.matches().len())
      .sum();

    // Pre-allocate the vector for performance optimization
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

        if let Some(matched_bytes) = data.get(offset..offset + length) {
          let matched_data = if matched_bytes.is_ascii() {
            unsafe { String::from_utf8_unchecked(matched_bytes.to_vec()) }
          } else {
            String::from_utf8_lossy(matched_bytes).into_owned()
          };

          // Create a new MatchData instance with the extracted information
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

  /// Processes the scan results and returns a vector of RuleMatch.
  /// This function takes the scan results, the scanned data, and the environment,
  /// and returns a vector of RuleMatch representing the matching rules found during the scan.
  ///
  /// Example
  ///
  /// ```rust
  /// let results = scanner.scan(data).map_err(scan_error_to_napi)?;
  /// // Process the scan results
  /// let matches = Self::process_scan_results(results, data, env)?;
  /// ```
  fn process_scan_results(
    results: yara_x::ScanResults,
    data: &[u8],
    env: napi::Env,
  ) -> Result<Vec<RuleMatch>> {
    let matching_rules = results.matching_rules();
    let rule_count = matching_rules.len();

    if rule_count == 0 {
      return Ok(Vec::new());
    }

    // Pre-allocate the vector for performance optimization
    let mut rule_matches = Vec::with_capacity(rule_count);

    for rule in matching_rules {
      let matches_vec = Self::extract_matches(&rule, data);

      let tags: Vec<String> = rule.tags()
        .map(|tag| tag.identifier().to_string())
        .collect();

      // Create a meta object for the rule
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

/// Implementations for YaraX
/// This implementation provides methods for getting compiler errors and warnings,
/// scanning data, and emitting WASM files.
#[napi]
impl YaraX {
  /// Returns the compiler errors generated during the compilation process.
  /// This function takes a reference to the YARA compiler and returns a vector of CompilerError.
  fn get_compiler_errors(compiler: &Compiler) -> Result<Vec<CompilerError>> {
    let errors = compiler.errors();

    // Convert compiler errors to a vector of CompilerError
    // This allows for consistent handling of errors in the library.
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
  /// This function takes a reference to the YARA compiler and returns a vector of CompilerWarning.
  fn get_compiler_warnings(compiler: &Compiler) -> Result<Vec<CompilerWarning>> {
    let warnings = compiler.warnings();

    // Convert compiler warnings to a vector of CompilerWarning
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
    // TODO: redundant code, or good for the API?
    self.warnings.clone()
  }

  /// Scans the provided data using the compiled YARA rules.
  /// This function takes the scanned data and an optional object of variables,
  /// and returns a vector of RuleMatch representing the matching rules found during the scan.
  #[napi(ts_args_type = "data: Buffer, variables?: Record<string, string | number>")]
  pub fn scan(&self, env: Env, data: Buffer, variables: Option<Object>) -> Result<Vec<RuleMatch>> {
    let mut scanner = Scanner::new(&self.rules);

    scanner.apply_variables_from_map(&self.variables)?;

    scanner.apply_variables_from_object(&variables)?;

    let results = scanner.scan(data.as_ref()).map_err(scan_error_to_napi)?;

    Self::process_scan_results(results, data.as_ref(), env)
  }

  /// Scans a file using the compiled YARA rules.
  /// This function takes the file path and an optional object of variables,
  /// and returns a vector of RuleMatch representing the matching rules found during the scan.
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

  /// Emits a WASM file from the compiled YARA rules.
  /// This function takes the output path and writes the compiled rules to a WASM file.
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

  /// Compiles a source string to a WASM file.
  /// This function takes a source string, output path, and optional compiler options,
  /// and writes the compiled rules to a WASM file.
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

  /// Scans the provided data asynchronously using the compiled YARA rules.
  /// This function takes the scanned data and an optional object of variables,
  /// and returns an AsyncTask that will resolve to a vector of RuleMatch representing the matching
  /// rules found during the scan.
  ///
  /// This allows for non-blocking scanning of data, which can be useful for large datasets or
  /// performance-critical applications.
  #[napi]
  pub fn scan_async(&self, data: Buffer, variables: Option<Object>) -> Result<AsyncTask<ScanTask>> {
    let data_vec = data.to_vec();
    let vars_map = Self::convert_variables_to_map(variables)?;

    // Create a new ScanTask with the provided data and variables
    Ok(AsyncTask::new(ScanTask::new(
      self.rules.clone(),
      data_vec,
      vars_map,
    )))
  }

  /// Scans a file asynchronously using the compiled YARA rules.
  /// This function takes the file path and an optional object of variables,
  /// and returns an AsyncTask that will resolve to a vector of RuleMatch representing the matching
  /// rules found during the scan.
  ///
  /// This allows for non-blocking scanning of files, which can be useful for large files or
  /// performance-critical applications.
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
  /// This function takes the output path
  /// and returns an AsyncTask that will resolve when the WASM file is successfully emitted.
  #[napi]
  pub fn emit_wasm_file_async(&self, output_path: String) -> Result<AsyncTask<EmitWasmFileTask>> {
    Ok(AsyncTask::new(EmitWasmFileTask {
      source_code: self.source_code.clone(),
      output_path,
    }))
  }

  /// Adds a rule source to the YARA compiler.
  /// This function takes a rule source string,
  /// compiles it, and updates the YaraX instance with the new rules.
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
      // Pre-allocate the source code string to avoid reallocations
      let new_capacity = source.len() + rule_source.len() + 1;
      source.reserve(new_capacity);
      source.push('\n');
      source.push_str(&rule_source);
    } else {
      self.source_code = Some(rule_source);
    }

    Ok(())
  }

  /// Adds a rule file to the YARA compiler.
  /// This function takes a file path,
  /// reads the file content, and adds it to the YaraX instance.
  #[napi]
  pub fn add_rule_file(&mut self, file_path: String) -> Result<()> {
    let file_content = std::fs::read_to_string(Path::new(&file_path))
      .map_err(|e| io_error_to_napi(e, &format!("reading file {}", file_path)))?;
    self.add_rule_source(file_content)
  }

  /// Defines a variable for the YARA compiler.
  /// This function takes a variable name and value,
  /// and adds it to the YaraX instance.
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

    // Update the source code with the new variable
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

// -- Task implementations --

// See [napi.rs AsyncTask](https://napi.rs/docs/concepts/async-task) for more details on the below implementations.
// Each of these *Task structs represent a specific task that can be executed asynchronously.
// They implement the Task trait, which defines how to compute and resolve the task.
// This allows for non-blocking execution of potentially long-running tasks, such as scanning data
// or files with YARA rules.
// This is useful for performance-critical applications or when processing large datasets.
// The tasks can be executed in a separate thread, and the results can be resolved back to the
// main thread when completed.

/// BaseYaraTask struct represents a base task for YARA scanning.
/// It contains the compiled YARA rules and any variables to be applied during scanning.
struct BaseYaraTask {
  // The compiled YARA rules
  rules: Arc<Rules>,
  // The variables to be applied during scanning
  variables: Option<VariableMap>,
}

/// Implementations for BaseYaraTask
/// This implementation provides methods for creating a scanner and processing scan results.
/// This allows for reusability and cleaner code in the ScanTask and ScanFileTask implementations.
/// This struct is not exposed to the public API.
impl BaseYaraTask {
  fn new(rules: Arc<Rules>, variables: Option<VariableMap>) -> Self {
    Self { rules, variables }
  }

  /// Creates a new scanner with the compiled YARA rules and applies any defined variables.
  /// This function initializes a new Scanner instance with the provided rules
  /// and applies any variables defined in the YaraX instance.
  fn create_scanner(&self) -> Result<Scanner> {
    let mut scanner = Scanner::new(&self.rules);
    scanner.apply_variables_from_map(&self.variables)?;
    Ok(scanner)
  }

  /// Processes the scan results and returns a vector of RuleMatch.
  /// This function takes the scan results and the scanned data,
  /// and returns a vector of RuleMatch representing the matching rules found during the scan.
  fn process_results(&self, env: Env, data: &[u8]) -> Result<Vec<RuleMatch>> {
    let mut scanner = self.create_scanner()?;
    let results = scanner.scan(data).map_err(scan_error_to_napi)?;
    YaraX::process_scan_results(results, data, env)
  }
}

/// ScanTask struct represents a task for scanning data with YARA rules.
/// It contains the base YARA task and the data to be scanned.
pub struct ScanTask {
  /// The base YARA task containing the compiled rules and variables
  base: BaseYaraTask,
  /// The data to be scanned
  data: Vec<u8>,
}

/// Implementations for ScanTask
/// This implementation provides methods for creating a new ScanTask and processing the scan
/// results.
impl ScanTask {
  /// Creates a new ScanTask with the provided rules, data, and variables.
  fn new(rules: Arc<Rules>, data: Vec<u8>, variables: Option<VariableMap>) -> Self {
    Self {
      base: BaseYaraTask::new(rules, variables),
      data,
    }
  }
}

/// Task trait implementation for ScanTask
/// This implementation provides methods for computing the scan results and resolving them to a
/// vector of RuleMatch.
impl Task for ScanTask {
  type Output = Vec<u8>;
  type JsValue = Vec<RuleMatch>;

  fn compute(&mut self) -> Result<Self::Output> {
    // Return the data to be scanned, using std::mem::take to avoid ownership issues
    Ok(std::mem::take(&mut self.data))
  }

  /// Processes the scan results and returns a vector of RuleMatch.
  fn resolve(&mut self, env: napi::Env, data: Self::Output) -> Result<Self::JsValue> {
    self.base.process_results(env, &data)
  }
}

/// ScanFileTask struct represents a task for scanning a file with YARA rules.
/// It contains the base YARA task and the file path to be scanned.
pub struct ScanFileTask {
  /// The base YARA task containing the compiled rules and variables
  base: BaseYaraTask,
  /// The file path to be scanned
  file_path: String,
}

/// Implementations for ScanFileTask
/// This implementation provides methods for creating a new ScanFileTask and processing the scan
/// results.
impl ScanFileTask {
  /// Creates a new ScanFileTask with the provided rules, file path, and variables.
  fn new(rules: Arc<Rules>, file_path: String, variables: Option<VariableMap>) -> Self {
    Self {
      base: BaseYaraTask::new(rules, variables),
      file_path,
    }
  }
}

/// Task trait implementation for ScanFileTask
/// This implementation provides methods for computing the file data and resolving it to a vector
/// of RuleMatch.
impl Task for ScanFileTask {
  /// The output type for the task, which is the file data as a byte vector
  type Output = Vec<u8>;
  /// The JavaScript value type for the task, which is a vector of RuleMatch
  type JsValue = Vec<RuleMatch>;

  fn compute(&mut self) -> Result<Self::Output> {
    std::fs::read(&self.file_path)
      .map_err(|e| io_error_to_napi(e, &format!("reading file {}", self.file_path)))
  }

  fn resolve(&mut self, env: napi::Env, data: Self::Output) -> Result<Self::JsValue> {
    self.base.process_results(env, &data)
  }
}

/// EmitWasmFileTask struct represents a task for emitting a WASM file from YARA rules.
/// It contains the source code and the output path for the WASM file.
pub struct EmitWasmFileTask {
  /// The source code used to compile the YARA rules
  source_code: Option<String>,
  /// The output path for the WASM file
  output_path: String,
}

/// Task trait implementation for EmitWasmFileTask
/// This implementation provides methods for computing the WASM file emission and resolving it.
impl Task for EmitWasmFileTask {
  /// The output type for the task, which is nothing (unit type)
  type Output = ();
  /// The JavaScript value type for the task, which is also nothing (unit type)
  type JsValue = ();

  /// Computes the emission of the WASM file from the source code.
  fn compute(&mut self) -> Result<Self::Output> {
    // Check if the source code is available
    let source = self.source_code.as_ref().ok_or_else(|| {
      Error::new(
        Status::InvalidArg,
        "Cannot emit WASM file: source code not available",
      )
    })?;

    YaraX::compile_source_to_wasm(source, &self.output_path, None)?;
    Ok(())
  }

  /// Resolves the task, which does nothing in this case.
  /// Since the task is to emit a file, there is no meaningful value to return.
  fn resolve(&mut self, _env: napi::Env, _output: Self::Output) -> Result<Self::JsValue> {
    Ok(())
  }
}

/// Compiles a YARA rule source string and returns any warnings or errors generated during the
/// compilation process.
///
/// Exported as `validate` in the NAPI interface.
///
/// Example
///
/// ```javascript
/// const { validate } = require('your_yara_module');
/// const result = validate('rule example { strings: $a = "example" condition: $a }');
/// ```
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
///
/// Exported as `compile` in the NAPI interface.
///
/// Example
///
/// ```javascript
/// const { compile } = require('your_yara_module');
/// const yarax = compile('rule example { strings: $a = "example" condition: $a }');
/// ```
#[napi]
pub fn compile(rule_source: String, options: Option<CompilerOptions>) -> Result<YaraX> {
  let yarax = YaraX::create_scanner_from_source(rule_source, options)?;
  Ok(yarax)
}

/// Creates a new YaraX instance with empty rules and no source code.
///
/// Exported as `create` in the NAPI interface.
///
/// Example
///
/// ```javascript
/// const { create } = require('your_yara_module');
/// const yarax = create();
///
/// // Now you can add rules or compile them later
///
/// yarax.addRuleSource('rule example { strings: $a = "example" condition: $a }');
/// yarax.addRuleFile('path/to/rule_file.yar');
/// yarax.defineVariable('myVar', 'myValue');
/// ```
#[napi]
pub fn create() -> YaraX {
  YaraX {
    // The compiled YARA rules
    rules: Arc::new(Compiler::new().build()),
    // The source code used to compile the YARA rules
    source_code: Some(String::new()),
    // Any warnings generated during the compilation process
    warnings: Vec::new(),
    // The variables defined for the YARA rules
    variables: None,
  }
}

/// Creates a new YaraX instance from a file containing YARA rules.
///
/// Exported as `fromFile` in the NAPI interface.
///
/// Example
///
/// ```javascript
/// const { fromFile } = require('your_yara_module');
/// const yarax = fromFile('path/to/rule_file.yar');
/// ```
#[napi]
pub fn from_file(rule_path: String, options: Option<CompilerOptions>) -> Result<YaraX> {
  let file_content = std::fs::read_to_string(Path::new(&rule_path))
    .map_err(|e| io_error_to_napi(e, &format!("reading file {}", rule_path)))?;

  YaraX::create_scanner_from_source(file_content, options)
}

/// Compiles a YARA rule source string to a WASM file.
///
/// Exported as `compileToWasm` in the NAPI interface.
///
/// Example
///
/// ```javascript
/// const { compileToWasm } = require('your_yara_module');
/// compileToWasm('rule example { strings: $a = "example" condition: $a }', 'output.wasm');
/// ```
#[napi]
pub fn compile_to_wasm(
  rule_source: String,
  output_path: String,
  options: Option<CompilerOptions>,
) -> Result<()> {
  YaraX::compile_source_to_wasm(&rule_source, &output_path, options.as_ref())
}

/// Compiles a YARA rule file to a WASM file.
///
/// Exported as `compileFileToWasm` in the NAPI interface.
///
/// Example
///
/// ```javascript
/// const { compileFileToWasm } = require('your_yara_module');
/// compileFileToWasm('path/to/rule_file.yar', 'output.wasm');
/// ```
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
