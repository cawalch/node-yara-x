//! YARA compiler utilities and configuration.
//!
//! This module provides functions for configuring and using the YARA compiler,
//! including applying compiler options and generating WASM output.

use crate::error::compile_error_to_napi;
use crate::types::{
  BannedModule, CompilerError, CompilerOptions, IgnoredRule, RuleSource, VariableMap,
};
use crate::variables::{get_variable_value, VariableHandler};
use napi::bindgen_prelude::Object;
use napi::{Error, Result, Status};
use std::collections::HashMap;
use std::path::Path;
use yara_x::errors::CompileError;
use yara_x::{Compiler, IgnoredRuleReason};

/// The compiler options that affect how rule sources are compiled, excluding
/// the fields handled separately by [`crate::scanner::YaraX`] (namespace,
/// `define_variables`, `ignore_invalid_rules`).
///
/// Unlike [`CompilerOptions`] this is plain owned data with no N-API object
/// references, so it can be stored on the scanner and replayed across
/// incremental recompilations and WASM emission.
#[derive(Debug, Clone, Default)]
pub struct StoredCompilerOptions {
  pub ignore_modules: Vec<String>,
  pub banned_modules: Vec<BannedModule>,
  pub features: Vec<String>,
  pub relaxed_re_syntax: bool,
  pub condition_optimization: bool,
  pub error_on_slow_pattern: bool,
  pub error_on_slow_loop: bool,
  pub max_warnings: Option<usize>,
  pub disable_warnings: Vec<String>,
  pub enable_all_warnings: Option<bool>,
  pub include_directories: Vec<String>,
  pub enable_includes: Option<bool>,
}

/// Extracts the persisted compiler options from a [`CompilerOptions`] object.
///
/// `namespace`, `define_variables` and `ignore_invalid_rules` are excluded:
/// they are tracked separately by the scanner.
pub fn stored_options_from(options: Option<&CompilerOptions<'_>>) -> StoredCompilerOptions {
  let mut stored = StoredCompilerOptions::default();

  if let Some(opts) = options {
    if let Some(modules) = &opts.ignore_modules {
      stored.ignore_modules = modules.clone();
    }
    if let Some(modules) = &opts.banned_modules {
      stored.banned_modules = modules.clone();
    }
    if let Some(features) = &opts.features {
      stored.features = features.clone();
    }
    stored.relaxed_re_syntax = opts.relaxed_re_syntax.unwrap_or(false);
    stored.condition_optimization = opts.condition_optimization.unwrap_or(false);
    stored.error_on_slow_pattern = opts.error_on_slow_pattern.unwrap_or(false);
    stored.error_on_slow_loop = opts.error_on_slow_loop.unwrap_or(false);
    stored.max_warnings = opts.max_warnings.map(|m| m as usize);
    if let Some(codes) = &opts.disable_warnings {
      stored.disable_warnings = codes.clone();
    }
    stored.enable_all_warnings = opts.enable_all_warnings;
    if let Some(dirs) = &opts.include_directories {
      stored.include_directories = dirs.clone();
    }
    stored.enable_includes = opts.enable_includes;
  }

  stored
}

/// Applies previously-stored compiler options to a compiler instance.
///
/// This is the persisted counterpart of the option half of
/// [`apply_compiler_options`], used when replaying a scanner's compilation
/// state during incremental recompilation or WASM emission.
pub fn apply_stored_compiler_options(
  compiler: &mut Compiler<'_>,
  stored: &StoredCompilerOptions,
) -> Result<()> {
  for module in &stored.ignore_modules {
    let _ = compiler.ignore_module(module);
  }

  for banned in &stored.banned_modules {
    let _ = compiler.ban_module(&banned.name, &banned.error_title, &banned.error_message);
  }

  for feature in &stored.features {
    let _ = compiler.enable_feature(feature);
  }

  for dir in &stored.include_directories {
    compiler.add_include_dir(dir);
  }

  if let Some(enable_includes) = stored.enable_includes {
    compiler.enable_includes(enable_includes);
  }

  compiler
    .relaxed_re_syntax(stored.relaxed_re_syntax)
    .condition_optimization(stored.condition_optimization)
    .error_on_slow_pattern(stored.error_on_slow_pattern)
    .error_on_slow_loop(stored.error_on_slow_loop);

  if let Some(max) = stored.max_warnings {
    compiler.max_warnings(max);
  }

  if let Some(enable_all) = stored.enable_all_warnings {
    compiler.switch_all_warnings(enable_all);
  }

  for code in &stored.disable_warnings {
    compiler
      .switch_warning(code, false)
      .map_err(crate::error::to_napi_err)?;
  }

  Ok(())
}

/// Adds a source string to the compiler, switching namespaces when requested.
///
/// A `None` namespace means the default namespace; the compiler switches to
/// it explicitly so that a source without a namespace never inherits the
/// namespace of a previously added source.
pub fn add_source_to_compiler(
  compiler: &mut Compiler<'_>,
  source: &str,
  namespace: Option<&str>,
) -> Result<()> {
  compiler.new_namespace(namespace.unwrap_or("default"));

  compiler
    .add_source(source)
    .map_err(|e| compile_error_to_napi(&e))?;

  Ok(())
}

/// Adds a source string to the compiler, optionally tolerating per-rule
/// compilation errors so that the remaining rules can still be compiled.
///
/// When `tolerate` is `true`, a rule that fails to compile is skipped and
/// tracked by the compiler (reportable via
/// [`collect_ignored_rules`](Self::collect_ignored_rules)) instead of
/// propagating the error. When `false`, the first error is returned, exactly
/// like [`add_source_to_compiler`](Self::add_source_to_compiler).
///
/// Errors that cannot be attributed to a single skipped rule (syntax errors,
/// invalid UTF-8, banned or unknown module imports, include failures) are not
/// recorded by the compiler as ignored rules; callers surfacing them via
/// [`uncovered_compiler_errors`](Self::uncovered_compiler_errors) or
/// [`crate::variables::get_compiler_errors`].
pub fn add_source_to_compiler_tolerant(
  compiler: &mut Compiler<'_>,
  source: &str,
  namespace: Option<&str>,
  tolerate: bool,
) -> Result<()> {
  // A `None` namespace means the default namespace; switch to it explicitly
  // so a source without a namespace never inherits a previously set one.
  compiler.new_namespace(namespace.unwrap_or("default"));

  if tolerate {
    let _ = compiler.add_source(source);
    Ok(())
  } else {
    compiler
      .add_source(source)
      .map(|_| ())
      .map_err(|e| compile_error_to_napi(&e))
  }
}

/// Collects the rules that were skipped during compilation, along with the
/// reason each one was ignored.
///
/// The report is only populated when rules were actually skipped (e.g. because
/// compilation was performed with `ignore_invalid_rules`, or because the
/// rules depend on ignored modules).
pub fn collect_ignored_rules(compiler: &Compiler) -> Vec<IgnoredRule> {
  compiler
    .ignored_rules()
    .map(|(name, reason)| match reason {
      IgnoredRuleReason::IgnoredModule(module) => IgnoredRule {
        name: name.to_string(),
        reason: "ignored_module".to_string(),
        detail: Some(module.to_string()),
      },
      IgnoredRuleReason::IgnoredRule(rule) => IgnoredRule {
        name: name.to_string(),
        reason: "ignored_rule".to_string(),
        detail: Some(rule.to_string()),
      },
      IgnoredRuleReason::CompileError(err) => IgnoredRule {
        name: name.to_string(),
        reason: "compile_error".to_string(),
        detail: Some(err.to_string()),
      },
    })
    .collect()
}

/// Collects the compilation errors that are **not** attributable to a skipped
/// rule recorded by [`Compiler::ignored_rules`].
///
/// yara-x only records per-rule failures (unknown identifiers, linter errors)
/// as ignored rules; errors that affect the whole source or import/include
/// processing — syntax errors, invalid UTF-8, banned or unknown module imports
/// — are pushed to the compiler's error list without a matching
/// `IgnoredRuleReason::CompileError` entry. This helper returns exactly those
/// errors so callers that tolerate compilation failures can surface them
/// instead of silently dropping them.
pub fn uncovered_compiler_errors(compiler: &Compiler) -> Vec<CompilerError> {
  let covered: Vec<*const CompileError> = compiler
    .ignored_rules()
    .filter_map(|(_, reason)| match reason {
      IgnoredRuleReason::CompileError(err) => Some(err as *const CompileError),
      _ => None,
    })
    .collect();

  compiler
    .errors()
    .iter()
    .filter(|err| {
      !covered
        .iter()
        .any(|covered| std::ptr::eq(*covered, *err as *const CompileError))
    })
    .map(|err| CompilerError {
      code: err.code().to_string(),
      message: err.to_string(),
      source: None,
      line: None,
      column: None,
    })
    .collect()
}

/// Applies compiler options to a YARA compiler instance.
///
/// This function configures the compiler based on the provided options,
/// including module handling, feature flags, and optimization settings.
///
/// # Arguments
///
/// * `compiler` - The YARA compiler to configure
/// * `options` - Optional compiler options
/// * `store_variables` - Whether to store variables for later use
///
/// # Returns
///
/// An optional VariableMap containing the defined variables if `store_variables` is true
pub fn apply_compiler_options(
  compiler: &mut Compiler<'_>,
  options: Option<&CompilerOptions>,
  store_variables: bool,
) -> Result<Option<VariableMap>> {
  let mut stored_variables = None;

  if let Some(opts) = options {
    let stored = stored_options_from(Some(opts));
    apply_stored_compiler_options(compiler, &stored)?;

    // Apply variables
    if let Some(vars) = &opts.define_variables {
      let property_names = Object::keys(vars)?;
      if property_names.is_empty() {
        return Ok(stored_variables);
      }

      if store_variables {
        stored_variables = Some(HashMap::with_capacity(property_names.len()));
      }

      for key in &property_names {
        let value = get_variable_value(vars, key)?;
        compiler.apply_variable_value(key, &value)?;

        if let Some(var_map) = &mut stored_variables {
          var_map.insert(key.clone(), value);
        }
      }
    }
  }

  Ok(stored_variables)
}

/// Compiles a YARA rule source string to a WASM file.
///
/// This function creates a compiler, applies options, compiles the source,
/// and emits the result as a WebAssembly module.
///
/// # Arguments
///
/// * `source` - The YARA rule source code
/// * `output_path` - Path where the WASM file should be written
/// * `options` - Optional compiler options
///
/// # Returns
///
/// Ok(()) on success, or an error if compilation or emission fails
pub fn compile_source_to_wasm(
  source: &str,
  output_path: &str,
  options: Option<&CompilerOptions>,
) -> Result<()> {
  let namespace = options.and_then(|opts| opts.namespace.as_deref());
  compile_sources_to_wasm(
    &[RuleSource {
      source: source.to_string(),
      namespace: namespace.map(str::to_string),
    }],
    output_path,
    options,
  )
}

/// Compiles YARA rule sources to a WASM file.
pub fn compile_sources_to_wasm(
  sources: &[RuleSource],
  output_path: &str,
  options: Option<&CompilerOptions>,
) -> Result<()> {
  let mut compiler = Compiler::new();

  apply_compiler_options(&mut compiler, options, false)?;

  let ignore_invalid_rules = options
    .as_ref()
    .and_then(|opts| opts.ignore_invalid_rules)
    .unwrap_or(false);

  add_sources_and_emit(compiler, sources, ignore_invalid_rules, output_path)
}

/// Replays a scanner's persisted compilation state (stored options and
/// variables) and emits the resulting WASM module from its rule sources.
///
/// This is the WASM counterpart of the scanner's incremental recompilation:
/// it applies the same stored compiler options and the same global variables
/// (in the same order, variables before sources) so the emitted module
/// matches the scanner's semantics — including `ignore_invalid_rules`.
pub fn replay_sources_to_wasm(
  sources: &[RuleSource],
  output_path: &str,
  stored: &StoredCompilerOptions,
  variables: Option<&VariableMap>,
  ignore_invalid_rules: bool,
) -> Result<()> {
  let mut compiler = Compiler::new();

  apply_stored_compiler_options(&mut compiler, stored)?;

  if let Some(vars) = variables {
    for (key, value) in vars {
      compiler.apply_variable_value(key, value)?;
    }
  }

  add_sources_and_emit(compiler, sources, ignore_invalid_rules, output_path)
}

/// Adds all sources to the compiler and emits the WASM module, rejecting
/// source-level errors when tolerating invalid rules (there is no report
/// channel on the one-shot WASM path).
fn add_sources_and_emit(
  mut compiler: Compiler<'_>,
  sources: &[RuleSource],
  ignore_invalid_rules: bool,
  output_path: &str,
) -> Result<()> {
  for rule_source in sources {
    add_source_to_compiler_tolerant(
      &mut compiler,
      &rule_source.source,
      rule_source.namespace.as_deref(),
      ignore_invalid_rules,
    )?;
  }

  // When tolerating invalid rules, errors that cannot be attributed to a
  // single skipped rule (syntax errors, banned or unknown module imports,
  // include failures) would otherwise be silently dropped. There is no
  // report channel on the one-shot WASM path, so surface them as an error
  // instead of emitting a WASM module that silently lacks rules.
  if ignore_invalid_rules {
    let uncovered = uncovered_compiler_errors(&compiler);
    if !uncovered.is_empty() {
      let details = uncovered
        .iter()
        .map(|e| format!("{}: {}", e.code, e.message))
        .collect::<Vec<_>>()
        .join("\n");
      return Err(Error::new(
        Status::GenericFailure,
        format!("Compilation error(s) not attributable to a skipped rule: {details}"),
      ));
    }
  }

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
