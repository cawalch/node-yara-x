//! YARA compiler utilities and configuration.
//!
//! This module provides functions for configuring and using the YARA compiler,
//! including applying compiler options and generating WASM output.

use crate::error::compile_error_to_napi;
use crate::types::{CompilerError, CompilerOptions, IgnoredRule, RuleSource, VariableMap};
use crate::variables::{get_variable_value, VariableHandler};
use napi::bindgen_prelude::Object;
use napi::{Error, Result, Status};
use std::collections::HashMap;
use std::path::Path;
use yara_x::errors::CompileError;
use yara_x::{Compiler, IgnoredRuleReason};

/// Adds a source string to the compiler, switching namespaces when requested.
pub fn add_source_to_compiler(
  compiler: &mut Compiler<'_>,
  source: &str,
  namespace: Option<&str>,
) -> Result<()> {
  if let Some(namespace) = namespace {
    compiler.new_namespace(namespace);
  }

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
  if let Some(namespace) = namespace {
    compiler.new_namespace(namespace);
  }

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
    // Configure ignored modules
    if let Some(ignored_modules) = &opts.ignore_modules {
      for module in ignored_modules {
        let _ = compiler.ignore_module(module);
      }
    }

    // Configure banned modules
    if let Some(banned_modules) = &opts.banned_modules {
      for banned in banned_modules {
        let _ = compiler.ban_module(&banned.name, &banned.error_title, &banned.error_message);
      }
    }

    // Enable features
    if let Some(features) = &opts.features {
      for feature in features {
        let _ = compiler.enable_feature(feature);
      }
    }

    // Add include directories
    if let Some(include_dirs) = &opts.include_directories {
      for dir in include_dirs {
        compiler.add_include_dir(dir);
      }
    }

    // Enable or disable includes
    if let Some(enable_includes) = opts.enable_includes {
      compiler.enable_includes(enable_includes);
    }

    // Apply compiler flags
    compiler
      .relaxed_re_syntax(opts.relaxed_re_syntax.unwrap_or(false))
      .condition_optimization(opts.condition_optimization.unwrap_or(false))
      .error_on_slow_pattern(opts.error_on_slow_pattern.unwrap_or(false))
      .error_on_slow_loop(opts.error_on_slow_loop.unwrap_or(false));

    // Apply warning controls.
    //
    // `switch_all_warnings` toggles every warning type at once, while
    // `switch_warning` flips an individual code. `switch_warning` returns
    // `Err(InvalidWarningCode)` for an unknown code, which we surface as a
    // N-API error via the Display impl rather than silently dropping it.
    if let Some(max) = opts.max_warnings {
      compiler.max_warnings(max as usize);
    }

    if let Some(enable_all) = opts.enable_all_warnings {
      compiler.switch_all_warnings(enable_all);
    }

    if let Some(disabled) = &opts.disable_warnings {
      for code in disabled {
        compiler
          .switch_warning(code, false)
          .map_err(crate::error::to_napi_err)?;
      }
    }

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
