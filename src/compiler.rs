//! YARA compiler utilities and configuration.
//!
//! This module provides functions for configuring and using the YARA compiler,
//! including applying compiler options and generating WASM output.

use crate::error::compile_error_to_napi;
use crate::types::{
  BannedModule, CompilerError, CompilerOptions, CompilerWarning, IgnoredRule, RuleSource,
  VariableMap,
};
use crate::variables::{diagnostic_location, get_variable_value, VariableHandler};
use napi::bindgen_prelude::Object;
use napi::{Env, Error, Result, Status};
use std::collections::HashMap;
use std::path::Path;
use yara_x::errors::CompileError;
use yara_x::{Compiler, IgnoredRuleReason, SourceCode};

/// Modules compiled into this build, mirroring the `yara-x` features enabled in
/// `Cargo.toml`. YARA-X accepts any string in `ignore_module`/`ban_module` and
/// silently matches nothing when the name is misspelled, so validate names
/// here before handing them over.
const KNOWN_MODULES: &[&str] = &[
  "console", "pe", "elf", "macho", "math", "hash", "string", "time", "dotnet", "zip", "lnk", "dex",
  "crx", "cuckoo",
];

/// Rejects a module name that is not compiled into this build.
fn validate_module_name(name: &str, option: &str) -> Result<()> {
  if KNOWN_MODULES.contains(&name) {
    return Ok(());
  }

  Err(Error::new(
    Status::InvalidArg,
    format!(
      "Unknown module `{name}` in `{option}`. Known modules: {}",
      KNOWN_MODULES.join(", ")
    ),
  ))
}

/// Returns a warning for every `ignoreModules` entry that is not compiled into
/// this build.
///
/// Unknown names are allowed there — ignoring a module that is not compiled in
/// (for example `vt` on a build without `vt-module`) is how callers tolerate
/// rule sets that import it. The warning makes a typo visible without turning
/// that use case into a hard error. `bannedModules` uses a hard error instead
/// because an unknown name means the ban is not enforced.
pub fn ignored_module_warnings(stored: &StoredCompilerOptions) -> Vec<CompilerWarning> {
  stored
    .ignore_modules
    .iter()
    .filter(|module| !KNOWN_MODULES.contains(&module.as_str()))
    .map(|module| CompilerWarning {
      code: "unknown_ignored_module".to_string(),
      message: format!(
        "Ignored module `{module}` is not compiled into this build, so this entry matches nothing"
      ),
      source: None,
      line: None,
      column: None,
    })
    .collect()
}

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

impl From<&CompilerOptions<'_>> for StoredCompilerOptions {
  fn from(opts: &CompilerOptions<'_>) -> Self {
    Self {
      ignore_modules: opts.ignore_modules.clone().unwrap_or_default(),
      banned_modules: opts.banned_modules.clone().unwrap_or_default(),
      features: opts.features.clone().unwrap_or_default(),
      relaxed_re_syntax: opts.relaxed_re_syntax.unwrap_or(false),
      condition_optimization: opts.condition_optimization.unwrap_or(false),
      error_on_slow_pattern: opts.error_on_slow_pattern.unwrap_or(false),
      error_on_slow_loop: opts.error_on_slow_loop.unwrap_or(false),
      max_warnings: opts.max_warnings.map(|m| m as usize),
      disable_warnings: opts.disable_warnings.clone().unwrap_or_default(),
      enable_all_warnings: opts.enable_all_warnings,
      include_directories: opts.include_directories.clone().unwrap_or_default(),
      enable_includes: opts.enable_includes,
    }
  }
}

/// Extracts the persisted compiler options from a [`CompilerOptions`] object.
///
/// `namespace`, `define_variables` and `ignore_invalid_rules` are excluded:
/// they are tracked separately by the scanner.
pub fn stored_options_from(options: Option<&CompilerOptions<'_>>) -> StoredCompilerOptions {
  options.map_or_else(StoredCompilerOptions::default, StoredCompilerOptions::from)
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
  for banned in &stored.banned_modules {
    validate_module_name(&banned.name, "bannedModules[].name")?;
  }

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
///
/// `env` is the JavaScript environment to decorate a thrown compilation error
/// with; `None` (a background task, or a caller that discards the error) keeps
/// the plain one.
pub fn add_source_to_compiler(
  compiler: &mut Compiler<'_>,
  source: &str,
  namespace: Option<&str>,
  origin: Option<&str>,
  env: Option<&Env>,
) -> Result<()> {
  add_source_to_compiler_tolerant(compiler, source, namespace, origin, false, env)
}

/// Adds a source to the compiler, optionally skipping rules that fail.
///
/// With `tolerate`, a failing rule is skipped and recorded by the compiler
/// (see [`collect_ignored_rules`](Self::collect_ignored_rules)); otherwise the
/// first error is returned. Errors that belong to no single rule — syntax,
/// invalid UTF-8, banned/unknown module, include failures — are only visible
/// through [`uncovered_compiler_errors`](Self::uncovered_compiler_errors), so
/// callers that tolerate per-rule failures must still check them.
pub fn add_source_to_compiler_tolerant(
  compiler: &mut Compiler<'_>,
  source: &str,
  namespace: Option<&str>,
  origin: Option<&str>,
  tolerate: bool,
  env: Option<&Env>,
) -> Result<()> {
  // A `None` namespace means the default namespace; switch to it explicitly
  // so a source without a namespace never inherits a previously set one.
  compiler.new_namespace(namespace.unwrap_or("default"));

  if let Some(origin) = origin {
    // Resolve `include` statements relative to the rule file, in addition to
    // the explicit `includeDirectories`. Those were applied first, so an
    // explicitly configured directory still wins over a sibling file.
    if let Some(parent) = Path::new(origin).parent() {
      if !parent.as_os_str().is_empty() {
        compiler.add_include_dir(parent);
      }
    }
  }

  let mut source_code = SourceCode::from(source);
  if let Some(origin) = origin {
    source_code = source_code.with_origin(origin);
  }

  if tolerate {
    let _ = compiler.add_source(source_code);
    Ok(())
  } else {
    compiler
      .add_source(source_code)
      .map(|_| ())
      .map_err(|e| compile_error_to_napi(&e, env))
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
  let covered: std::collections::HashSet<*const CompileError> = compiler
    .ignored_rules()
    .filter_map(|(_, reason)| match reason {
      IgnoredRuleReason::CompileError(err) => Some(std::ptr::from_ref(err)),
      _ => None,
    })
    .collect();

  compiler
    .errors()
    .iter()
    .filter(|err| !covered.contains(&std::ptr::from_ref(*err)))
    .map(|err| {
      let (source, line, column) = diagnostic_location(err);
      CompilerError {
        code: err.code().to_string(),
        message: err.to_string(),
        source,
        line,
        column,
      }
    })
    .collect()
}

/// Rejects compilation errors that cannot be attributed to a skipped rule.
///
/// In tolerant mode yara-x records per-rule failures as ignored rules, but
/// source-level failures (syntax errors, invalid UTF-8, banned or unknown
/// module imports, include failures) are only placed in the error list. A
/// scanner built on top of those would silently lack rules, so surface them
/// instead.
pub fn ensure_no_uncovered_errors(compiler: &Compiler) -> Result<()> {
  let uncovered = uncovered_compiler_errors(compiler);
  if uncovered.is_empty() {
    return Ok(());
  }

  let details = uncovered
    .iter()
    .map(|e| format!("{}: {}", e.code, e.message))
    .collect::<Vec<_>>()
    .join("\n");
  Err(Error::new(
    Status::GenericFailure,
    format!("Compilation error(s) not attributable to a skipped rule: {details}"),
  ))
}

/// Applies compiler options to a YARA compiler instance.
///
/// This function configures the compiler based on the provided options,
/// including module handling, feature flags, and optimization settings.
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
/// Ok(()) on success, or an error if compilation or emission fails
pub fn compile_source_to_wasm(
  source: &str,
  output_path: &str,
  options: Option<&CompilerOptions>,
  origin: Option<&str>,
) -> Result<()> {
  let namespace = options.and_then(|opts| opts.namespace.as_deref());
  compile_sources_to_wasm(
    &[RuleSource {
      source: source.to_string(),
      namespace: namespace.map(str::to_string),
    }],
    &[origin.map(str::to_string)],
    output_path,
    options,
  )
}

/// Compiles YARA rule sources to a WASM file.
pub fn compile_sources_to_wasm(
  sources: &[RuleSource],
  origins: &[Option<String>],
  output_path: &str,
  options: Option<&CompilerOptions>,
) -> Result<()> {
  let mut compiler = Compiler::new();

  apply_compiler_options(&mut compiler, options, false)?;

  let ignore_invalid_rules = options
    .as_ref()
    .and_then(|opts| opts.ignore_invalid_rules)
    .unwrap_or(false);

  add_sources_and_emit(
    compiler,
    sources,
    origins,
    ignore_invalid_rules,
    output_path,
  )
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
  origins: &[Option<String>],
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

  add_sources_and_emit(
    compiler,
    sources,
    origins,
    ignore_invalid_rules,
    output_path,
  )
}

/// Adds all sources and emits the WASM module, rejecting source-level errors
/// outright when tolerating invalid rules (this path has no report channel).
fn add_sources_and_emit(
  mut compiler: Compiler<'_>,
  sources: &[RuleSource],
  origins: &[Option<String>],
  ignore_invalid_rules: bool,
  output_path: &str,
) -> Result<()> {
  for (index, rule_source) in sources.iter().enumerate() {
    // Emission has no report channel and runs without a JavaScript
    // environment, so the diagnostics are not decorated.
    add_source_to_compiler_tolerant(
      &mut compiler,
      &rule_source.source,
      rule_source.namespace.as_deref(),
      origins.get(index).and_then(Option::as_deref),
      ignore_invalid_rules,
      None,
    )?;
  }

  // Otherwise a tolerated source-level error would emit a WASM module that
  // silently lacks rules, with nowhere to report it.
  if ignore_invalid_rules {
    ensure_no_uncovered_errors(&compiler)?;
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
