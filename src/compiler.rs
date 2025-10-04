//! YARA compiler utilities and configuration.
//!
//! This module provides functions for configuring and using the YARA compiler,
//! including applying compiler options and generating WASM output.

use crate::error::compile_error_to_napi;
use crate::types::{CompilerOptions, VariableMap};
use crate::variables::VariableHandler;
use napi::bindgen_prelude::{JsObjectValue, Object};
use napi::{Error, Result, Status};
use std::collections::HashMap;
use std::path::Path;
use yara_x::Compiler;

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
  let mut compiler = Compiler::new();

  apply_compiler_options(&mut compiler, options, false)?;

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
