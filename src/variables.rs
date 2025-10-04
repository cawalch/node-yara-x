//! Variable handling for YARA-X compiler and scanner.
//!
//! This module provides utilities for applying variables to both the YARA compiler
//! and scanner, with automatic type inference for boolean, integer, and string values.

use crate::error::to_napi_err;
use crate::types::{CompilerError, CompilerWarning, VariableMap};
use napi::bindgen_prelude::{JsObjectValue, Object};
use napi::Result;
use std::collections::HashMap;
use std::fmt::Display;
use yara_x::{Compiler, Scanner};

/// Trait for types that can have variables applied to them.
///
/// This trait is implemented by both `Compiler` and `Scanner` to provide
/// a unified interface for setting global variables.
pub trait VariableHandler {
  /// Applies a single variable to the handler.
  ///
  /// The value is automatically parsed as boolean, integer, or string.
  ///
  /// # Arguments
  ///
  /// * `name` - The variable name
  /// * `value` - The variable value as a string
  fn apply_variable(&mut self, name: &str, value: &str) -> Result<()>;

  /// Applies variables from a map to the handler.
  ///
  /// # Arguments
  ///
  /// * `variables` - Optional map of variable names to values
  fn apply_variables_from_map(&mut self, variables: &Option<VariableMap>) -> Result<()> {
    if let Some(vars) = variables {
      for (key, value) in vars {
        self.apply_variable(key, value)?;
      }
    }
    Ok(())
  }

  /// Applies variables from a JavaScript object to the handler.
  ///
  /// # Arguments
  ///
  /// * `variables` - Optional N-API object containing variables
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
  ///
  /// Values are parsed in the following order:
  /// 1. Boolean ("true" or "false", case-insensitive)
  /// 2. Integer (valid i64)
  /// 3. String (fallback)
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
  ///
  /// Values are parsed in the following order:
  /// 1. Boolean ("true" or "false", case-insensitive)
  /// 2. Integer (valid i64)
  /// 3. String (fallback)
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

/// Converts a JavaScript object of variables to a VariableMap.
///
/// This is used for async operations where we need to transfer variables
/// across thread boundaries.
///
/// # Arguments
///
/// * `variables` - Optional N-API object containing variables
///
/// # Returns
///
/// An optional HashMap of variable names to values
pub fn convert_variables_to_map(variables: Option<Object>) -> Result<Option<VariableMap>> {
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

/// Converts a list of compiler messages to a vector of output types.
///
/// This is a generic helper for converting both warnings and errors.
///
/// # Arguments
///
/// * `messages` - Slice of compiler messages
/// * `to_output` - Function to convert each message to the output type
///
/// # Returns
///
/// A vector of converted messages
pub fn convert_compiler_messages<T, U>(messages: &[T], to_output: impl Fn(&T) -> U) -> Vec<U>
where
  T: Display,
{
  let mut result = Vec::with_capacity(messages.len());
  for msg in messages {
    result.push(to_output(msg));
  }
  result
}

/// Extracts compiler errors from a Compiler instance.
///
/// # Arguments
///
/// * `compiler` - The YARA compiler
///
/// # Returns
///
/// A vector of CompilerError structs
pub fn get_compiler_errors(compiler: &Compiler) -> Result<Vec<CompilerError>> {
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

/// Extracts compiler warnings from a Compiler instance.
///
/// # Arguments
///
/// * `compiler` - The YARA compiler
///
/// # Returns
///
/// A vector of CompilerWarning structs
pub fn get_compiler_warnings(compiler: &Compiler) -> Result<Vec<CompilerWarning>> {
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
