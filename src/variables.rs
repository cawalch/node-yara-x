//! Variable handling for YARA-X compiler and scanner.
//!
//! This module provides utilities for applying variables to both the YARA compiler
//! and scanner, with automatic type inference for boolean, integer, and string values.

use crate::error::to_napi_err;
use crate::types::{CompilerError, CompilerWarning, VariableMap, VariableValue};
use napi::bindgen_prelude::{JsObjectValue, Object, Unknown};
use napi::{Error, Result, Status, ValueType};
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

  /// Applies a typed variable to the handler.
  fn apply_variable_value(&mut self, name: &str, value: &VariableValue) -> Result<()> {
    match value {
      VariableValue::Bool(value) => self.apply_bool_variable(name, *value),
      VariableValue::Integer(value) => self.apply_integer_variable(name, *value),
      VariableValue::Float(value) => self.apply_float_variable(name, *value),
      VariableValue::String(value) => self.apply_variable(name, value),
    }
  }

  /// Applies a boolean variable to the handler.
  fn apply_bool_variable(&mut self, name: &str, value: bool) -> Result<()>;

  /// Applies an integer variable to the handler.
  fn apply_integer_variable(&mut self, name: &str, value: i64) -> Result<()>;

  /// Applies a floating-point variable to the handler.
  fn apply_float_variable(&mut self, name: &str, value: f64) -> Result<()>;

  /// Applies variables from a map to the handler.
  ///
  /// # Arguments
  ///
  /// * `variables` - Optional map of variable names to values
  fn apply_variables_from_map(&mut self, variables: &Option<VariableMap>) -> Result<()> {
    if let Some(vars) = variables {
      for (key, value) in vars {
        self.apply_variable_value(key, value)?;
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
        let value = get_variable_value(vars, key)?;
        self.apply_variable_value(key, &value)?;
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

  fn apply_bool_variable(&mut self, name: &str, value: bool) -> Result<()> {
    self.set_global(name, value).map(|_| ()).map_err(to_napi_err)
  }

  fn apply_integer_variable(&mut self, name: &str, value: i64) -> Result<()> {
    self.set_global(name, value).map(|_| ()).map_err(to_napi_err)
  }

  fn apply_float_variable(&mut self, name: &str, value: f64) -> Result<()> {
    self.set_global(name, value).map(|_| ()).map_err(to_napi_err)
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

  fn apply_bool_variable(&mut self, name: &str, value: bool) -> Result<()> {
    self.define_global(name, value).map(|_| ()).map_err(to_napi_err)
  }

  fn apply_integer_variable(&mut self, name: &str, value: i64) -> Result<()> {
    self.define_global(name, value).map(|_| ()).map_err(to_napi_err)
  }

  fn apply_float_variable(&mut self, name: &str, value: f64) -> Result<()> {
    self.define_global(name, value).map(|_| ()).map_err(to_napi_err)
  }
}

/// Reads a JavaScript value and converts it into a YARA global variable.
pub fn get_variable_value(vars: &Object, key: &str) -> Result<VariableValue> {
  let value = vars.get_named_property::<Unknown>(key)?;

  match value.get_type()? {
    ValueType::Boolean => Ok(VariableValue::Bool(unsafe { value.cast::<bool>()? })),
    ValueType::Number => {
      let value = unsafe { value.cast::<f64>()? };
      if value.fract() == 0.0 && value >= i64::MIN as f64 && value <= i64::MAX as f64 {
        Ok(VariableValue::Integer(value as i64))
      } else {
        Ok(VariableValue::Float(value))
      }
    }
    ValueType::String => Ok(VariableValue::String(unsafe { value.cast::<String>()? })),
    value_type => Err(Error::new(
      Status::InvalidArg,
      format!("Unsupported variable type for `{key}`: {value_type}"),
    )),
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

  for key in &property_names {
    let value = get_variable_value(&vars, key)?;
    map.insert(key.clone(), value);
  }

  Ok(Some(map))
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
