//! Variable handling for YARA-X compiler and scanner.
//!
//! This module provides utilities for applying variables to both the YARA compiler
//! and scanner, with automatic type inference for boolean, integer, and string values.

use crate::error::to_napi_err;
use crate::types::{CompilerError, CompilerWarning, VariableMap, VariableValue};
use napi::bindgen_prelude::{BigInt, JsObjectValue, Object, Unknown};
use napi::{Error, Result, Status, ValueType};
use std::collections::HashMap;
use yara_x::{Compiler, Scanner};

/// Trait for types that can have variables applied to them.
///
/// This trait is implemented by both `Compiler` and `Scanner` to provide
/// a unified interface for setting global variables.
pub trait VariableHandler {
  /// Applies a typed variable to the handler.
  fn apply_variable_value(&mut self, name: &str, value: &VariableValue) -> Result<()> {
    match value {
      VariableValue::Bool(value) => self.apply_bool_variable(name, *value),
      VariableValue::Integer(value) => self.apply_integer_variable(name, *value),
      VariableValue::Float(value) => self.apply_float_variable(name, *value),
      VariableValue::String(value) => self.apply_string_variable(name, value),
    }
  }

  /// Applies a boolean variable to the handler.
  fn apply_bool_variable(&mut self, name: &str, value: bool) -> Result<()>;

  /// Applies an integer variable to the handler.
  fn apply_integer_variable(&mut self, name: &str, value: i64) -> Result<()>;

  /// Applies a floating-point variable to the handler.
  fn apply_float_variable(&mut self, name: &str, value: f64) -> Result<()>;

  /// Applies a string variable to the handler.
  fn apply_string_variable(&mut self, name: &str, value: &str) -> Result<()>;

  /// Applies variables from a map to the handler.
  fn apply_variables_from_map(&mut self, variables: &Option<VariableMap>) -> Result<()> {
    if let Some(vars) = variables {
      for (key, value) in vars {
        self.apply_variable_value(key, value)?;
      }
    }
    Ok(())
  }

  /// Applies variables from a JavaScript object to the handler.
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

macro_rules! impl_variable_handler {
  ($target:ident, $setter:ident) => {
    impl<'a> VariableHandler for $target<'a> {
      fn apply_bool_variable(&mut self, name: &str, value: bool) -> Result<()> {
        self.$setter(name, value).map(|_| ()).map_err(to_napi_err)
      }

      fn apply_integer_variable(&mut self, name: &str, value: i64) -> Result<()> {
        self.$setter(name, value).map(|_| ()).map_err(to_napi_err)
      }

      fn apply_float_variable(&mut self, name: &str, value: f64) -> Result<()> {
        self.$setter(name, value).map(|_| ()).map_err(to_napi_err)
      }

      fn apply_string_variable(&mut self, name: &str, value: &str) -> Result<()> {
        self.$setter(name, value).map(|_| ()).map_err(to_napi_err)
      }
    }
  };
}

impl_variable_handler!(Scanner, set_global);
impl_variable_handler!(Compiler, define_global);

/// Reads a JavaScript value and converts it into a YARA global variable.
pub fn get_variable_value(vars: &Object, key: &str) -> Result<VariableValue> {
  let value = vars.get_named_property::<Unknown>(key)?;
  variable_value_from_unknown(value, key)
}

/// Converts a raw JavaScript value into a YARA global variable.
///
/// `key` is only used in error messages. JavaScript has no distinct unsigned
/// integer type, so whole `number`s inside the `i64` range become integers,
/// other numbers become floats, and `bigint` becomes an exact integer.
pub fn variable_value_from_unknown(value: Unknown<'_>, key: &str) -> Result<VariableValue> {
  match value.get_type()? {
    ValueType::Boolean => Ok(VariableValue::Bool(unsafe { value.cast::<bool>()? })),
    ValueType::Number => {
      let number = unsafe { value.cast::<f64>()? };
      // Only whole numbers strictly below 2^63 are convertible to i64
      // exactly. `i64::MAX as f64` rounds up to 2^63, so a value at or above
      // that boundary would silently saturate to i64::MAX in an `as i64`
      // cast — treat it as a float instead.
      if number.fract() == 0.0 && number >= i64::MIN as f64 && number < i64::MAX as f64 {
        Ok(VariableValue::Integer(number as i64))
      } else {
        Ok(VariableValue::Float(number))
      }
    }
    ValueType::String => Ok(VariableValue::String(unsafe { value.cast::<String>()? })),
    ValueType::BigInt => {
      let bigint = unsafe { value.cast::<BigInt>()? };
      let (integer, lossless) = bigint.get_i64();
      if lossless {
        Ok(VariableValue::Integer(integer))
      } else {
        Err(Error::new(
          Status::InvalidArg,
          format!(
            "BigInt variable `{key}` is outside the signed 64-bit range YARA integers support"
          ),
        ))
      }
    }
    value_type => Err(Error::new(
      Status::InvalidArg,
      format!(
        "Unsupported variable type for `{key}`: {}",
        js_type_name(value_type)
      ),
    )),
  }
}

/// Returns the JavaScript `typeof`-style name for a napi value type.
fn js_type_name(value_type: ValueType) -> &'static str {
  match value_type {
    ValueType::Undefined => "undefined",
    ValueType::Null => "null",
    ValueType::Boolean => "boolean",
    ValueType::Number => "number",
    ValueType::String => "string",
    ValueType::Symbol => "symbol",
    ValueType::Object => "object",
    ValueType::Function => "function",
    ValueType::External => "external",
    ValueType::BigInt => "bigint",
    ValueType::Unknown => "unknown",
  }
}

/// Extracts the source origin and 1-based line/column from a compiler
/// diagnostic.
///
/// yara-x computes these while rendering the report, but only exposes the
/// rendered message on the error/warning value itself. Its `Serialize` impl
/// carries the same data — `line`/`column` for the report and `code_origin`
/// per label — so read it from there instead of re-parsing the message.
pub fn diagnostic_location<T: serde::Serialize>(
  diagnostic: &T,
) -> (Option<String>, Option<u32>, Option<u32>) {
  let Ok(report) = serde_json::to_value(diagnostic) else {
    return (None, None, None);
  };

  let labels = report.get("labels").and_then(serde_json::Value::as_array);

  let as_u32 = |value: Option<&serde_json::Value>| {
    value
      .and_then(serde_json::Value::as_u64)
      .map(|value| value as u32)
  };

  let source = labels.and_then(|labels| {
    labels.iter().find_map(|label| {
      label
        .get("code_origin")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
    })
  });

  let line = as_u32(report.get("line")).or_else(|| {
    labels
      .and_then(|labels| labels.first())
      .and_then(|label| as_u32(label.get("line")))
  });
  let column = as_u32(report.get("column")).or_else(|| {
    labels
      .and_then(|labels| labels.first())
      .and_then(|label| as_u32(label.get("column")))
  });

  (source, line, column)
}

/// Converts a JavaScript object of variables to a VariableMap.
///
/// This is used for async operations where we need to transfer variables
/// across thread boundaries.
pub fn convert_variables_to_map(variables: Option<Object>) -> Result<Option<VariableMap>> {
  let Some(vars) = variables else {
    return Ok(None);
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
pub fn convert_compiler_messages<T, U>(messages: &[T], to_output: impl Fn(&T) -> U) -> Vec<U> {
  messages.iter().map(to_output).collect()
}

/// Extracts compiler errors from a Compiler instance.
///
/// A vector of CompilerError structs
pub fn get_compiler_errors(compiler: &Compiler) -> Vec<CompilerError> {
  convert_compiler_messages(compiler.errors(), |e| {
    let (source, line, column) = diagnostic_location(e);
    CompilerError {
      code: e.code().to_string(),
      message: e.to_string(),
      source,
      line,
      column,
    }
  })
}

/// Extracts compiler warnings from a Compiler instance.
pub fn get_compiler_warnings(compiler: &Compiler) -> Vec<CompilerWarning> {
  convert_compiler_messages(compiler.warnings(), |w| {
    let (source, line, column) = diagnostic_location(w);
    CompilerWarning {
      code: w.code().to_string(),
      message: w.to_string(),
      source,
      line,
      column,
    }
  })
}
