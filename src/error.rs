//! Error handling utilities for YARA-X Node.js bindings.
//!
//! This module provides conversion functions from YARA-X errors to N-API errors,
//! ensuring proper error propagation to JavaScript.

use crate::variables::diagnostic_location;
use napi::bindgen_prelude::{JsObjectValue, Unknown};
use napi::{Env, Error, JsValue, Status};
use yara_x::errors::CompileError;

/// Converts a YARA compilation error into a N-API error, prefixing the code.
///
/// With an `Env`, the thrown error also carries `ruleCode` (the `E0nn` code) and,
/// when the diagnostic has one, `source`, `line` and `column` - the same names as
/// the `CompilerError` objects from `getCompilationErrors()` - so a caller can
/// branch without parsing `message`. Its `code` and `message` are exactly what
/// they were without the fields. The background tasks have no `Env` and pass
/// `None`, so they keep throwing the plain error.
pub fn compile_error_to_napi(error: &CompileError, env: Option<&Env>) -> Error {
  let message = format!("Compilation error ({}): {error}", error.code());

  match env.and_then(|env| decorated(env, &message, error)) {
    Some(error) => error,
    None => Error::new(Status::GenericFailure, message),
  }
}

/// Builds the thrown error as an object carrying the diagnostic fields.
///
/// Returns `None` if the object cannot be built or decorated: the extra fields
/// must never cost a caller the message or the code it already had.
fn decorated(env: &Env, message: &str, error: &CompileError) -> Option<Error> {
  let mut object = env
    .create_error(Error::new(Status::GenericFailure, message))
    .ok()?;

  object.set_named_property("ruleCode", error.code()).ok()?;

  let (source, line, column) = diagnostic_location(error);
  if let Some(source) = source {
    object.set_named_property("source", source).ok()?;
  }
  if let Some(line) = line {
    object.set_named_property("line", line).ok()?;
  }
  if let Some(column) = column {
    object.set_named_property("column", column).ok()?;
  }

  // The object built above is the object that is thrown: napi's throw path
  // reuses a retained JavaScript error instead of rebuilding one, so own
  // properties reach the caller (`napi-3.16.2/src/error.rs`,
  // `JsError::into_value`, and `Error::from_unknown_without_coercion`).
  Some(Error::from_unknown_without_coercion(unsafe {
    Unknown::from_raw_unchecked(env.raw(), object.raw())
  }))
}

/// Converts a YARA scan error into a N-API error.
///
pub fn scan_error_to_napi(error: yara_x::ScanError) -> Error {
  match error {
    yara_x::ScanError::Timeout => Error::new(Status::Cancelled, "Scan timed out"),
    yara_x::ScanError::OpenError { path, err } => Error::new(
      Status::GenericFailure,
      format!("I/O error (reading file {}): {err}", path.display()),
    ),
    yara_x::ScanError::MapError { path, err } => Error::new(
      Status::GenericFailure,
      format!("Failed to map file '{}': {err}", path.display()),
    ),
    yara_x::ScanError::ProtoError { module, err } => Error::new(
      Status::GenericFailure,
      format!("Protobuf error in module '{module}': {err}"),
    ),
    yara_x::ScanError::UnknownModule { module } => Error::new(
      Status::GenericFailure,
      format!("Unknown module: '{module}'"),
    ),
    other => Error::new(
      Status::GenericFailure,
      format!("Unknown scan error: {other:?}"),
    ),
  }
}

/// Wraps an I/O error with a description of the failed operation.
pub fn io_error_to_napi(error: std::io::Error, context: &str) -> Error {
  Error::new(
    Status::GenericFailure,
    format!("I/O error ({context}): {error}"),
  )
}

/// Wraps any `Display` error as a N-API error.
///
/// A N-API error with the error's display representation
pub fn to_napi_err<E: std::fmt::Display>(err: E) -> Error {
  Error::new(Status::GenericFailure, err.to_string())
}
