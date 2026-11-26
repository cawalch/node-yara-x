//! Error handling utilities for YARA-X Node.js bindings.
//!
//! This module provides conversion functions from YARA-X errors to N-API errors,
//! ensuring proper error propagation to JavaScript.

use napi::{Error, Status};
use yara_x::errors::CompileError;

/// Converts a YARA compilation error into a N-API error, prefixing the code.
pub fn compile_error_to_napi(error: &CompileError) -> Error {
  Error::new(
    Status::GenericFailure,
    format!("Compilation error ({}): {error}", error.code()),
  )
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
