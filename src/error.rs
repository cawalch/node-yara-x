//! Error handling utilities for YARA-X Node.js bindings.
//!
//! This module provides conversion functions from YARA-X errors to N-API errors,
//! ensuring proper error propagation to JavaScript.

use napi::{Error, Status};
use yara_x::errors::CompileError;

/// Converts a YARA compilation error to a N-API error.
///
/// # Arguments
///
/// * `error` - The compilation error from YARA-X
///
/// # Returns
///
/// A N-API error with appropriate status and message
pub fn compile_error_to_napi(error: &CompileError) -> Error {
  Error::new(
    Status::GenericFailure,
    format!("Compilation error ({}): {}", error.code(), error),
  )
}

/// Converts a YARA scan error to a N-API error.
///
/// Maps different scan error types to appropriate error messages.
///
/// # Arguments
///
/// * `error` - The scan error from YARA-X
///
/// # Returns
///
/// A N-API error with appropriate status and message
pub fn scan_error_to_napi(error: yara_x::ScanError) -> Error {
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
      format!("Protobuf error in module '{module}': {err}"),
    ),
    yara_x::ScanError::UnknownModule { module } => Error::new(
      Status::GenericFailure,
      format!("Unknown module: '{module}'"),
    ),
    _ => Error::new(
      Status::GenericFailure,
      format!("Unknown scan error: {error:?}"),
    ),
  }
}

/// Converts an I/O error to a N-API error with context.
///
/// # Arguments
///
/// * `error` - The I/O error
/// * `context` - A description of what operation failed
///
/// # Returns
///
/// A N-API error with appropriate status and message
pub fn io_error_to_napi(error: std::io::Error, context: &str) -> Error {
  Error::new(
    Status::GenericFailure,
    format!("I/O error ({context}): {error}"),
  )
}

/// Converts a generic error to a N-API error.
///
/// This is a catch-all converter for any error type that implements Display.
///
/// # Arguments
///
/// * `err` - Any error that implements Display
///
/// # Returns
///
/// A N-API error with the error's display representation
pub fn to_napi_err<E: std::fmt::Display>(err: E) -> Error {
  Error::new(Status::GenericFailure, err.to_string())
}
