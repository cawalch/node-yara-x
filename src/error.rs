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

/// Stable discriminator thrown as `kind`, so a caller can branch on the class
/// of failure without parsing `message` (#282).
///
/// These values are the contract: adding one is a minor change, renaming one is
/// not. A stamp never replaces `code`, `message`, or `ruleCode` - `code` stays
/// the N-API status, and a compile error keeps its `E0nn` in `ruleCode`.
pub const KIND_COMPILE: &str = "compile";
/// A scan exceeded the deadline set with `setTimeout()`.
pub const KIND_TIMEOUT: &str = "timeout";
/// Reading a file failed (rule file, scanned file, or serialized blob).
pub const KIND_IO: &str = "io";
/// Memory-mapping a scanned file failed.
pub const KIND_MMAP: &str = "mmap";
/// A module produced protobuf that could not be decoded.
pub const KIND_PROTOBUF: &str = "protobuf";
/// A rule referenced a module this build does not include.
pub const KIND_UNKNOWN_MODULE: &str = "unknown-module";
/// A scan cancelled through an `AbortSignal` (#285).
pub const KIND_CANCELLED: &str = "cancelled";
/// A failure the wrapper does not classify yet.
pub const KIND_UNKNOWN: &str = "unknown";

/// Builds the error to throw, stamped with `kind` wherever a JS object exists.
///
/// The background tasks have no `Env`, so an async rejection keeps the plain
/// error and `kind` is absent. Decoration must never cost a caller the message
/// or the `code` it already had: any failure to build or stamp the object
/// throws the plain error instead.
fn stamped(env: Option<&Env>, status: Status, message: String, kind: &'static str) -> Error {
  stamped_props(env, status, message, &[("kind", kind)])
}

/// Builds the error to throw with each `(key, value)` as an own string property; the
/// abort rejection uses this for `name`, which an `Error` built in Rust cannot carry.
fn stamped_props(
  env: Option<&Env>,
  status: Status,
  message: String,
  props: &[(&str, &str)],
) -> Error {
  let Some(env) = env else {
    return Error::new(status, message);
  };

  match env.create_error(Error::new(status, message.clone())) {
    Ok(mut object) => {
      for &(key, value) in props {
        if object.set_named_property(key, value).is_err() {
          return Error::new(status, message);
        }
      }
      // The object built here is the object that is thrown; see the note in
      // [`decorated`].
      Error::from_unknown_without_coercion(unsafe {
        Unknown::from_raw_unchecked(env.raw(), object.raw())
      })
    }
    Err(_) => Error::new(status, message),
  }
}

/// `name` and `message` N-API gives async work it cancels (`async_work.rs`).
const ABORT_MESSAGE: &str = "AbortError";

/// Builds the rejection for work cancelled through an `AbortSignal`: `code` `Cancelled`,
/// `name` and `message` `AbortError`, so one check catches a scan cancelled here and one
/// N-API cancelled itself, and `kind` `cancelled` to keep the rejection inside the `kind`
/// contract of the other failures. Off-thread neither stamp applies: [`stamped_abort`].
pub fn abort_error(env: Option<&Env>) -> Error {
  stamped_props(
    env,
    Status::Cancelled,
    ABORT_MESSAGE.to_owned(),
    &[("name", ABORT_MESSAGE), ("kind", KIND_CANCELLED)],
  )
}

/// Adds the abort `name` and `kind` to a rejection built on a worker thread; `Task::reject`
/// is the only later place with an environment. Anything else is returned untouched.
pub fn stamped_abort(env: &Env, error: Error) -> Error {
  if error.status == Status::Cancelled && error.reason == ABORT_MESSAGE {
    abort_error(Some(env))
  } else {
    error
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

  object.set_named_property("kind", KIND_COMPILE).ok()?;
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

/// Converts a YARA scan error into a N-API error carrying a `kind`.
///
/// `env` is the current environment when one exists; the background tasks pass
/// `None` and their rejections keep the plain, unstamped error.
pub fn scan_error_to_napi(error: yara_x::ScanError, env: Option<&Env>) -> Error {
  match error {
    yara_x::ScanError::Timeout => stamped(
      env,
      Status::Cancelled,
      "Scan timed out".into(),
      KIND_TIMEOUT,
    ),
    yara_x::ScanError::OpenError { path, err } => stamped(
      env,
      Status::GenericFailure,
      format!("I/O error (reading file {}): {err}", path.display()),
      KIND_IO,
    ),
    yara_x::ScanError::MapError { path, err } => stamped(
      env,
      Status::GenericFailure,
      format!("Failed to map file '{}': {err}", path.display()),
      KIND_MMAP,
    ),
    yara_x::ScanError::ProtoError { module, err } => stamped(
      env,
      Status::GenericFailure,
      format!("Protobuf error in module '{module}': {err}"),
      KIND_PROTOBUF,
    ),
    yara_x::ScanError::UnknownModule { module } => stamped(
      env,
      Status::GenericFailure,
      format!("Unknown module: '{module}'"),
      KIND_UNKNOWN_MODULE,
    ),
    other => stamped(
      env,
      Status::GenericFailure,
      format!("Unknown scan error: {other:?}"),
      KIND_UNKNOWN,
    ),
  }
}

/// Wraps an I/O error with a description of the failed operation, stamped `io`.
pub fn io_error_to_napi(error: std::io::Error, context: &str, env: Option<&Env>) -> Error {
  stamped(
    env,
    Status::GenericFailure,
    format!("I/O error ({context}): {error}"),
    KIND_IO,
  )
}

/// Wraps any `Display` error as a N-API error.
///
/// A N-API error with the error's display representation
pub fn to_napi_err<E: std::fmt::Display>(err: E) -> Error {
  Error::new(Status::GenericFailure, err.to_string())
}
