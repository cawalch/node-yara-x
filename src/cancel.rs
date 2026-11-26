//! Cancellation for the asynchronous entry points, on N-API's own `AbortSignal`: the
//! wrapper cancels work that has not started, and `on_abort` mirrors a later abort into
//! the flag the batch workers read between files.

use napi::bindgen_prelude::{AbortSignal, Env};
use napi::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use crate::error::abort_error;

/// The abort as worker threads see it; cloned into a batch's file loop.
#[derive(Clone, Default)]
pub struct CancelFlag(Arc<AtomicBool>);

impl CancelFlag {
  /// The flag of a call made without a signal: one shared cell, never set.
  pub fn never() -> Self {
    static NEVER: OnceLock<CancelFlag> = OnceLock::new();
    NEVER.get_or_init(CancelFlag::default).clone()
  }

  pub fn is_cancelled(&self) -> bool {
    self.0.load(Ordering::Relaxed)
  }

  pub fn reject_if_cancelled(&self) -> Result<()> {
    if self.is_cancelled() {
      Err(abort_error(None))
    } else {
      Ok(())
    }
  }
}

/// What one call knows about its cancellation. N-API owns the listener, so there is
/// nothing to take back off the signal when the call settles.
pub struct CancelState {
  pub flag: CancelFlag,
}

impl CancelState {
  pub fn never() -> Self {
    Self {
      flag: CancelFlag::never(),
    }
  }

  pub fn reject_if_cancelled(&self) -> Result<()> {
    self.flag.reject_if_cancelled()
  }

  pub fn release(&mut self, _env: &Env) {}
}

/// Turns the `signal` argument into task state: a later abort sets the flag the batch
/// workers read, and N-API cancels a queued single scan through the same signal.
pub fn dispatch_cancel(signal: &Option<AbortSignal>) -> Result<CancelState> {
  let Some(signal) = signal else {
    return Ok(CancelState::never());
  };
  let flag = CancelFlag::default();
  let watched = flag.clone();
  signal.on_abort(move || watched.0.store(true, Ordering::Relaxed));
  Ok(CancelState { flag })
}
