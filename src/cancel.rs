//! Cancellation for the asynchronous entry points: a `signal?: AbortSignal` stops work
//! that has not started. Already-aborted rejects before dispatch, aborted while queued is
//! caught at the top of `compute()`, and a batch skips what it had not reached and
//! resolves with the part it got. A running scan cannot be preempted — that stays
//! `setTimeout()` / `setMaxScanSize()`. Every cancellation rejects with `AbortError` and
//! `code` `Cancelled`, and none throws from the call.
//!
//! The abort is watched by a listener hung on the signal for the life of the call, not by
//! N-API's `AbortSignal` wrapper: a wrapper conversion retains ~250 bytes for the life of
//! the signal, and sees no signal that aborted before the call (#305 measures both). What
//! that listener reaches is an id, never a pointer — the flag is published in [`WATCHING`]
//! only while its call runs, so a listener
//! the caller refused to un-listen looks up a miss and writes nothing, and memory follows
//! cancelled scans *in flight*, not scans ever made.

use napi::bindgen_prelude::{FromNapiValue, Object, TypeName, ValidateNapiValue};
use napi::{Env, Error, Result, Status, ValueType};
use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::{c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};

use crate::error::abort_error;

/// Success, spelled once.
const OK: c_int = napi::sys::Status::napi_ok;

const ABORT_EVENT: &CStr = c"abort";

const ABORT_LISTENER: &CStr = c"yaraXAbortListener";

/// The abort as the worker threads see it; cloned into a batch's file loop.
#[derive(Clone, Default)]
pub struct CancelFlag(Arc<AtomicBool>);

impl CancelFlag {
  /// What a call without a signal runs with: one shared cell, never set, so the
  /// 120k-calls/s path allocates nothing.
  pub fn never() -> Self {
    static NEVER: LazyLock<CancelFlag> = LazyLock::new(CancelFlag::default);
    NEVER.clone()
  }

  /// Whether the signal has aborted.
  pub fn is_cancelled(&self) -> bool {
    self.0.load(Ordering::Relaxed)
  }

  /// Refuses the scan once the signal has aborted — the last point it still can.
  pub fn reject_if_cancelled(&self) -> Result<()> {
    // Without an `env`: `Task::reject` stamps the `name` where a JavaScript object can be
    // built. A signal aborted before the call gets here too, its flag set at argument read
    // time.
    if self.is_cancelled() {
      return Err(abort_error(None));
    }
    Ok(())
  }
}

/// The flags of the calls currently watching a signal, by the id their listener carries.
/// An entry lives as long as its call, ids are never reused, and a lookup is the whole of
/// what the listener does — so a listener outliving its call cannot reach another call's
/// flag, and nothing a caller keeps alive can make this grow.
static WATCHING: LazyLock<Mutex<HashMap<usize, Arc<AtomicBool>>>> = LazyLock::new(Mutex::default);

/// Ids start at 1, so a listener's N-API `data` is never the null pointer.
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

/// A poisoned lock is taken as it is: these sections only insert, look up and remove, so
/// an unrelated panic must not disable cancellation for the rest of the process. No
/// JavaScript call is made while the lock is held — an abort listener may start a scan on
/// this same thread, and a non-reentrant lock would then wait on itself.
fn watching() -> MutexGuard<'static, HashMap<usize, Arc<AtomicBool>>> {
  WATCHING.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Publishes a flag for the life of one call and returns the id to hand its listener.
fn watch(flag: &Arc<AtomicBool>) -> usize {
  let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
  watching().insert(id, Arc::clone(flag));
  id
}

/// Takes it back; anything still holding that id is inert from here.
fn unwatch(id: usize) {
  watching().remove(&id);
}

/// What one call knows about its cancellation; `Task::finally` calls [`Self::release`],
/// and [`Drop`] covers the paths that never get there.
pub struct CancelState {
  /// The flag to hand to whatever runs on worker threads.
  pub flag: CancelFlag,
  /// The registry id and the two handles of an attached listener; `None` for a call
  /// without a signal, and for one whose signal had already aborted.
  held: Option<Held>,
}

/// The handles a call needs to take its listener back off the signal.
struct Held {
  id: usize,
  signal: napi::sys::napi_ref,
  listener: napi::sys::napi_ref,
}

// SAFETY: handles into the environment the call was made on, touched only on the
// JavaScript thread — attached during the call, released in `Task::finally`.
unsafe impl Send for Held {}

impl CancelState {
  /// The state of a call made without a signal.
  pub fn never() -> Self {
    Self {
      flag: CancelFlag::never(),
      held: None,
    }
  }

  /// Refuses the scan if the signal has aborted.
  pub fn reject_if_cancelled(&self) -> Result<()> {
    self.flag.reject_if_cancelled()
  }

  /// Gives the flag back, then takes the listener off the signal. Best effort and
  /// silent: the scan is over either way, and a settled promise must not turn into a
  /// rejected one. The registry goes first, so a listener the signal refused to
  /// un-listen is inert before anything else is released.
  pub fn release(&mut self, env: &Env) {
    let Some(held) = self.held.take() else {
      return;
    };
    unwatch(held.id);
    let Held {
      signal,
      listener,
      id: _,
    } = held;
    let raw_env = env.raw();
    let mut signal_value = ptr::null_mut();
    let mut listener_value = ptr::null_mut();
    if (unsafe { napi::sys::napi_get_reference_value(raw_env, signal, &mut signal_value) }) == OK
      && (unsafe { napi::sys::napi_get_reference_value(raw_env, listener, &mut listener_value) })
        == OK
    {
      unsafe {
        event_listener(
          raw_env,
          signal_value,
          listener_value,
          c"removeEventListener",
        );
      }
    }
    unsafe {
      napi::sys::napi_delete_reference(raw_env, signal);
      napi::sys::napi_delete_reference(raw_env, listener);
    }
  }
}

impl Drop for CancelState {
  /// Gives the flag back even when the task never reached `Task::finally`, so a dispatch
  /// that failed on the way in cannot publish one forever. No environment is needed to
  /// make a left-behind listener harmless — its id no longer resolves — which is why
  /// `release` unwatches before taking the listener off.
  fn drop(&mut self) {
    if let Some(held) = &self.held {
      unwatch(held.id);
    }
  }
}

/// Turns the `signal` argument into task state, in the calling frame — which is what makes
/// the raw handle in [`CancelSignal`] usable.
pub fn dispatch_cancel(env: &Env, signal: Option<CancelSignal>) -> Result<CancelState> {
  match signal {
    Some(signal) => signal.dispatch(env),
    None => Ok(CancelState::never()),
  }
}

/// An `AbortSignal` argument: validated and read, not yet attached. `signal` is valid
/// until the wrapper returns — the window [`dispatch_cancel`] uses it in.
pub struct CancelSignal {
  aborted: bool,
  signal: napi::sys::napi_value,
}

impl TypeName for CancelSignal {
  fn type_name() -> &'static str {
    "AbortSignal"
  }

  fn value_type() -> ValueType {
    ValueType::Object
  }
}

/// Runs before converting, for an argument that is not an object at all.
impl ValidateNapiValue for CancelSignal {}

impl FromNapiValue for CancelSignal {
  /// # Safety
  ///
  /// `env` and `napi_val` are what the generated N-API wrapper passes: a live
  /// environment and a live value.
  unsafe fn from_napi_value(
    env: napi::sys::napi_env,
    napi_val: napi::sys::napi_value,
  ) -> Result<Self> {
    if napi_val.is_null() {
      return Err(not_a_signal());
    }
    let signal = unsafe { Object::from_napi_value(env, napi_val)? };
    // All three parts are required, and `get` walks the prototype chain to find them:
    // `aborted` comes from `AbortSignal.prototype`, the listener methods from
    // `EventTarget`. Refuse a value that is not a signal rather than accept one that
    // quietly never cancels.
    let aborted = match signal.get::<bool>("aborted") {
      Ok(Some(aborted)) => aborted,
      // A getter that throws leaves an exception pending, and that must not outlive
      // the call that refused the argument.
      _ => {
        unsafe { clear_pending(env) };
        return Err(not_a_signal());
      }
    };
    if named_function(env, napi_val, c"addEventListener").is_none()
      || named_function(env, napi_val, c"removeEventListener").is_none()
    {
      return Err(not_a_signal());
    }

    Ok(Self {
      aborted,
      signal: napi_val,
    })
  }
}

impl CancelSignal {
  /// Publishes a flag and hangs the listener on it; an abort that already happened leaves
  /// the flag set and registers nothing, since a signal that has aborted never fires again.
  fn dispatch(self, env: &Env) -> Result<CancelState> {
    let flag = Arc::new(AtomicBool::new(self.aborted));
    if self.aborted {
      return Ok(CancelState {
        flag: CancelFlag(flag),
        held: None,
      });
    }

    let id = watch(&flag);
    let raw_env = env.raw();
    let mut listener = ptr::null_mut();
    if unsafe {
      napi::sys::napi_create_function(
        raw_env,
        ABORT_LISTENER.as_ptr(),
        ABORT_LISTENER.to_bytes().len() as isize,
        Some(observe_abort),
        // All the callback needs, as an integer in the pointer N-API hands it.
        id as *mut c_void,
        &mut listener,
      )
    } != OK
    {
      unwatch(id);
      return Err(Error::new(
        Status::GenericFailure,
        "failed to build the abort listener",
      ));
    }

    // The signal is referenced as well as the listener: `removeEventListener` needs
    // both at settlement, and nothing else keeps the target alive past this frame.
    let mut refs = [ptr::null_mut(); 2];
    let attached = unsafe {
      napi::sys::napi_create_reference(raw_env, self.signal, 1, &mut refs[0]) == OK
        && napi::sys::napi_create_reference(raw_env, listener, 1, &mut refs[1]) == OK
        && event_listener(raw_env, self.signal, listener, c"addEventListener")
    };
    if !attached {
      unsafe {
        for handle in refs {
          if !handle.is_null() {
            napi::sys::napi_delete_reference(raw_env, handle);
          }
        }
      }
      unwatch(id);
      return Err(Error::new(
        Status::InvalidArg,
        "signal is not an AbortSignal: adding an abort listener failed",
      ));
    }

    // The target may have aborted from inside its own `addEventListener`, leaving a
    // listener that can never fire: re-read, so a signal aborted by the time this
    // returns always cancels the call whatever the target did in between.
    match unsafe { Object::from_napi_value(raw_env, self.signal) } // valid: this frame
      .and_then(|signal| signal.get::<bool>("aborted"))
    {
      Ok(Some(true)) => flag.store(true, Ordering::Relaxed),
      Ok(_) => {}
      Err(_) => unsafe { clear_pending(raw_env) },
    }

    Ok(CancelState {
      flag: CancelFlag(flag),
      held: Some(Held {
        id,
        signal: refs[0],
        listener: refs[1],
      }),
    })
  }
}

/// Drops the exception a failing JavaScript call leaves pending. N-API keeps one until
/// someone clears it, and an environment carrying one turns the *next* call — anyone's —
/// into the same failure; un-cleared it escapes as an uncaught exception, killing the
/// process.
unsafe fn clear_pending(env: napi::sys::napi_env) {
  let mut ignored = ptr::null_mut();
  unsafe { napi::sys::napi_get_and_clear_last_exception(env, &mut ignored) };
}

fn not_a_signal() -> Error {
  Error::new(
    Status::InvalidArg,
    "signal is not an AbortSignal: it has no readable `aborted` property, or cannot add and remove an abort listener",
  )
}

/// `object[name]`, when it is callable.
///
/// # Safety
///
/// `env` and `object` are live handles in the current call; `name` is a C string.
unsafe fn named_function(
  env: napi::sys::napi_env,
  object: napi::sys::napi_value,
  name: &CStr,
) -> Option<napi::sys::napi_value> {
  let mut method = ptr::null_mut();
  if unsafe { napi::sys::napi_get_named_property(env, object, name.as_ptr(), &mut method) } != OK {
    unsafe { clear_pending(env) };
    return None;
  }
  let mut kind: napi::sys::napi_valuetype = 0;
  if unsafe { napi::sys::napi_typeof(env, method, &mut kind) } != OK
    || kind != napi::sys::ValueType::napi_function
  {
    unsafe { clear_pending(env) };
    return None;
  }
  Some(method)
}

/// `signal[method]("abort", listener, { once: true })`. The options go on removal too:
/// `removeEventListener` reads only `capture` from them, and `once` is what takes a
/// listener off a signal on its own if this side is ever refused.
///
/// # Safety
///
/// `env`, `signal` and `listener` are live handles in the current call.
unsafe fn event_listener(
  env: napi::sys::napi_env,
  signal: napi::sys::napi_value,
  listener: napi::sys::napi_value,
  method: &CStr,
) -> bool {
  let Some(callback) = (unsafe { named_function(env, signal, method) }) else {
    return false;
  };
  // A failing creation here means a dying environment, with nothing to attach to.
  let (mut event, mut yes, mut options) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
  if unsafe {
    napi::sys::napi_create_string_utf8(
      env,
      ABORT_EVENT.as_ptr(),
      ABORT_EVENT.to_bytes().len() as isize,
      &mut event,
    )
  } != OK
    || unsafe { napi::sys::napi_get_boolean(env, true, &mut yes) } != OK
    || unsafe { napi::sys::napi_create_object(env, &mut options) } != OK
    || unsafe { napi::sys::napi_set_named_property(env, options, c"once".as_ptr(), yes) } != OK
  {
    return false;
  }

  let argv = [event, listener, options];
  let mut ignored = ptr::null_mut();
  if unsafe { napi::sys::napi_call_function(env, signal, callback, 3, argv.as_ptr(), &mut ignored) }
    != OK
  {
    unsafe { clear_pending(env) };
    return false;
  }
  true
}

/// The `abort` listener: sets the flag of the call it was hung for, if that call is still
/// running.
///
/// # Safety
///
/// N-API calls this with the callback info of the function
/// [`CancelSignal::dispatch`] created. Its `data` is not a pointer but a registry id, and
/// looking it up is all this does with it.
unsafe extern "C" fn observe_abort(
  env: napi::sys::napi_env,
  info: napi::sys::napi_callback_info,
) -> napi::sys::napi_value {
  let mut argc = 0;
  let mut watched: *mut c_void = ptr::null_mut();
  // The event object is not wanted: one listener per call, so this callback already
  // knows which flag is its own. Reading `data` is why this is a N-API callback
  // rather than a Rust closure.
  if unsafe {
    napi::sys::napi_get_cb_info(
      env,
      info,
      &mut argc,
      ptr::null_mut(),
      ptr::null_mut(),
      &mut watched,
    )
  } != OK
  {
    return ptr::null_mut();
  }

  if let Some(flag) = watching().get(&(watched as usize)) {
    flag.store(true, Ordering::Relaxed);
  }

  ptr::null_mut()
}
