//! Cancellation for the asynchronous entry points: a `signal?: AbortSignal` stops
//! work that has not started. Already-aborted rejects before dispatch, aborted while
//! queued is caught at the top of `compute()`, and a batch skips what it had not
//! reached and resolves with the part it got. A running scan cannot be preempted —
//! that stays `setTimeout()` / `setMaxScanSize()`. Every cancellation rejects with
//! `name`/`message` `AbortError` and `code` `Cancelled`, and none throws from the call.
//!
//! The abort is watched by a listener hung on the signal for the life of the call — not
//! N-API's `AbortSignal` wrapper, which retains ~250 bytes per call for as long as the
//! signal lives (measurements in the PR that added this file). A flag is a slot index
//! plus the stamp that slot carried while the call owned it, and the listener gets that
//! pair as its N-API `data`: no Rust allocation is reachable from JavaScript, so a
//! listener that fires late writes nothing, and memory follows cancelled scans *in
//! flight*, not scans ever made.

use napi::bindgen_prelude::{FromNapiValue, Object, TypeName, ValidateNapiValue};
use napi::{Env, Error, Result, Status, ValueType};
use std::ffi::CStr;
use std::os::raw::{c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::error::abort_error;

/// Success, spelled once.
const OK: c_int = napi::sys::Status::napi_ok;

const ABORT_EVENT: &CStr = c"abort";

const ABORT_LISTENER: &CStr = c"yaraXAbortListener";

/// Slot and stamp share the listener's `data` value: 20 bits, then 44. The callback
/// reads it as an integer and never dereferences it.
const SLOT_BITS: u32 = 20;
const STAMP_BITS: u32 = 64 - SLOT_BITS;
const STAMP_MASK: u64 = (1 << STAMP_BITS) - 1;
const SLOT_MASK: usize = (1 << SLOT_BITS) - 1;

/// The abort bit, above the 44 bits a stamp can occupy.
const ABORTED: u64 = 1 << 63;

#[derive(Clone, Copy)]
pub struct CancelFlag {
  slot: usize,
  stamp: u64,
}

/// What a call without a signal runs with: no table, so the 120k-calls/s path
/// allocates nothing.
const NO_SLOT: usize = usize::MAX;

impl CancelFlag {
  pub fn never() -> Self {
    Self {
      slot: NO_SLOT,
      stamp: 0,
    }
  }

  /// Whether the signal has aborted. The stamp is read as well as the bit, so a
  /// slot that has gone to another call cannot read as cancelled through a flag
  /// that no longer owns it.
  pub fn is_cancelled(&self) -> bool {
    self.slot != NO_SLOT
      && TABLE.get(self.slot).is_some_and(|state| {
        let state = state.load(Ordering::Acquire);
        state & !ABORTED == self.stamp && state & ABORTED != 0
      })
  }

  /// Refuses the scan once the signal has aborted — the last point it still can.
  pub fn reject_if_cancelled(&self) -> Result<()> {
    // Without a `name`: `reject` stamps it where a JavaScript object can be built.
    // A signal aborted before the call gets here too, its slot stamped at argument
    // read time.
    if self.is_cancelled() {
      return Err(abort_error(None));
    }
    Ok(())
  }
}

/// All slots, in one static array, so an address is valid for the life of the process
/// and a listener cannot reach freed memory. Pages are charged on first touch, and only
/// by a scan that is cancelled *and* in flight.
///
/// One word per slot: the owner's stamp, with the abort bit above it. 0 means nobody
/// owns it, which is what makes a stale stamp inert.
static TABLE: [AtomicU64; 1 << SLOT_BITS] = [const { AtomicU64::new(0) }; 1 << SLOT_BITS];

/// Slots returned and waiting to be handed out again; the guard also serialises
/// first-time assignment, the only allocation here.
static FREE: Mutex<Vec<usize>> = Mutex::new(Vec::new());
static NEXT_SLOT: AtomicUsize = AtomicUsize::new(0);
static NEXT_STAMP: AtomicU64 = AtomicU64::new(0);

/// Takes a stamped slot for a call, or `None` if they are all in use.
fn acquire_slot() -> Option<CancelFlag> {
  // A panic anywhere else must not make every later scan fail, so a poisoned guard
  // is taken as it is: this vector is only ever pushed and popped.
  let slot = FREE
    .lock()
    .unwrap_or_else(std::sync::PoisonError::into_inner)
    .pop()
    .or_else(|| {
      let next = NEXT_SLOT.fetch_add(1, Ordering::Relaxed);
      (next < TABLE.len()).then_some(next)
    })?;
  // Stamps do not repeat until this counter wraps at 2^44, so a listener left on a
  // signal by a hostile target cannot match a stamp on a slot it no longer owns.
  let stamp = NEXT_STAMP.fetch_add(1, Ordering::Relaxed) % STAMP_MASK + 1;
  TABLE.get(slot)?.store(stamp, Ordering::Release);
  Some(CancelFlag { slot, stamp })
}

/// Puts a slot back; anything still holding the old stamp is inert from here.
fn release_slot(slot: usize) {
  if let Some(state) = TABLE.get(slot) {
    state.store(0, Ordering::Release);
    if let Ok(mut free) = FREE.lock() {
      free.push(slot);
    }
  }
}

/// Sets the abort if the slot still belongs to this flag; a stale flag is ignored.
fn abort_slot(slot: usize, stamp: u64) {
  if let Some(state) = TABLE.get(slot) {
    // Only the owner raises the bit, so a listener whose slot has gone elsewhere
    // writes nothing.
    let _ = state.try_update(Ordering::Release, Ordering::Relaxed, |current| {
      (current == stamp).then_some(current | ABORTED)
    });
  }
}

/// What one call knows about its cancellation; `Task::finally` calls [`Self::release`],
/// and [`Drop`] covers the paths that never get there.
pub struct CancelState {
  /// The flag to hand to whatever runs on worker threads.
  pub flag: CancelFlag,
  /// The listener's two handles, taken when the slot goes back.
  held: Option<Held>,
  /// True when the table was full and this call cannot be watched.
  saturated: bool,
}

/// The handles a call needs to take its listener back off the signal.
struct Held {
  signal: napi::sys::napi_ref,
  listener: napi::sys::napi_ref,
}

// SAFETY: handles into the environment the call was made on, touched only on the
// JavaScript thread — attached during the call, released in `Task::finally`.
// Workers reach the abort through `CancelFlag`, which is `Send + Sync`.
unsafe impl Send for Held {}

impl CancelState {
  /// The state of a call made without a signal.
  pub fn never() -> Self {
    Self {
      flag: CancelFlag::never(),
      held: None,
      saturated: false,
    }
  }

  /// Refuses the scan if the signal aborted or the table had no slot for it.
  pub fn reject_if_cancelled(&self) -> Result<()> {
    if self.saturated {
      return Err(Error::new(
        Status::GenericFailure,
        "too many cancellable scans in flight to watch another signal",
      ));
    }
    self.flag.reject_if_cancelled()
  }

  /// Gives the slot back, then takes the listener off the signal. Best effort and
  /// silent: the scan is over either way, and a settled promise must not turn into a
  /// rejected one. The slot goes back first, so a listener the signal refused to
  /// un-listen is inert before anything else is released.
  pub fn release(&mut self, env: &Env) {
    if self.flag.slot != NO_SLOT {
      release_slot(self.flag.slot);
      self.flag = CancelFlag::never();
    }
    let Some(held) = self.held.take() else {
      return;
    };
    let Held { signal, listener } = held;
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
          false,
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
  /// Gives the slot back even when the task never reached `Task::finally`, so a dispatch
  /// that failed on the way in cannot leak one. No environment is needed to make a
  /// left-behind listener harmless — the slot reads as free once its stamp is gone —
  /// which is why `release` clears the flag before taking the listener off.
  fn drop(&mut self) {
    if self.flag.slot != NO_SLOT {
      release_slot(self.flag.slot);
      self.flag = CancelFlag::never();
    }
  }
}

/// Turns the `signal` argument into task state, in the calling frame — which is what
/// makes the raw handle in [`CancelSignal`] usable.
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
  /// Takes a slot and hangs the listener; an abort that already happened leaves the
  /// flag set, so the task refuses itself in `compute`.
  fn dispatch(self, env: &Env) -> Result<CancelState> {
    // A full table refuses the scan in `compute`, so the call rejects instead of
    // throwing at the caller and never runs work it was meant to be able to stop.
    let Some(flag) = acquire_slot() else {
      return Ok(CancelState {
        flag: CancelFlag::never(),
        held: None,
        saturated: true,
      });
    };
    if self.aborted {
      // Read before anything is registered: a signal that has already aborted will
      // never fire its listener again.
      abort_slot(flag.slot, flag.stamp);
      return Ok(CancelState {
        flag,
        held: None,
        saturated: false,
      });
    }

    let raw_env = env.raw();
    // All the callback needs, as an integer in the pointer N-API hands it.
    let watched = ((flag.slot << STAMP_BITS) | (flag.stamp & STAMP_MASK) as usize) as *mut c_void;

    let mut listener = ptr::null_mut();
    if unsafe {
      napi::sys::napi_create_function(
        raw_env,
        ABORT_LISTENER.as_ptr(),
        ABORT_LISTENER.to_bytes().len() as isize,
        Some(observe_abort),
        watched,
        &mut listener,
      )
    } != OK
    {
      release_slot(flag.slot);
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
        && event_listener(raw_env, self.signal, listener, c"addEventListener", true)
    };
    if !attached {
      unsafe {
        for handle in refs {
          if !handle.is_null() {
            napi::sys::napi_delete_reference(raw_env, handle);
          }
        }
      }
      release_slot(flag.slot);
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
      Ok(Some(true)) => abort_slot(flag.slot, flag.stamp),
      Ok(_) => {}
      Err(_) => unsafe { clear_pending(raw_env) },
    }

    Ok(CancelState {
      flag,
      held: Some(Held {
        signal: refs[0],
        listener: refs[1],
      }),
      saturated: false,
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

/// `signal[method]("abort", listener)`, `{ once: true }` when adding — that is what
/// takes the listener off an aborted signal without waiting for this side to settle.
///
/// # Safety
///
/// `env`, `signal` and `listener` are live handles in the current call.
unsafe fn event_listener(
  env: napi::sys::napi_env,
  signal: napi::sys::napi_value,
  listener: napi::sys::napi_value,
  method: &CStr,
  once: bool,
) -> bool {
  let Some(callback) = (unsafe { named_function(env, signal, method) }) else {
    return false;
  };
  // A failing string creation means a dying environment, with nothing left to
  // attach a listener to.
  let mut event = ptr::null_mut();
  if unsafe {
    napi::sys::napi_create_string_utf8(
      env,
      ABORT_EVENT.as_ptr(),
      ABORT_EVENT.to_bytes().len() as isize,
      &mut event,
    )
  } != OK
  {
    return false;
  }

  let mut argv = [event, listener, ptr::null_mut()];
  let mut argc = 2;
  if once {
    let mut yes = ptr::null_mut();
    let mut options = ptr::null_mut();
    if unsafe { napi::sys::napi_get_boolean(env, true, &mut yes) } != OK
      || unsafe { napi::sys::napi_create_object(env, &mut options) } != OK
      || unsafe { napi::sys::napi_set_named_property(env, options, c"once".as_ptr(), yes) } != OK
    {
      return false;
    }
    argv[2] = options;
    argc = 3;
  }

  let mut ignored = ptr::null_mut();
  if (unsafe {
    napi::sys::napi_call_function(env, signal, callback, argc, argv.as_ptr(), &mut ignored)
  }) != OK
  {
    unsafe { clear_pending(env) };
    return false;
  }
  true
}

/// The `abort` listener: sets the flag of the call it was hung for, if that call
/// still owns the slot.
///
/// # Safety
///
/// N-API calls this with the callback info of the function
/// [`CancelSignal::dispatch`] created. Its `data` is not a pointer but a packed slot
/// and stamp, and reading it as an integer is all this does with it.
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

  let packed = watched as usize;
  abort_slot(
    (packed >> STAMP_BITS) & SLOT_MASK,
    (packed & STAMP_MASK as usize) as u64,
  );

  ptr::null_mut()
}
