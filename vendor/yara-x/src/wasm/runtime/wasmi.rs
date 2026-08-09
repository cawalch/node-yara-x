//! Wasmi runtime backend.
//!
//! A pure-Rust interpreter backend that replaces Wasmtime on native targets
//! (feature `wasmi-runtime`). Trade-off: conditions are interpreted instead of
//! JIT-compiled, in exchange for a much smaller binary footprint, no
//! executable memory pages, and a smaller supply-chain surface.
//!
//! The host-function bridge mirrors `browser.rs`: host imports are wired by
//! capturing a raw pointer to the [`Store`] (kept alive by the store itself)
//! and dispatching through YARA-X's trampolines using the [`ValRaw`] ABI.
//! While a host function is executing, the Wasmi store is borrowed by the
//! interpreter; the raw pointer is used only to reach the user data (`T`),
//! never to re-enter Wasmi, so no reentrancy occurs.

use std::sync::OnceLock;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};

use super::common::{self, RuntimeBackend};
use crate::scanner::ScanError;

/// Alias for [`common::Caller`] specialized for the wasmi backend.
pub type Caller<'a, T> = common::Caller<'a, T, Backend>;
/// Alias for [`common::Instance`] specialized for the wasmi backend.
pub(crate) type Instance = common::Instance<Backend>;
/// Alias for [`common::Linker`] specialized for the wasmi backend.
pub(crate) type Linker<T> = common::Linker<T, Backend>;
/// Alias for [`common::Memory`] specialized for the wasmi backend.
pub(crate) type Memory = common::Memory;
/// Alias for [`common::Module`] specialized for the wasmi backend.
pub(crate) type Module = common::Module<Backend>;
/// Alias for [`common::Store`] specialized for the wasmi backend.
pub(crate) type Store<T> = common::Store<T, Backend>;
/// Alias for [`common::TypedFunc`] specialized for the wasmi backend.
pub(crate) type TypedFunc<P, R> = common::TypedFunc<P, R, Backend>;

/// Shared Wasmtime-like runtime types used by the wasmi backend.
pub(crate) use super::common::{
    AsContext, AsContextMut, Config, Engine, Extern, FuncType, Global,
    GlobalType, MemoryType, Mutability, OptLevel, Val, ValRaw, ValType,
};

pub(crate) type Trampoline<T> = common::Trampoline<T, Backend>;
pub(crate) type TrampolineResult = common::TrampolineResult;

/// Fuel budget per microsecond of remaining scan time.
///
/// Wasmi consumes one unit of fuel per executed WASM instruction, so this
/// rate approximates a wall-clock deadline. It is deliberately generous: the
/// interpreter typically executes far more than 100 instructions per
/// microsecond, so the timeout remains a safety net rather than a precise
/// scheduler.
const FUEL_PER_US: u64 = 100;

/// The global Wasmi engine used by all stores.
///
/// Fuel metering is enabled so that scan timeouts can be enforced through
/// fuel exhaustion (see [`RuntimeState::deadline`]).
static ENGINE: OnceLock<wasmi::Engine> = OnceLock::new();

fn wasmi_engine() -> &'static wasmi::Engine {
    ENGINE.get_or_init(|| {
        let mut config = wasmi::Config::default();
        config.consume_fuel(true);
        wasmi::Engine::new(&config)
    })
}

/// Raw pointer wrapper that is `Send + Sync`.
///
/// The pointed-to [`Store`] is owned by the runtime state and outlives every
/// host-function invocation, so sharing the pointer across the Wasmi host
/// closure boundary is safe as long as the closure never dereferences it
/// reentrantly (it does not).
struct StorePtr<T>(*mut T);

// Manual impls: `derive` would add `T: Clone`/`T: Copy` bounds, which the
// pointee type does not satisfy.
impl<T> Clone for StorePtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for StorePtr<T> {}

impl<T> StorePtr<T> {
    /// Returns the wrapped raw pointer.
    ///
    /// Accessing the pointer through a method (rather than the field) makes
    /// closures capture the whole wrapper instead of just the field, so the
    /// `Send`/`Sync` impls below apply.
    fn get(&self) -> *mut T {
        self.0
    }
}

// SAFETY: see the struct-level comment. Dereference happens only on the
// thread that owns the store, and never while the store is re-entered.
unsafe impl<T> Send for StorePtr<T> {}
unsafe impl<T> Sync for StorePtr<T> {}

/// Backend-specific runtime state stored alongside each [`Store`].
pub(crate) struct RuntimeState {
    /// The Wasmi store, created lazily on first use.
    store: Option<Box<wasmi::Store<()>>>,
    /// Globals created through [`common::Global::new`].
    globals: Vec<wasmi::Global>,
    /// Memories created through [`common::Memory::new`].
    memories: Vec<wasmi::Memory>,
    /// Wall-clock deadline for the current scan, if a timeout is set.
    deadline: Option<Instant>,
    /// Error raised by a host function, preserved across the Wasmi boundary.
    pending_error: Option<anyhow::Error>,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            store: None,
            globals: Vec::new(),
            memories: Vec::new(),
            deadline: None,
            pending_error: None,
        }
    }
}

impl RuntimeState {
    /// Returns a mutable reference to the Wasmi store, creating it if needed.
    fn ensure_store(&mut self) -> &mut wasmi::Store<()> {
        self.store
            .get_or_insert_with(|| Box::new(wasmi::Store::new(wasmi_engine(), ())))
    }
}

/// Backend-specific representation of an instantiated module.
pub(crate) struct InstanceInner {
    instance: wasmi::Instance,
    /// Pointer to the Wasmi store that owns `instance`.
    ///
    /// The store lives in [`RuntimeState`], which outlives the instance, so
    /// the pointer stays valid for the whole lifetime of the instance.
    store_ptr: *mut wasmi::Store<()>,
}

impl RuntimeBackend for Backend {
    type RuntimeState = RuntimeState;
    type ModuleInner = wasmi::Module;
    type InstanceInner = InstanceInner;
    type TypedFuncHandle = wasmi::Func;

    fn set_epoch_deadline(runtime: &mut Self::RuntimeState, deadline: u64) {
        runtime.deadline =
            Some(Instant::now() + Duration::from_secs(deadline));
    }

    fn prepare_for_instantiation(runtime: &mut Self::RuntimeState) {
        runtime.pending_error = None;
    }

    fn reset_for_store_reuse(runtime: &mut Self::RuntimeState) {
        runtime.globals.clear();
        runtime.memories.clear();
        runtime.pending_error = None;
        runtime.deadline = None;
    }

    fn create_global(
        runtime: &mut Self::RuntimeState,
        ty: GlobalType,
        value: Val,
    ) -> Result<usize> {
        let store = runtime.ensure_store();
        let mutability = match ty.mutability {
            Mutability::Const => wasmi::Mutability::Const,
            Mutability::Var => wasmi::Mutability::Var,
        };
        let global = wasmi::Global::new(store, val_to_wasmi(value), mutability);
        runtime.globals.push(global);
        Ok(runtime.globals.len() - 1)
    }

    fn get_global(runtime: &mut Self::RuntimeState, id: usize) -> Val {
        let store = runtime.store.as_deref().unwrap();
        wasmi_to_val(runtime.globals[id].get(store))
    }

    fn set_global(
        runtime: &mut Self::RuntimeState,
        id: usize,
        value: Val,
    ) -> Result<()> {
        let store_ptr = runtime.ensure_store() as *mut wasmi::Store<()>;
        // SAFETY: `store_ptr` is the store owned by `runtime`; the borrow
        // ends at the end of this statement.
        runtime.globals[id]
            .set(unsafe { &mut *store_ptr }, val_to_wasmi(value))
            .map_err(|e| anyhow!("failed to set global: {e}"))
    }

    fn create_memory(
        runtime: &mut Self::RuntimeState,
        ty: MemoryType,
    ) -> Result<usize> {
        let store = runtime.ensure_store();
        let mem_type = wasmi::MemoryType::new(ty.initial, ty.maximum);
        let memory = wasmi::Memory::new(store, mem_type)
            .map_err(|e| anyhow!("failed to create memory: {e}"))?;
        runtime.memories.push(memory);
        Ok(runtime.memories.len() - 1)
    }

    fn memory_data<'a>(
        runtime: &'a Self::RuntimeState,
        id: usize,
    ) -> &'a [u8] {
        let store: &'a wasmi::Store<()> = runtime.store.as_deref().unwrap();
        runtime.memories[id].data(store)
    }

    fn memory_data_mut<'a>(
        runtime: &'a mut Self::RuntimeState,
        id: usize,
    ) -> &'a mut [u8] {
        let store: &'a mut wasmi::Store<()> =
            runtime.store.as_deref_mut().unwrap();
        runtime.memories[id].data_mut(store)
    }

    fn memory_data_ptr(
        runtime: &mut Self::RuntimeState,
        id: usize,
    ) -> *mut u8 {
        let store_ptr = runtime.ensure_store() as *mut wasmi::Store<()>;
        // SAFETY: `store_ptr` is the store owned by `runtime`.
        runtime.memories[id]
            .data_mut(unsafe { &mut *store_ptr })
            .as_mut_ptr()
    }

    fn module_from_binary(
        _engine: &Engine,
        bytes: &[u8],
    ) -> Result<Self::ModuleInner> {
        wasmi::Module::new(wasmi_engine(), bytes)
            .map_err(|e| anyhow!("failed to compile WASM module: {e}"))
    }

    fn instantiate<T: 'static>(
        store: &mut Store<T>,
        linker: &Linker<T>,
        module: &Module,
    ) -> Result<Self::InstanceInner> {
        // Ensure the Wasmi store exists, then keep a raw pointer to it so the
        // interpreter and the host closures can share it without holding
        // overlapping borrows of the runtime state.
        let wasmi_store_ptr = store.runtime.ensure_store() as *mut wasmi::Store<()>;

        let store_ptr = StorePtr(store as *mut Store<T>);

        let mut imports: Vec<wasmi::Extern> = Vec::new();

        // Wasmi matches imports positionally, so walk the module's import
        // section and resolve each import against the linker in order.
        for import in module.inner.imports() {
            let module_name = import.module();
            let import_name = import.name();

            match import.ty() {
                wasmi::ExternType::Func(_) => {
                    let reg = linker
                        .functions
                        .iter()
                        .find(|r| {
                            r.module == module_name && r.name == import_name
                        })
                        .ok_or_else(|| {
                            anyhow!(
                                "import not registered: {module_name}::{import_name}"
                            )
                        })?;

                    let param_tys = reg.ty.params.clone();
                    let result_tys = reg.ty.results.clone();
                    let trampoline = Arc::clone(&reg.trampoline);

                    let func_type = wasmi::FuncType::new(
                        param_tys.iter().map(|t| wasmi_valuetype(*t)),
                        result_tys.iter().map(|t| wasmi_valuetype(*t)),
                    );

                    // SAFETY: `store_ptr` points to the store that owns the
                    // Wasmi store (`runtime.store`), which outlives the
                    // closure. While the closure runs, Wasmi holds a borrow
                    // of its own store; the raw pointer is only used to reach
                    // the user data (`T`) through `common::Caller`, never to
                    // re-enter Wasmi.
                    let ptr = store_ptr;
                    let func = wasmi::Func::new(
                        unsafe { &mut *wasmi_store_ptr },
                        func_type,
                        move |_caller: wasmi::Caller<'_, ()>,
                              args: &[wasmi::Val],
                              out: &mut [wasmi::Val]|
                              -> Result<(), wasmi::Error> {
                            let store = unsafe { &mut *ptr.get() };

                            let mut args_and_results = vec![
                                ValRaw::default();
                                common::callback_storage_len(
                                    &param_tys,
                                    &result_tys,
                                )
                            ];
                            for (i, v) in args.iter().enumerate() {
                                args_and_results[i] =
                                    val_to_valraw(wasmi_to_val(v.clone()));
                            }

                            let caller = Caller::new(store);
                            if let Err(e) = trampoline(
                                caller,
                                &mut args_and_results,
                            ) {
                                // Preserve the original error (e.g.
                                // `ScanError::Timeout`) across the Wasmi
                                // boundary; it is surfaced by
                                // `typed_func_call_i32`.
                                store.runtime.pending_error = Some(e);
                                return Err(wasmi::Error::new(
                                    "host function returned an error",
                                ));
                            }

                            for (i, ty) in result_tys.iter().enumerate() {
                                out[i] = val_to_wasmi(valraw_to_val(
                                    args_and_results[i],
                                    *ty,
                                ));
                            }

                            Ok(())
                        },
                    );
                    imports.push(wasmi::Extern::Func(func));
                }
                wasmi::ExternType::Global(_) => {
                    let defined = linker
                        .externs
                        .iter()
                        .find(|d| {
                            d.module == module_name && d.name == import_name
                        })
                        .ok_or_else(|| {
                            anyhow!(
                                "extern not defined: {module_name}::{import_name}"
                            )
                        })?;
                    let Extern::Global(global) = defined.value else {
                        return Err(anyhow!(
                            "{module_name}::{import_name} is not a global"
                        ));
                    };
                    imports.push(wasmi::Extern::Global(
                        store.runtime.globals[global.id],
                    ));
                }
                wasmi::ExternType::Memory(_) => {
                    let defined = linker
                        .externs
                        .iter()
                        .find(|d| {
                            d.module == module_name && d.name == import_name
                        })
                        .ok_or_else(|| {
                            anyhow!(
                                "extern not defined: {module_name}::{import_name}"
                            )
                        })?;
                    let Extern::Memory(memory) = defined.value else {
                        return Err(anyhow!(
                            "{module_name}::{import_name} is not a memory"
                        ));
                    };
                    imports.push(wasmi::Extern::Memory(
                        store.runtime.memories[memory.id],
                    ));
                }
                wasmi::ExternType::Table(_) => {
                    return Err(anyhow!(
                        "table imports are not supported by the wasmi runtime"
                    ));
                }
            }
        }

        let instance = wasmi::Instance::new(
            unsafe { &mut *wasmi_store_ptr },
            &module.inner,
            &imports,
        )
        .map_err(|e| anyhow!("failed to instantiate module: {e}"))?;

        Ok(InstanceInner {
            instance,
            store_ptr: wasmi_store_ptr,
        })
    }

    fn get_typed_func_handle<P, R>(
        instance: &Self::InstanceInner,
        name: &str,
    ) -> Result<Self::TypedFuncHandle> {
        // SAFETY: the store outlives the instance (see `InstanceInner`).
        let store = unsafe { &*instance.store_ptr };
        instance
            .instance
            .get_func(store, name)
            .ok_or_else(|| anyhow!("export `{name}` is not a function"))
    }

    fn typed_func_call_i32<T>(
        store: &mut Store<T>,
        func: &Self::TypedFuncHandle,
    ) -> Result<i32> {
        let runtime = &mut store.runtime;
        let deadline = runtime.deadline;
        let wasmi_store = runtime.ensure_store();

        // Enforce the scan deadline through the fuel budget.
        if let Some(deadline) = deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let fuel = (remaining.as_micros() as u64)
                .saturating_mul(FUEL_PER_US)
                .max(1);
            wasmi_store
                .set_fuel(fuel)
                .map_err(|e| anyhow!("failed to set fuel: {e}"))?;
        } else {
            let _ = wasmi_store.set_fuel(u64::MAX);
        }

        let typed = func
            .typed::<(), i32>(&*wasmi_store)
            .map_err(|e| anyhow!("failed to type-check main function: {e}"))?;

        let result = typed.call(&mut *wasmi_store, ());

        match result {
            Ok(value) => Ok(value),
            Err(e) => {
                // A host function may have raised a typed error (e.g.
                // `ScanError::Timeout` from `search_for_patterns`); surface it
                // exactly as the Wasmtime backend would.
                if let Some(pending) = runtime.pending_error.take() {
                    return Err(pending);
                }
                if e.as_trap_code() == Some(wasmi::TrapCode::OutOfFuel) {
                    return Err(anyhow::Error::new(ScanError::Timeout));
                }
                Err(anyhow::Error::new(e))
            }
        }
    }
}

/// The wasmi backend is a unit struct; all state lives in [`RuntimeState`].
#[derive(Clone, Default)]
pub struct Backend;

fn wasmi_valuetype(ty: ValType) -> wasmi::ValType {
    match ty {
        ValType::I32 => wasmi::ValType::I32,
        ValType::I64 => wasmi::ValType::I64,
        ValType::F32 => wasmi::ValType::F32,
        ValType::F64 => wasmi::ValType::F64,
    }
}

fn wasmi_to_val(value: wasmi::Val) -> Val {
    match value {
        wasmi::Val::I32(v) => Val::I32(v),
        wasmi::Val::I64(v) => Val::I64(v),
        wasmi::Val::F32(v) => Val::F32(v.to_bits()),
        wasmi::Val::F64(v) => Val::F64(v.to_bits()),
        wasmi::Val::FuncRef(_) | wasmi::Val::ExternRef(_) => {
            unreachable!("YARA-X conditions do not use references")
        }
        wasmi::Val::V128(_) => unreachable!("YARA-X conditions do not use SIMD"),
    }
}

fn val_to_wasmi(value: Val) -> wasmi::Val {
    match value {
        Val::I32(v) => wasmi::Val::I32(v),
        Val::I64(v) => wasmi::Val::I64(v),
        Val::F32(bits) => wasmi::Val::F32(wasmi::F32::from_bits(bits)),
        Val::F64(bits) => wasmi::Val::F64(wasmi::F64::from_bits(bits)),
    }
}

fn val_to_valraw(value: Val) -> ValRaw {
    match value {
        Val::I32(v) => ValRaw::i32(v),
        Val::I64(v) => ValRaw::i64(v),
        Val::F32(bits) => ValRaw::f32(bits),
        Val::F64(bits) => ValRaw::f64(bits),
    }
}

fn valraw_to_val(raw: ValRaw, ty: ValType) -> Val {
    match ty {
        ValType::I32 => Val::I32(raw.get_i32()),
        ValType::I64 => Val::I64(raw.get_i64()),
        ValType::F32 => Val::F32(raw.get_f32()),
        ValType::F64 => Val::F64(raw.get_f64()),
    }
}
