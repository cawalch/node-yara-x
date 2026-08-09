//! WebAssembly execution runtime abstraction for YARA-X.
//!
//! YARA-X compiles rules into WebAssembly bytecode for high-performance
//! execution. This module provides a backend-neutral abstraction layer (shim)
//! that allows the compiler and scanner to run seamlessly on both native
//! platforms and in browser-based environments.
//!
//! ## Backend Architecture
//!
//! The runtime backend is selected at compile-time:
//!
//! 1. **Native Backend (`native.rs`)**: Default on native targets. Uses the
//!    optimizing **Wasmtime** compiler and JIT engine.
//! 2. **Browser Backend (`browser.rs`)**: Used when compiling to WebAssembly
//!    targets (e.g., `wasm32-unknown-unknown`). Wraps the host environment's
//!    built-in JavaScript `WebAssembly` APIs via `wasm-bindgen`.
//! 3. **Wasmi Backend (`wasmi.rs`)**: Optional on native targets (feature
//!    `wasmi-runtime`). Replaces Wasmtime with the pure-Rust **Wasmi**
//!    interpreter, trading JIT speed for a much smaller binary footprint,
//!    no executable memory pages, and a smaller supply-chain surface.
//!
//! ## Unified Wasmtime-like Interface
//!
//! To avoid scattering conditional compilation directives
//! (`#[cfg(target_family = "wasm")]`) throughout the compiler and scanner
//! code, this module exposes a single, unified API that matches Wasmtime's
//! standard interface. On Wasm targets, the custom shim (implemented in
//! `common.rs` and `browser.rs`) serves as a drop-in replacement for
//! Wasmtime. The same shim is used by the Wasmi backend on native targets.

// The shim (`common.rs`) is used by both the browser and the Wasmi backends.
#[cfg(any(target_family = "wasm", feature = "wasmi-runtime"))]
mod common;

// Native builds execute generated WASM through Wasmtime.
#[cfg(all(not(target_family = "wasm"), not(feature = "wasmi-runtime")))]
mod native;

// Browser builds execute generated WASM through the host WebAssembly runtime.
#[cfg(target_family = "wasm")]
mod browser;

// Native builds with the `wasmi-runtime` feature execute through Wasmi.
#[cfg(all(not(target_family = "wasm"), feature = "wasmi-runtime"))]
mod wasmi;

#[cfg(all(not(target_family = "wasm"), not(feature = "wasmi-runtime")))]
pub use native::*;

#[cfg(target_family = "wasm")]
pub use browser::*;

#[cfg(all(not(target_family = "wasm"), feature = "wasmi-runtime"))]
pub use wasmi::*;
