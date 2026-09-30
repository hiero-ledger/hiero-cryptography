// SPDX-License-Identifier: Apache-2.0

// Every JNI entry point wraps its body in catch_unwind so a panic becomes a false or null
// return instead of killing the JVM. Those guards are inert under panic = "abort", and the
// setting lives in one line of Cargo.toml, so fail the build rather than ship them silently
// disabled. This cannot be a test: cargo forces unwind for the test profile regardless of
// what release is set to.
#[cfg(panic = "abort")]
compile_error!("hinTS JNI entry points rely on catch_unwind, which is inert under panic=abort");

pub mod hints;
pub mod jni_blst;
pub mod jni_crs;
pub mod jni_hints;
pub mod setup;
pub mod errors;

mod kzg;
mod utils;
mod jni_util;
mod jni_cache;
