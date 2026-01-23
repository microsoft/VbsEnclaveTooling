// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
extern crate alloc;

mod enclave_ffi;

pub mod common;
pub mod userboundkey;

// Re-export the SDK generated enclave crate.
// This is used internally by the export_sdk_enclave_functions! macro.
pub use sdk_enclave_gen;

/// Export all SDK enclave functions.
///
/// Call this macro once in your enclave's lib.rs to enable SDK features.
/// This exports the necessary callback registration and trusted functions
/// that the SDK needs to communicate with VTL0.
///
/// # Example
///
/// ```rust,ignore
/// // In your enclave's lib.rs:
/// vbsenclave_sdk_enclave::export_sdk_enclave_functions!();
/// ```
///
/// This is equivalent to manually exporting each SDK module's functions,
/// but hides the internal implementation details.
#[macro_export]
macro_rules! export_sdk_enclave_functions {
    () => {
        // Export SDK userboundkey enclave functions in a private module
        // to avoid naming conflicts with the application's own exports
        mod __sdk_userboundkey_exports {
            $crate::sdk_enclave_gen::export_enclave_functions!($crate::userboundkey::TrustedImpl);
        }

        // Future SDK features will be added here as additional modules
    };
}
