// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![allow(dead_code)]
#![allow(non_snake_case)]

mod enclave_ffi;

pub mod common;
pub mod userboundkey;

// Re-export the SDK generated enclave crate.
// This is used internally by the export_sdk_enclave_functions! macro.
pub use sdk_enclave_gen;

// Re-export Uuid from the uuid crate for use in enclave code.
pub use uuid::Uuid;

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
        // Export SDK enclave functions in a private module
        // to avoid naming conflicts with the application's own exports
        mod __sdk_exports {
            $crate::sdk_enclave_gen::export_enclave_functions!($crate::common::EnclaveImpl);
        }

        // Future SDK features will be added here as additional modules
    };
}
