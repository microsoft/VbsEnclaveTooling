// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![allow(dead_code)]
#![allow(non_snake_case)]
extern crate alloc;

pub mod common;
pub mod etw;
pub mod userboundkey;

// Re-export generated SDK enclave's export macro
// and println stub for use in this crate's macros.
pub use sdk_enclave_gen::export_enclave_functions;
pub use sdk_enclave_gen::stubs::untrusted::println;

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
            $crate::export_enclave_functions!($crate::common::EnclaveImpl);
        }
    };
}

/// Print formatted output from the enclave to the host's standard output.
/// This macro works like `format!` and appends a newline.
/// # Example
/// ```rust,ignore
/// use vbsenclave_sdk_enclave::enclave_println;
/// enclave_println!("Hello from the enclave: {}", 42);
/// ```
#[macro_export]
macro_rules! enclave_println {
    ($($arg:tt)*) => {{
        let mut s = alloc::format!($($arg)*);
        let _ = $crate::println(&s);
    }};
}
