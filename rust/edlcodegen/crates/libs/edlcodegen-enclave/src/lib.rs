// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![allow(dead_code)]
extern crate alloc;

pub mod enclave_ffi;
pub mod enclave_global_allocator;
pub mod enclave_helpers;
pub mod memory_helpers;
pub mod vtl0_pointers;
pub mod win_enclave_bindings;

// Re-export core functionalities so consumers don't have to depend
// on edlcodegen-core directly.
pub use edlcodegen_core::EdlDerive;
pub use edlcodegen_core::edl_core_types::AbiError;
pub use edlcodegen_core::helpers::assign_if_some;
pub use edlcodegen_core::flatbuffer_support::FlatbufferPack;
pub use edlcodegen_core::impl_flatbuffer_pack;
pub use edlcodegen_core::return_hr_as_pvoid;
