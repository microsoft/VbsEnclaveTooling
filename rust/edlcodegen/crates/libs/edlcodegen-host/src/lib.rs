// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub mod host_ffi;
pub mod host_helpers;
pub mod win_host_bindings;

// Re-export core functionalities so consumers don't have to depend
// on edlcodegen-core directly.
pub use edlcodegen_core::EdlDerive;
pub use edlcodegen_core::edl_core_types::AbiError;
pub use edlcodegen_core::edl_core_types::EnclaveHandle;
pub use edlcodegen_core::flatbuffer_support::FlatbufferPack;
pub use edlcodegen_core::helpers::{
    abi_func_to_address, allocate_memory_ffi, assign_if_some,
    deallocate_memory_ffi,
};
pub use edlcodegen_core::impl_flatbuffer_pack;
pub use edlcodegen_core::return_hr_as_pvoid;
