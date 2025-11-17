// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <pch.h>

using namespace EdlProcessor;

namespace CodeGeneration::Rust
{
    inline constexpr std::string_view c_array_initializer = "[{};{}]";

    inline constexpr std::string_view c_enclave_crate_dep = "edlcodegen-enclave = \"0.1.0\"";

    inline constexpr std::string_view c_host_crate_dep = 
R"(edlcodegen-host = "0.1.0"
windows-strings = "0.5"
)";

    inline constexpr std::string_view c_cargo_toml_content =
R"([package]
name = "{}"
version = "0.0.0"
publish = false

[lib]
doc = false
doctest = false

[dependencies]
edlcodegen-core = "0.1.0"
{}
)";

    inline constexpr std::string_view c_abi_types_file_name = "abi_types.rs";

    inline constexpr std::string_view c_types_file_name = "types.rs";

    inline constexpr std::string_view c_dev_types_file =
R"({}
#![allow(unused)]
use alloc::string::String;
use alloc::vec::Vec;
use crate::fb_types::{};
use edlcodegen_core::EdlDerive;
{}
)";

    inline constexpr std::string_view c_abi_function_types_file =
R"({}
#![allow(unused)]
use alloc::string::String;
use alloc::vec::Vec;
use crate::implementation::types::*;
use crate::fb_types::{};
use edlcodegen_core::EdlDerive;
{}
)";

    inline constexpr std::string_view c_flatbuffers_module_name = "flatbuffers.rs";

    inline constexpr std::string_view c_flatbuffers_pack_statement = R"(
    impl_flatbuffer_pack!({}::{}T, {}::{}<'a>);)";

    inline constexpr std::string_view c_flatbuffers_module_content =
R"({}
#[allow(
    mismatched_lifetime_syntaxes,
    unsafe_op_in_unsafe_fn,
    dead_code,
    unused_imports,
    clippy::extra_unused_lifetimes,
    clippy::derivable_impls,
    clippy::missing_safety_doc
)]
pub mod fb_types {{
    use edlcodegen_core::flatbuffer_support::FlatbufferPack;
    use edlcodegen_core::impl_flatbuffer_pack;

    include!("flatbuffer_gen/mod.rs");
{}
}}
)";

    inline constexpr std::string_view c_struct_attributes = 
R"(
#[derive(Debug, Clone, PartialEq, Default, EdlDerive)]
#[target_struct({}::{}T)]
)";

    inline constexpr std::string_view c_enum_attributes =
R"(
#[repr(C, u32)]
#[derive(Debug, Clone, PartialEq, Default, EdlDerive)]
#[target_enum({}::{}T)]
)";

    inline constexpr std::string_view c_abi_rs =
R"({}
pub mod abi_types;
pub mod flatbuffers;
pub mod definitions;
)";

    inline constexpr std::string_view c_implementation_rs =
R"({}
pub mod types;
pub mod {};
)";

inline constexpr std::string_view c_stubs_lib_rs =
R"({}
pub mod {};
)";

    inline constexpr std::string_view c_enclave_lib_rs =
R"({}
#![no_std]

extern crate alloc;

pub mod abi;
pub use abi::definitions::export_enclave_functions;
pub mod implementation;
)";

    inline constexpr std::string_view c_host_lib_rs =
R"({}
pub mod abi;
pub use abi::definitions::define_host_boundary_functions;
pub mod implementation;
)";

    inline constexpr std::string_view c_extern_func =
R"(#[unsafe(no_mangle)]
pub extern "C" fn {}({}) -> *mut core::ffi::c_void
{{
{}
}}
)";

    inline constexpr std::string_view c_enclave_trusted_module =
R"({}
#![allow(unused)]
use alloc::string::String;
use alloc::vec::Vec;
use crate::implementation::types::*;

pub trait Trusted {{
{}
}}
)";

    inline constexpr std::string_view c_host_untrusted_module =
R"({}
#![allow(unused)]
use crate::stubs::trusted::Trusted;

pub trait Untrusted : Trusted {{
    use alloc::string::String;
    use alloc::vec::Vec;
    use crate::abi::abi_types::*;
    use crate::abi::flatbuffers::fb_types::*;
    use crate::implementation::types::*;

{}
}}
)";

    inline constexpr std::string_view c_enclave_untrusted_module =
R"({}
#![allow(unused)]
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Into;
use edlcodegen_core::edl_core_types::AbiError;
use edlcodegen_enclave::enclave_helpers::call_vtl0_callback_from_vtl1;
{}
)";

    inline constexpr std::string_view c_enclave_untrusted_func =
R"(
fn {}({}) -> Result<{}, AbiError>
{{
    use crate::abi::abi_types::{} as AbiTypeT;
    use crate::abi::flatbuffers::fb_types::{}T as FlatBufferT;
    let mut fb_native: FlatBufferT::default();
{}
    let {} = call_vtl0_callback_from_vtl1::<AbiTypeT, FlatBufferT>(&fb_native, "{}")?;
{}
    Ok({})
}})";

    inline constexpr std::string_view c_host_trusted_module =
R"({}
#![allow(unused)]
use edlcodegen_core::edl_core_types::AbiError;
use edlcodegen_host::host_helpers::call_vtl1_export_from_vtl0;
use windows_strings::s;

pub trait Trusted {{
{}
    fn register_vtl0_callbacks(&self) -> Result<(), AbiError>;
    fn enclave(&self) -> *mut core::ffi::c_void;
}}
)";

    inline constexpr std::string_view c_host_trusted_func =
R"(
    fn {}(&self, {}) -> Result<{}, edlcodegen_core::AbiError>
    {{
        use crate::abi::abi_types::{} as AbiTypeT;
        use crate::abi::flatbuffers::fb_types::{}T as FlatBufferT;
        let mut fb_native: FlatBufferT::default();
{}
        let {} = call_vtl1_export_from_vtl0::<AbiTypeT, FlatBufferT>(&fb_native, self::enclave(), s!("{}"))?;
{}
        Ok({})
    }}
)";

    inline constexpr std::string_view c_trait_func =
R"(    fn {}({}) -> {};)";

    inline constexpr std::string_view c_closure_content_with_result =
R"(dev_type.m__return_value_ = $T::{}({});)";

    inline constexpr std::string_view c_closure_content_no_result =
R"($T::{}({});)";

    inline constexpr std::string_view c_enclave_abi_definition_func =
R"(
        #[no_mangle]
        pub extern "C" {}(fn_context: *mut core::ffi::c_void) -> *mut core::ffi::c_void
        {{
            use $crate::abi::abi_types::{} as AbiTypeT;
            use $crate::abi::flatbuffers::fb_types::{}T as FlatBufferT;
            let dev_func = |dev_type: &mut AbiTypeT| {{
                {};
            }};

            edlcodegen_enclave::enclave_ffi::enable_enclave_restrict_containing_process_access_once();
            return_hr_as_pvoid!(call_vtl1_export_from_vtl1::<_, AbiTypeT, FlatBufferT>(dev_func, fn_context));
        }}
)";

    inline constexpr std::string_view c_export_enclave_funcs_macro =
R"(#[macro_export]
macro_rules! export_enclave_functions {{
    ($T:ty) => {{
        use edlcodegen_core::helpers::return_hr_as_pvoid;
        use edlcodegen_enclave::enclave_helpers::call_vtl1_export_from_vtl1;
{}
    }};
}}
)";

    inline constexpr std::string_view c_abi_definitions_rs =
R"({}
pub mod definitions;
pub use definitions::export_enclave_functions;
{}
)";

    inline constexpr std::string_view c_abi_definitions_module =
R"({}

{}
)";

    inline constexpr std::string_view c_host_abi_definition_func =
R"(
        #[no_mangle]
        pub extern "C" {}(fn_context: *mut core::ffi::c_void) -> *mut core::ffi::c_void
        {{
            use $crate::abi::abi_types::{} as AbiTypeT;
            use $crate::abi::flatbuffers::fb_types::{}T as FlatBufferT;
            let dev_func = |dev_type: &mut AbiTypeT| {{
                {};
            }};

            return_hr_as_pvoid!(call_vtl0_callback_from_vtl0::<_, AbiTypeT, FlatBufferT>(dev_func, fn_context));
        }}
)";

    inline constexpr std::string_view c_define_host_funcs_macro =
R"(#[macro_export]
macro_rules! define_host_boundary_functions {{
    ($T:ty) => {{
        use edlcodegen_core::helpers::return_hr_as_pvoid;
        use edlcodegen_enclave::enclave_helpers::call_vtl0_callback_from_vtl0;
{}
    }};
}}
)";
}
