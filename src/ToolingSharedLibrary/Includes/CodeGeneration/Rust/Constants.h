// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <pch.h>

using namespace EdlProcessor;

namespace CodeGeneration::Rust
{
    inline constexpr std::string_view c_array_initializer = "[{};{}]";

    // Temporary crate dependency string for edlcodegen-enclave until we publish to crates.io.
    // When testing not yet merged changes to edlcodegen-enclave, add the following: rev = "<commit hash from Github branch>"
    // after the subdir specification below.
    inline constexpr std::string_view c_enclave_crate_dep = R"(edlcodegen-enclave = { git = "https://github.com/microsoft/VbsEnclaveTooling" })";

    // Temporary crate dependency string for edlcodegen-host until we publish to crates.io.
    // When testing not yet merged changes to edlcodegen-host, add the following: rev = "<commit hash from Github branch>"
    // after the subdir specification below.
    inline constexpr std::string_view c_host_crate_dep =
R"(edlcodegen-host = { git = "https://github.com/microsoft/VbsEnclaveTooling" }
windows-strings = "0.5")";

    inline constexpr std::string_view c_cargo_toml_content =
R"([package]
name = "{}"
version = "0.0.0"
edition = "2024"
publish = false

[lib]
doc = false
doctest = false

[build-dependencies]
edlcodegen-tools = {{ git = "https://github.com/microsoft/VbsEnclaveTooling" }}

[dependencies]
{}
flatbuffers = {{ version = "25.9.23", default-features = false }}
)";

    inline constexpr std::string_view c_build_rs_file_content =
R"({}
use edlcodegen_tools::flatc_path;
use std::{{env, path::PathBuf, process::Command}};

fn main() {{
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let schema_path = manifest_dir.join("src\\abi\\flatbuffer_gen\\FlatbufferTypes.fbs");
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let gen_out_path = format!("{{out_dir}}/flatbuffer_gen");

    let status = Command::new(flatc_path())
        .current_dir(&manifest_dir)
        .args([
            "--rust",
            "--gen-object-api",
            "--force-empty",
            "--no-prefix",
            "--rust-module-root-file",
            "--gen-all",
            "--filename-suffix",
            "", // So --filename-suffix takes empty string as suffix
            "-o",
            &gen_out_path,
            schema_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run flatc");

    assert!(status.success(), "flatc failed with status {{}}", status);
}}
)";

    inline constexpr std::string_view c_abi_types_file_name = "abi_types.rs";

    inline constexpr std::string_view c_enclave_alloc_imports =
R"(use alloc::string::String;
use alloc::vec::Vec;
use alloc::boxed::Box;)";

    inline constexpr std::string_view c_enclave_vec_import =
R"(use alloc::vec::Vec;)";

    inline constexpr std::string_view c_types_file_name = "types.rs";

    inline constexpr std::string_view c_dev_types_file =
R"({}
#![allow(unused)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
{}
use crate::abi::fb_support::fb_types::{}::flatbuffer_types;
pub use crate::abi::abi_types::edl;
use {}::EdlDerive;
{}
)";

    inline constexpr std::string_view c_abi_function_types_file =
R"({}
#![allow(unused)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
{}
use crate::implementation::types::*;
use crate::abi::fb_support::fb_types::{}::flatbuffer_types;
use crate::abi::fb_support::fb_types::edl::WStringT;
use {}::EdlDerive;

{}
#[derive(Debug, Clone, PartialEq, Default, EdlDerive)]
#[target_struct(flatbuffer_types::AbiRegisterVtl0Callbacks_argsT)]
pub struct AbiRegisterVtl0Callbacks_args
{{
    pub m_callback_addresses: Vec<u64>,
    pub m_callback_names: Vec<String>,
    pub m__return_value_: i32,
}}

pub mod edl {{
    {}
    #[derive(Debug, Clone, PartialEq, Default, super::EdlDerive)]
    #[target_struct(super::WStringT)]
    pub struct WString {{
        pub wchars: Vec<u16>,
    }}
}}

)";

    inline constexpr std::string_view c_flatbuffers_module_name = "fb_support.rs";

    inline constexpr std::string_view c_flatbuffers_pack_statement = R"(
    impl_flatbuffer_pack!({}T, {}<'a>);)";

    inline constexpr std::string_view c_flatbuffers_module_content =
R"({}
#![allow(unused)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[allow(
    mismatched_lifetime_syntaxes,
    unsafe_op_in_unsafe_fn,
    dead_code,
    unused_imports,
    clippy::extra_unused_lifetimes,
    clippy::derivable_impls,
    clippy::missing_safety_doc
)]
pub mod fb_types{{
    use {}::FlatbufferPack;
    use {}::impl_flatbuffer_pack;
    use {}::flatbuffer_types::*;

    include!(concat!(env!("OUT_DIR"), "/flatbuffer_gen/mod.rs"));
{}
    impl_flatbuffer_pack!(AbiRegisterVtl0Callbacks_argsT, AbiRegisterVtl0Callbacks_args<'a>);
}}
)";

    inline constexpr std::string_view c_struct_attributes =
R"(
#[derive(Debug, Clone, PartialEq, Default, EdlDerive)]
#[target_struct(flatbuffer_types::{}T)]
)";

    inline constexpr std::string_view c_enum_attributes =
R"(
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Default, EdlDerive)]
#[target_enum(flatbuffer_types::{})]
)";

    inline constexpr std::string_view c_abi_mod_rs =
R"({}
pub mod abi_types;
pub mod fb_support;
pub mod definitions;
)";

    inline constexpr std::string_view c_implementation_mod_rs =
R"({}
pub mod types;
pub mod {};
)";

    inline constexpr std::string_view c_stubs_lib_mod_rs =
R"({}
pub mod {};
)";

    inline constexpr std::string_view c_enclave_lib_rs =
R"({}
#![no_std]

extern crate alloc;

pub mod abi;
pub use abi::abi_types::edl::WString;
pub mod implementation;
pub mod stubs;
pub use edlcodegen_enclave::enclave_ffi::enable_enclave_restrict_containing_process_access_once;
pub use edlcodegen_enclave::{{AbiError, return_hr_as_pvoid}};
pub use edlcodegen_enclave::enclave_helpers::{{
    call_vtl1_export_from_vtl1, register_vtl0_callouts
}};
)";

    inline constexpr std::string_view c_host_lib_rs =
R"({}
pub mod abi;
pub use abi::abi_types::edl::WString;
pub mod implementation;
pub mod stubs;
pub use stubs::trusted::{};
pub use edlcodegen_host::{{AbiError, abi_func_to_address, return_hr_as_pvoid}};
pub use edlcodegen_host::host_helpers::call_vtl0_callback_from_vtl0;
)";

    inline constexpr std::string_view c_trait_function =
R"(    fn {}({}) -> {};)";

    inline constexpr std::string_view c_enclave_trusted_module_outline =
R"({}
#![allow(unused)]
#![allow(non_snake_case)]

use alloc::string::String;
use alloc::vec::Vec;
use crate::implementation::types::*;

pub trait Trusted {{

{}
}}
)";

    inline constexpr std::string_view c_host_untrusted_module_outline =
R"({}
#![allow(unused)]
#![allow(non_snake_case)]

use crate::implementation::types::*;

pub trait Untrusted {{
{}
    crate::define_trait_callback_functions!();
}}
)";

    inline constexpr std::string_view c_enclave_untrusted_module_outline =
R"({}
#![allow(unused)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::abi::abi_types;
use crate::abi::fb_support::fb_types::{}::flatbuffer_types;
use crate::implementation::types::*;
use alloc::string::String;
use alloc::vec::Vec;
use edlcodegen_enclave::enclave_helpers::call_vtl0_callback_from_vtl1;
{}
)";

    inline constexpr std::string_view c_enclave_untrusted_function =
R"(
pub fn {}({}) -> Result<{}, edlcodegen_enclave::AbiError>
{{
    use abi_types::{} as AbiTypeT;
    use flatbuffer_types::{}T as FlatBufferT;
    let mut abi_type : AbiTypeT = AbiTypeT::default();
{}
    let fb_native : FlatBufferT = abi_type.into();
    let {} = call_vtl0_callback_from_vtl1::<AbiTypeT, FlatBufferT>(&fb_native, "{}")?;
{}
    Ok({})
}})";

    inline constexpr std::string_view c_host_trusted_module_outline =
R"({}
#![allow(unused)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::abi::abi_types;
use crate::abi::fb_support::fb_types::{}::flatbuffer_types;
use crate::implementation::types::*;
use crate::implementation::untrusted::Untrusted;
use edlcodegen_host::host_helpers::call_vtl1_export_from_vtl0;
use edlcodegen_host::EnclaveHandle;
use windows_strings::s;

pub struct {} {{
    enclave_handle: EnclaveHandle,
}}

impl {} {{
    pub fn new(enclave_ptr: *mut core::ffi::c_void) -> Self {{
        Self {{ enclave_handle : EnclaveHandle(enclave_ptr) }}
    }}
{}
    pub fn register_vtl0_callbacks<T: Untrusted>(&self) -> Result<(), edlcodegen_host::AbiError>
    {{
        use std::string::ToString;
        use flatbuffer_types::AbiRegisterVtl0Callbacks_argsT as FlatBufferT;
        let mut fb_native : FlatBufferT = FlatBufferT::default();
        fb_native.m_callback_addresses = T::callback_addresses().to_vec();
        fb_native.m_callback_names = T::callback_names().iter().map(ToString::to_string).collect();
        call_vtl1_export_from_vtl0::<abi_types::AbiRegisterVtl0Callbacks_args, FlatBufferT>(&fb_native, self.enclave_handle.0, s!("{}"))?;
        Ok(())
    }}
}}
)";

    inline constexpr std::string_view c_host_trusted_function =
R"(
    pub fn {}(&self, {}) -> Result<{}, edlcodegen_host::AbiError>
    {{
        use abi_types::{} as AbiTypeT;
        use flatbuffer_types::{}T as FlatBufferT;
        let mut abi_type : AbiTypeT = AbiTypeT::default();
{}
        let fb_native : FlatBufferT = abi_type.into();
        let {} = call_vtl1_export_from_vtl0::<AbiTypeT, FlatBufferT>(&fb_native, self.enclave_handle.0, s!("{}"))?;
{}
        Ok({})
    }}
)";

    inline constexpr std::string_view c_enclave_closure_content_with_result =
R"(abi_type.m__return_value_ = <$T>::{}({})?;)";

    inline constexpr std::string_view c_enclave_closure_content_no_result =
R"(<$T>::{}({})?;)";

inline constexpr std::string_view c_host_closure_content_with_result =
 R"(abi_type.m__return_value_ = Self::{}({})?;)";

inline constexpr std::string_view c_host_closure_content_no_result =
 R"(Self::{}({})?;)";

    inline constexpr std::string_view c_enclave_abi_definition_function =
R"(
        #[unsafe(no_mangle)]
        pub extern "system" fn {}(fn_context: *mut core::ffi::c_void) -> *mut core::ffi::c_void
        {{
            use abi_types::{} as AbiTypeT;
            use flatbuffer_types::{}T as FlatBufferT;
            let abi_func = |abi_type: &mut AbiTypeT| -> Result<(), AbiError> {{
                {}
                Ok(())
            }};
            $crate::enable_enclave_restrict_containing_process_access_once();
            return_hr_as_pvoid!(call_vtl1_export_from_vtl1::<_, AbiTypeT, FlatBufferT>(abi_func, fn_context))
        }}
)";

    inline constexpr std::string_view c_export_enclave_functions_macro =
R"(#[macro_export]
macro_rules! export_enclave_functions {{
    ($T:ty) => {{
        use $crate::abi::abi_types;
        use $crate::abi::fb_support::fb_types::{}::flatbuffer_types;
        use $crate::implementation::trusted::Trusted;
        use $crate::{{AbiError, return_hr_as_pvoid, call_vtl1_export_from_vtl1, register_vtl0_callouts}};
        {}
        #[unsafe(no_mangle)]
        pub extern "system" fn {}(fn_context: *mut core::ffi::c_void) -> *mut core::ffi::c_void
        {{
            use abi_types::AbiRegisterVtl0Callbacks_args as AbiTypeT;
            use flatbuffer_types::AbiRegisterVtl0Callbacks_argsT as FlatBufferT;
            let abi_func = |abi_type: &mut AbiTypeT| -> Result<(), AbiError> {{
                register_vtl0_callouts(&abi_type.m_callback_addresses, &abi_type.m_callback_names)?;
                abi_type.m__return_value_ = 0;
                Ok(())
            }};
            $crate::enable_enclave_restrict_containing_process_access_once();
            return_hr_as_pvoid!(call_vtl1_export_from_vtl1::<_, AbiTypeT, FlatBufferT>(abi_func, fn_context))
        }}
    }};
}}
)";

    inline constexpr std::string_view c_abi_definitions_rs =
R"({}
pub mod definitions;
{}
)";

    inline constexpr std::string_view c_abi_definitions_module_outline =
R"({}
{}
)";

    inline constexpr std::string_view c_host_abi_definition_function =
R"(
        extern "system" fn {}(fn_context: *mut core::ffi::c_void) -> *mut core::ffi::c_void
        {{
            use $crate::{{AbiError, abi_func_to_address, return_hr_as_pvoid, call_vtl0_callback_from_vtl0}};
            use $crate::abi::abi_types::{} as AbiTypeT;
            use $crate::abi::fb_support::fb_types::{}::flatbuffer_types::{}T as FlatBufferT;
            let abi_func = |abi_type: &mut AbiTypeT| -> Result<(), AbiError> {{
                {}
                Ok(())
            }};
            return_hr_as_pvoid!(call_vtl0_callback_from_vtl0::<_, AbiTypeT, FlatBufferT>(abi_func, fn_context))
        }}
)";

    inline constexpr std::string_view c_define_host_functions_macro =
R"(#[macro_export]
macro_rules! define_trait_callback_functions {{
    () => {{
        {}
        fn callback_names() -> [&'static str; {}] {{
            [{}]
        }}

        fn callback_addresses() -> [u64; {}] {{
            use $crate::abi_func_to_address;
            [{}]
        }}
    }};
}}
)";
}
