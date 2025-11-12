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
edition = "2024"
publish = false

[lib]
doc = false
doctest = false

[dependencies]
edlcodegen-core = "0.1.0"
{}
flatbuffers = "25.9.23"
)";

    inline constexpr std::string_view c_abi_types_file_name = "abi_types.rs";

    inline constexpr std::string_view c_enclave_vec_str=
R"(use alloc::string::String;
use alloc::vec::Vec;)";

    inline constexpr std::string_view c_types_file_name = "types.rs";

    inline constexpr std::string_view c_dev_types_file =
R"({}
#![allow(unused)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
{}
use crate::abi::fb_support::fb_types::{}::flatbuffer_types;
use crate::abi::abi_types::edl;
use edlcodegen_core::EdlDerive;
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
use edlcodegen_core::EdlDerive;

{}

pub mod edl {{
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
    use edlcodegen_core::flatbuffer_support::FlatbufferPack;
    use edlcodegen_core::impl_flatbuffer_pack;
    use {}::flatbuffer_types::*;

    include!("flatbuffer_gen/mod.rs");
{}
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
#[derive(Debug, Clone, PartialEq, Default, EdlDerive)]
#[target_enum(flatbuffer_types::{})]
)";

    inline constexpr std::string_view c_abi_mod_rs =
R"({}
pub mod abi_types;
pub mod fb_support;
)";

    inline constexpr std::string_view c_implementation_mod_rs =
R"({}
pub mod types;
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
pub mod implementation;
)";

    inline constexpr std::string_view c_host_lib_rs =
R"({}
pub mod abi;
pub mod implementation;
)";
}
