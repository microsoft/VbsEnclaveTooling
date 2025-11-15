// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <pch.h>

using namespace EdlProcessor;

namespace CodeGeneration::Rust
{
    inline constexpr std::string_view c_array_initializer = "[{};{}]";

    inline constexpr std::string_view c_enclave_crate_dep = "edlcodegen-enclave = \"0.1.0\"";

    inline constexpr std::string_view c_host_crate_dep = "edlcodegen-host = \"0.1.0\"";

    inline constexpr std::string_view c_cargo_toml_content =
R"([package]
name = "{}_gen"
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

    inline constexpr std::string_view c_flatbuffers_module_name = "flatbuffers_types.rs";

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
pub mod flatbuffer_types;
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

mod abi;
pub mod implementation;
)";

    inline constexpr std::string_view c_host_lib_rs =
R"({}
mod abi;
pub mod implementation;
)";
}
