// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <pch.h>
#include <Edl\Structures.h>

using namespace EdlProcessor;

namespace CodeGeneration::Rust
{
    inline constexpr std::string_view c_array_initializer = "[{};{}]";

    inline constexpr std::string_view c_enclave_crate_dep = "edlcodegen-enclave = \"0.1.0\"";

    inline constexpr std::string_view c_host_crate_dep = "edlcodegen-host = \"0.1.0\"";

    inline constexpr std::string_view c_cargo_toml_content =
R"([package]
name = "{}_generated"
version = "0.0.0"
publish = false

[lib]
doc = false
doctest = false

[dependencies]
edlcodegen-core = "0.1.0"
edlcodegen-macros = "0.1.0"
{}
)";

    inline constexpr std::string_view c_types_file_name = "types.rs";

    inline constexpr std::string_view c_dev_types_file =
R"({}

#![allow(unused)]
use alloc::string::String;
use alloc::vec::Vec;

{}
)";

    inline constexpr std::string_view c_abi_function_types_file =
R"({}

#![allow(unused)]
use alloc::string::String;
use alloc::vec::Vec;
use crate::implementation::types::*;

{}
)";

    inline constexpr std::string_view c_flatbuffers_module_name = "flatbuffers_support.rs";

    inline constexpr std::string_view c_flatbuffers_pack_statement = "    impl_flatbuffer_pack!({}::{}T, {}::{}<'a>);\n";

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
pub mod fb_generated {{
    use edlcodegen_core::flatbuffer_support::FlatbufferPack;
    use edlcodegen_core::impl_flatbuffer_pack;
    use super::flatbuffer_gen::*;

    {}
}}
)";

    inline constexpr std::string_view c_type_attributes = 
R"(#[derive(Debug, Clone, PartialEq, Default, EdlDerive)]
#[target_{}({}::{}T)]
)";
}
