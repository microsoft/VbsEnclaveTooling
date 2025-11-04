// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

extern crate alloc;

pub use edlcodegen_macros::EdlDerive;
pub mod edl_core_ffi;
pub mod edl_core_types;
pub mod flatbuffer_support;
pub mod helpers;
