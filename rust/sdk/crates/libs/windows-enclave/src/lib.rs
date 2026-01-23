// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![allow(non_camel_case_types, non_snake_case, dead_code)]
// For re-exporting the generated bindings without warnings
// E.g HRESULT is defined in both bcrypt and vertdll bindings
// with the same definition.
#![allow(ambiguous_glob_reexports)]

mod manual_bindings;

pub mod bcrypt {
    include!(concat!(env!("OUT_DIR"), "/bcrypt.rs"));
    pub use super::manual_bindings::bcrypt::*;
}

pub mod vertdll {
    include!(concat!(env!("OUT_DIR"), "/vertdll.rs"));
    pub use super::manual_bindings::vertdll::*;
}

pub mod veinterop {
    pub use super::manual_bindings::veinterop::*;
}
