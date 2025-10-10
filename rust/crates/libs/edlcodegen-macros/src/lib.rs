// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! # edlcodegen-macros
//!
//! This crate provides the procedural macros used by structs and enums
//! generated from EDL definitions.
//!
//! The macros automatically generates conversion code between the
//! developer-facing EDL types and their corresponding generated target
//! representations (e.g., schema-generated types used for serialization
//! like FlatBuffers).
//!
//! - [`#[derive(EdlDerive)]`](EdlDerive) together with
//!   `#[target_struct(path::Type)]` — generates impls for the `core::convert::From` trait
//!   to convert between an EDL-generated struct and its corresponding
//!   target struct type.
//!
//! - [`#[derive(EdlDerive)]`](EdlDerive) together with
//!   `#[target_enum(path::Type)]` — generates impls for the `core::convert::From` trait
//!   to convert between an EDL-generated enum and its corresponding
//!   target enum type.
//!
//! ## Example
//! ```ignore
//! #[derive(EdlDerive)]
//! #[target_struct(GeneratedModule::NestedStructT)]
//! pub struct NestedStruct {
//!     pub id: u32,
//!     pub name: String,
//!     pub active: bool,
//! }
//!
//! #[derive(EdlDerive)]
//! #[target_enum(GeneratedModule::Color)]
//! pub enum Color {
//!     Red,
//!     Green,
//!     Blue,
//! }
//! ```

use proc_macro::TokenStream;
use syn::parse_macro_input;
mod utils;
mod derive_struct;
mod derive_enum;

/// Entry point for `#[derive(EdlDerive)]`.
///
/// Supports:
/// - `#[target_struct(path::Type)]` — specifies the corresponding target struct.
/// - `#[target_enum(path::Type)]` — specifies the corresponding target enum.
/// - `#[boxed_inner_target]` — applied to Generic type fields whose inner type is boxed in the target struct.
/// - `#[boxed_target]` — applied to fields that are boxed in the target struct.
///
/// These annotations guide code generation for automatic conversions between
/// EDL-defined Rust types and their generated target representations.
///
/// Example:
/// ```ignore
/// #[derive(EdlDerive)]
/// #[target_struct(GeneratedModule::FooT)]
/// pub struct Foo {
///     #[boxed_inner_target]
///     pub opt_nested_struct: Option<NestedStruct>,
/// 
///     #[boxed_target]
///     pub nested_struct: NestedStruct,
/// 
///     pub flag: bool,
/// }
/// ```
#[proc_macro_derive(EdlDerive, attributes(target_struct, target_enum, boxed_inner_target, boxed_target))]
pub fn edl_type_to_target_type(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);

    if let Some(target_path) = utils::find_target_path(&input.attrs, "target_struct") {
        derive_struct::derive_struct(input, &target_path)
    } else if let Some(target_path) = utils::find_target_path(&input.attrs, "target_enum") {
        derive_enum::derive_enum(input, &target_path)
    } else {
        panic!("expected #[target_struct(...)] or #[target_enum(...)] attribute");
    }
}
