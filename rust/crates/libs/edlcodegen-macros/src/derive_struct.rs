// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Data, DeriveInput, Fields, Path
};
use crate::utils::{ Direction, FieldInfo, generate_field_assignment, parse_field_attr};

pub fn derive_struct(input: DeriveInput, target_path: &Path) -> TokenStream {
    let Data::Struct(data_struct) = &input.data else {
        panic!("#[target_struct] can only be used on structs");
    };

    let Fields::Named(field_name) = &data_struct.fields else {
        panic!("#[target_struct] supports only named-field structs");
    };

    // This is the edl struct with the target_struct attribute.
    let edl_struct = input.ident.clone();
    
    // This is the target struct inside the target_struct attribute.
    let target_struct = target_path;

    // Extract fields with attributes
    let mut to_target_fields = Vec::new();
    let mut to_edl_fields = Vec::new();
    for field in &field_name.named {
        let attr = parse_field_attr(field);

        let info = |dir| FieldInfo {
            name: field.ident.clone().unwrap(),
            ty: field.ty.clone(),
            attr,
            dir,
        };

        to_target_fields.push(generate_field_assignment(info(Direction::ToTarget)));
        to_edl_fields.push(generate_field_assignment(info(Direction::FromTarget)));
    }

    // Generate the conversion trait impls. Note, anything that appears inside the
    // quote! should be usable in a no_std environment.
    let expanded = quote! {

        // Trait implementation for: target struct -> edl struct.
        impl core::convert::From<#target_struct> for #edl_struct {
            fn from(src: #target_struct) -> Self {
                Self { #(#to_edl_fields),* }
            }
        }

        // Trait implementation for: edl struct -> target struct.
        impl core::convert::From<#edl_struct> for #target_struct {
            fn from(src: #edl_struct) -> Self {
                Self { #(#to_target_fields),* }
            }
        }
    };

    TokenStream::from(expanded)
}

