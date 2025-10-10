// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use proc_macro::TokenStream;
use quote::quote;
use syn::{ DeriveInput, Data, Path};

pub fn derive_enum(input: DeriveInput, target_path: &Path) -> TokenStream {
    let Data::Enum(data_enum) = &input.data else {
        panic!("#[target_enum] can only be used on enums");
    };

    // This is the edl enum with the target_enum attribute.
    let edl_enum = &input.ident;

    // This is the target enum inside the target_enum attribute.
    let target_enum: &Path= target_path;

    // Collect variant identifiers
    let variants = data_enum.variants.iter().map(|v| &v.ident);

    // Generate the conversion trait impls. Note, anything that appears inside the
    // quote! should be usable in a no_std environment.
    let expanded = quote! {

        // Trait implementation for: target enum -> edl enum.
        impl core::convert::From<#target_enum> for #edl_enum {
            fn from(src: #target_enum) -> Self {
                match src.0 as u32 {
                    #(x if x == #edl_enum::#variants as u32 => #edl_enum::#variants,)*
                    _ => panic!("Invalid enum value: {}", src.0),
                }
            }
        }

        // Trait implementation for: edl enum -> target enum.
        impl core::convert::From<#edl_enum> for #target_enum {
            fn from(src: #edl_enum) -> Self {
                Self(src as u32)
            }
        }
    };

    expanded.into()
}