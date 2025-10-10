// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Ident, Path, PathArguments, Type, TypePath, Attribute};

/// Indicates the conversion direction.
#[derive(Copy, Clone)]
pub enum Direction {
    ToTarget,
    FromTarget,
}

/// Indicates how a field in the EDL-generated struct maps to its corresponding
/// type in the target (e.g., FlatBuffer) representation.
///
/// Used by codegen to handle special cases such as when a target field
/// is wrapped in a `Box<T>` rather than being stored by value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TargetFieldHint {
    None,
    Boxed,
}

/// Metadata about a single struct field to make figuring out
/// how to convert the field from edl type <-> target type easier.
pub struct FieldInfo {
    pub name: Ident,
    pub ty: Type,
    pub attr: TargetFieldHint,
    pub dir: Direction,
}

pub fn generate_field_assignment(field: FieldInfo) -> TokenStream2 {
    let name = &field.name;
    let expr = quote! { src.#name };
    let converted = generate_conversion(expr, &field.ty, &field);
    quote! { #name: #converted }
}

/// Reads through the AST for the field and handles conversion between the edl type
/// and the target type.
fn generate_conversion(expr: TokenStream2, typ: &Type, field: &FieldInfo) -> TokenStream2 {
    // handle edl type is array [T; N] but target type is Vec<T>
    if let Type::Array(_) = typ {
        return handle_array_to_vec(expr, field);
    };

    let Type::Path(TypePath { path, .. }) = typ else {
        panic!("expected a Type::Path, got {:?}", typ);
    };

    // Get name of edl type so we can handle converting the type
    let name = path
        .segments
        .last()
        .unwrap_or_else(|| panic!("expected non-empty path"))
        .ident
        .to_string();

    if name == "Option" {
       return handle_option_to_option(expr, path, field);
    } else if name == "Vec" {
        return handle_vec_to_vec(expr, path, field);
    } else if name == "Box" {
        return handle_boxed_to_boxed(expr, path, field);
    }

    // If we get here then we're looking at a plain unwrapped type T
    // in the edl struct.

    // Called when the edl type is T and the target type is Box<T>
    if field.attr == TargetFieldHint::Boxed {
        return handle_unboxed_to_boxed(expr, field);
    }

    return  quote! { #expr.into() };
}


/// Converts `Option<T>`, `Vec<T>` generically using a provided closure pattern.
fn convert_generic<F>(_expr: TokenStream2, path: &Path, field: &FieldInfo, wrapper: F) -> TokenStream2
where
    F: Fn(TokenStream2) -> TokenStream2,
{
    let inner_ty = extract_inner_type(path);
    let inner_expr = generate_conversion(quote! { inner }, &inner_ty, field);
    wrapper(inner_expr)
}

/// `Option<T> <-> Option<U>`
fn handle_option_to_option(expr: TokenStream2, path: &Path, field: &FieldInfo) -> TokenStream2 {
    convert_generic(expr.clone(), path, field, |inner_expr| {
        quote! { #expr.map(|inner| { #inner_expr }) }
    })
}

/// `Vec<T> <-> Vec<U>`
fn handle_vec_to_vec(expr: TokenStream2, path: &Path, field: &FieldInfo) -> TokenStream2 {
    convert_generic(expr.clone(), path, field, |inner_expr| {
        quote! { #expr.into_iter().map(|inner| { #inner_expr }).collect() }
    })
}

/// `Box<T> <-> Box<U>`
fn handle_boxed_to_boxed(expr: TokenStream2, path: &Path, field: &FieldInfo) -> TokenStream2 {
    convert_generic(expr.clone(), path, field, |inner_expr| {
        quote! {{let inner = *#expr; Box::new(#inner_expr) }}
    })
}

/// Extracts the inner type T from  `Option<T>`, `Vec<T>` and `Box<T>`
fn extract_inner_type(path: &Path) -> Type {
    let Some(seg) = path.segments.first() else {
        panic!("empty path");
    };

    let PathArguments::AngleBracketed(args) = &seg.arguments else {
        panic!("expected angle-bracketed generic args");
    };

    let Some(syn::GenericArgument::Type(typ)) = args.args.first() else {
        panic!("expected one generic argument");
    };

    typ.clone()
}

fn handle_unboxed_to_boxed(expr: TokenStream2, field: &FieldInfo) -> TokenStream2
{
    match field.dir {
            Direction::ToTarget => quote! { Box::new(#expr.into()) },
            Direction::FromTarget => quote! { (*#expr).into() },
        }
}

fn handle_array_to_vec(expr: TokenStream2, field: &FieldInfo) -> TokenStream2 {
    match field.dir {
        // edl type: [T; N] → target: Vec<T>
        Direction::ToTarget => {
            quote! { #expr.iter().map(|x| x.clone().into()).collect::<Vec<_>>() }
        }

        // Target: Vec<T> → edl type: [T; N]
        Direction::FromTarget => {
            quote! {{
                core::array::from_fn(|i| {
                    if i < #expr.len() {
                        #expr[i].clone().into()
                    } else {
                        Default::default()
                    }
                })
            }}
        }
    }
}

pub fn parse_field_attr(field: &syn::Field) -> TargetFieldHint {
    let mut attrs_seen = std::collections::HashSet::new();

    for attr in &field.attrs {
        if let Some(ident) = attr.path().get_ident() {
            attrs_seen.insert(ident.to_string());
        }
    }

    if attrs_seen.contains("boxed_inner_target") || attrs_seen.contains("boxed_target") {
        TargetFieldHint::Boxed
    } else {
        TargetFieldHint::None
    }
}

pub fn find_target_path(attrs: &[Attribute], attr_name: &str) -> Option<Path> {
    let attr = attrs.iter().find(|a| a.path().is_ident(attr_name))?;
    attr.parse_args::<Path>().ok()
}