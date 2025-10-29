// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::test_types::{dev_types, edl_types};

pub fn create_nested_data_struct() -> dev_types::NestedData {
    dev_types::NestedData {
        id: 42,
        name: "Inner Item".to_string(),
        active: true,
        values: vec![0.1, 0.2, 0.3],
        color: dev_types::Color::Green,
    }
}

pub fn create_all_types_struct() -> dev_types::AllTypes {
    let nested_data = create_nested_data_struct();
    dev_types::AllTypes {
        i8_field: -8,
        i16_field: -1600,
        i32_field: -32000,
        i64_field: -64000,
        u8_field: 8,
        u16_field: 1600,
        u32_field: 32000,
        u64_field: 64000,
        bool_field: true,
        f32_field: std::f32::consts::PI,
        f64_field: std::f64::consts::TAU,
        str_field: "Hello FlatBuffers!".to_string(),
        color_field: dev_types::Color::Red,
        vec_i8: vec![-1, 0, 1],
        vec_i16: vec![-10, 0, 10],
        vec_i32: vec![-100, 0, 100],
        vec_i64: vec![-1000, 0, 1000],
        vec_u8: vec![1, 2, 3],
        vec_u16: vec![10, 20, 30],
        vec_u32: vec![100, 200, 300],
        vec_u64: vec![1000, 2000, 3000],
        vec_f32: vec![1.1, 2.2, 3.3],
        vec_f64: vec![4.4, 5.5, 6.6],
        vec_bool: vec![true, false, true],
        vec_str: vec!["foo".to_string(), "bar".to_string(), "baz".to_string()],
        vec_color: vec![
            dev_types::Color::Red,
            dev_types::Color::Green,
            dev_types::Color::Blue,
        ],
        opt_i32: Some(123),
        opt_str: Some("optional string".to_string()),
        opt_nested_struct: Some(nested_data.clone()),
        opt_vec_f64: Some(vec![0.11, 0.22, 0.33]),
        opt_vec_nested_struct: Some(vec![nested_data.clone()]),
        opt_box_to_same_struct_type: Some(Box::new(dev_types::AllTypes::default())),
        nested_struct: nested_data.clone(),
        vec_nested_struct: vec![nested_data.clone(), nested_data.clone()],
        wstr: edl_types::WString {
            wchars: vec![11u16, 22u16, 33u16],
        },
        vec_wstr: vec![edl_types::WString {
            wchars: vec![11u16, 22u16, 33u16],
        }],
        str_arr: ["foo".to_string(), "bar".to_string()],
        nested_struct_arr: [nested_data.clone(), nested_data.clone()],
    }
}
