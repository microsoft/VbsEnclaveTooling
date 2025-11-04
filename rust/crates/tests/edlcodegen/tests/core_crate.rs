// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod common;
use common::test_helpers::*;
use common::test_types::*;

use core::ffi::c_void;
use edlcodegen_core::{
    flatbuffer_support::FlatbufferPack, flatbuffer_support::pack_flatbuffer,
    helpers::hresult_to_pvoid, helpers::pvoid_to_hresult,
};
use windows_sys::Win32::Foundation::{E_ACCESSDENIED, E_INVALIDARG, S_OK};

#[cfg(test)]
mod edl_core {
    use super::fb_generated::flatbuffer_test;
    use super::*;

    #[test]
    fn conversion_between_edl_types_and_flatbuffer_types() {
        let initial_edl_struct = create_all_types_struct();

        // Developer type -> Flatbuffer type
        let flatbuffer_struct: flatbuffer_test::AllTypesT = initial_edl_struct.clone().into();

        // Flatbuffer type -> Developer type
        let ending_dev_struct: dev_types::AllTypes = flatbuffer_struct.into();

        // Check that the dev type struct we ended up with is the same as the initial
        // struct to confirm we succeeded the round trip.
        assert_eq!(initial_edl_struct, ending_dev_struct);
    }

    #[test]
    fn flatbuffer_packing() {
        let all_types_data = create_all_types_struct();
        let native_table: flatbuffer_test::AllTypesT = all_types_data.clone().into();
        let builder = pack_flatbuffer(&native_table);
        let fin_data = builder.finished_data();

        let back_to_native_table: flatbuffer_test::AllTypesT =
            flatbuffer_test::AllTypesT::unpack(fin_data)
                .unwrap_or_else(|err| panic!("Failed to unpack flatbuffer: {}", err));

        assert_eq!(native_table, back_to_native_table);
    }

    #[test]
    fn flatbuffer_packing_failure() {
        // Invalid flatbuffer data — random data that doesn't match the schema.
        let invalid_bytes = vec![0xAB; 32];

        let result = flatbuffer_test::NestedDataT::unpack(&invalid_bytes);

        // Verify that unpacking fails with an error type.
        assert!(result.is_err());
    }

    #[test]
    fn round_trip_hresult_pointer_conversions() {
        let test_values = [S_OK, E_INVALIDARG, E_ACCESSDENIED];

        for &hr in &test_values {
            let ptr: *mut c_void = hresult_to_pvoid(hr);
            let result: i32 = pvoid_to_hresult(ptr);

            assert_eq!(hr, result, "Round-trip failed for HRESULT 0x{:08X}", hr);
        }
    }
}
