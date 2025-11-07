// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod common;
mod mocks;
use common::test_helpers::*;
use common::test_types::{dev_types::AllTypes, fb_generated::flatbuffer_test::AllTypesT};

use core::ffi::c_void;
use edlcodegen_core::{
    edl_core_types::EnclaveFunctionContext,
    flatbuffer_support::{FlatbufferPack, pack_flatbuffer},
    helpers::{abi_func_to_address, allocate_memory, allocate_memory_ffi, deallocate_memory_ffi},
};
use edlcodegen_enclave::{enclave_ffi::*, enclave_helpers::*};

#[allow(unused_imports)]
use mocks::mock_functions::*;
use std::ptr;
use windows_sys::Win32::Foundation::S_OK;

#[cfg(test)]
mod edl_enclave {
    use super::*;

    fn register_vtl0_callouts_helper(
        additional_addrs_opt: Option<&[u64]>,
        additonal_names_opt: Option<&[String]>,
    ) {
        let alloc_addr = abi_func_to_address(allocate_memory_ffi);
        let dealloc_addr = abi_func_to_address(deallocate_memory_ffi);

        let mut addrs = vec![alloc_addr, dealloc_addr];
        let mut names = vec![
            "VbsEnclaveABI::HostApp::AllocateVtl0MemoryCallback".to_string(),
            "VbsEnclaveABI::HostApp::DeallocateVtl0MemoryCallback".to_string(),
        ];

        if let Some(additional_addrs) = additional_addrs_opt {
            addrs.extend_from_slice(additional_addrs);
        }

        if let Some(additonal_names) = additonal_names_opt {
            names.extend_from_slice(additonal_names);
        }

        _ = register_vtl0_callouts(&addrs, &names).map_err(|err| {
            panic!(
                "Failed to register VTL0 callouts due to error: {:X}",
                err.to_hresult().0
            );
        });
    }

    #[test]
    fn enclave_restrict_containing_process_access_happens_only_once() {
        enable_enclave_restrict_containing_process_access_once();
        enable_enclave_restrict_containing_process_access_once();
        enable_enclave_restrict_containing_process_access_once();
    }

    #[test]
    fn call_vtl1_export_from_vtl1_succeeds() {
        // Arrange
        let all_types_data = create_all_types_struct();
        let native_table: AllTypesT = all_types_data.clone().into();
        let builder = pack_flatbuffer(&native_table);
        let fb_data = builder.finished_data();
        let mut context = EnclaveFunctionContext::default();
        context.forwarded_parameters.buffer = fb_data.as_ptr() as *mut c_void;
        context.forwarded_parameters.buffer_size = fb_data.len();

        // Test function to be called by call_vtl1_export_from_vtl1.
        let dev_func = |dev_type: &mut AllTypes| {
            dev_type.i32_field = 1999; // simple mutation to verify roundtrip logic
        };

        register_vtl0_callouts_helper(None, None);

        // Act
        let void_context = &mut context as *mut _ as *mut c_void;
        let result = call_vtl1_export_from_vtl1::<_, AllTypes, AllTypesT>(dev_func, void_context);

        // Assert
        assert!(
            result.is_ok(),
            "call_vtl1_export_from_vtl1 failed with Hresult: {:?}",
            result.err().unwrap().to_hresult().0
        );

        let ret_buf = context.returned_parameters.buffer as *const u8;
        let ret_size = context.returned_parameters.buffer_size;

        let ret_slice = unsafe { core::slice::from_raw_parts(ret_buf, ret_size) };
        let new_all_types_data = AllTypesT::unpack(ret_slice).unwrap();
        assert_eq!(1999, new_all_types_data.i32_field);
    }

    // A Test developer function
    // Used during the "call_vtl0_callback_from_vtl1_succeeds" test.
    fn developer_host_impl(some_str: &mut String) {
        *some_str = String::from("This was added via generated_developer_host_impl_ffi");
    }

    // This simulates functionality that the edlcodegen host crate will perform when the
    // edlcodegen enclave crate calls into the CallEnclave API.
    // This is used during "call_vtl0_callback_from_vtl1_succeeds" test.
    extern "system" fn generated_developer_host_impl_ffi(context: *mut c_void) -> *mut c_void {
        let vtl0_context_ptr = context as *mut EnclaveFunctionContext;
        let in_buf = unsafe { (*vtl0_context_ptr).forwarded_parameters.buffer as *const u8 };
        let in_size = unsafe { (*vtl0_context_ptr).forwarded_parameters.buffer_size };
        let in_slice = unsafe { core::slice::from_raw_parts(in_buf, in_size) };
        let fb_input = AllTypesT::unpack(in_slice).unwrap();
        let mut dev_input: AllTypes = fb_input.into();

        // Simulate the edlcodegen host crate calling the developers impl function with the
        // input data.
        developer_host_impl(&mut dev_input.str_field);

        let fb_output: AllTypesT = dev_input.into();
        let fb_builder = pack_flatbuffer(&fb_output);
        let fb_output_slice = fb_builder.finished_data();

        unsafe {
            (*vtl0_context_ptr).returned_parameters.buffer_size = fb_output_slice.len();

            (*vtl0_context_ptr).returned_parameters.buffer = allocate_memory(fb_output_slice.len());

            ptr::copy_nonoverlapping(
                fb_output_slice.as_ptr(),
                (*vtl0_context_ptr).returned_parameters.buffer as *mut u8,
                fb_output_slice.len(),
            );
        }

        S_OK as *mut c_void
    }

    #[test]
    fn call_vtl0_callback_from_vtl1_succeeds() {
        // Arrange
        let all_types_data = create_all_types_struct();
        let fb_native: AllTypesT = all_types_data.into();
        let additional_addrs = vec![abi_func_to_address(generated_developer_host_impl_ffi)];
        let additional_names = vec!["generated_developer_host_impl_ffi".to_string()];
        register_vtl0_callouts_helper(Some(&additional_addrs), Some(&additional_names));

        // Act
        let result = call_vtl0_callback_from_vtl1::<AllTypes, AllTypesT>(
            &fb_native,
            "generated_developer_host_impl_ffi",
        );

        // Assert
        assert!(
            result.is_ok(),
            "call_vtl0_callback_from_vtl1 failed with {:?}",
            result.err()
        );

        let unpacked_data = result.unwrap();
        assert_eq!(
            "This was added via generated_developer_host_impl_ffi".to_string(),
            unpacked_data.str_field
        );
    }
}
