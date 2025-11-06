// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod common;
mod mocks;
use common::test_helpers::*;
use common::test_types::{
    dev_types::{AllTypes, TestFuncArgs},
    fb_generated::flatbuffer_test::{AllTypesT, TestFuncArgsT},
};

use core::ffi::c_void;
use edlcodegen_core::{edl_core_ffi::S_OK, helpers::hresult_to_pvoid};
use edlcodegen_enclave::enclave_helpers::call_vtl1_export_from_vtl1;
use edlcodegen_host::host_helpers::*;

#[allow(unused_imports)]
use mocks::mock_functions::*;
use windows::core::s;

/// A Test developer function in an enclave.
pub fn dev_enclave_func_impl(dev_type: &mut AllTypes) -> String {
    dev_type.str_field = "This was added as a test".to_string();
    "string returned by dev_enclave_func_impl".to_string()
}

/// helper functions that simulates a generated function exported by an enclave dll.
/// # Safety
///
/// `context` must be a valid pointer to a properly initialized `TestFuncArgs` structure.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn test_export_func_helper(context: *mut c_void) -> *mut c_void {
    // Use closure to call the developers impl function in the enclave.
    let dev_func = |dev_type: &mut TestFuncArgs| {
        // simple mutation to verify roundtrip logic
        dev_type.return_val = dev_enclave_func_impl(&mut dev_type.all_types);
    };

    let result = call_vtl1_export_from_vtl1::<_, TestFuncArgs, TestFuncArgsT>(dev_func, context);

    if let Some(err) = result.err() {
        return hresult_to_pvoid(err.to_hresult().0);
    }

    S_OK as *mut c_void
}

// Mock for get_proc_address which is called in the call_vtl1_export_from_vtl0_succeeds test
#[unsafe(no_mangle)]
unsafe extern "system" fn get_proc_address(
    _module_param: *mut c_void,
    func_name: windows::core::PCSTR,
) -> Option<unsafe extern "system" fn() -> isize> {
    let func_str = unsafe {
        func_name
            .to_string()
            .expect("couldn't convert func_name to string")
    };

    if func_str == "test_export_func_helper" {
        unsafe {
            Some(std::mem::transmute::<
                *const (),
                unsafe extern "system" fn() -> isize,
            >(test_export_func_helper as *const ()))
        }
    } else {
        panic!("Function name `{:?}` not found", func_str);
    }
}

#[cfg(test)]
mod edl_host {
    use edlcodegen_core::{
        edl_core_types::EnclaveFunctionContext,
        flatbuffer_support::{FlatbufferPack, pack_flatbuffer},
    };

    use super::*;

    #[test]
    fn call_vtl1_export_from_vtl0_succeeds() {
        // Arrange
        let test_func_args = create_test_func_args();
        let fb_native: TestFuncArgsT = test_func_args.into();

        // Our Abi only uses an instance of the enclave to retrieve the proc address of a function
        // within the enclave dll. In our tests we have mocked GetProcAddress so it does not use the
        // enclave instance. We only need a pointer to a c_void to satisfy the test.
        let mut fake_enclave = vec![1, 2, 3, 4, 5, 6];

        register_vtl0_callouts_helper(None, None);

        // Act
        let result = call_vtl1_export_from_vtl0::<TestFuncArgs, TestFuncArgsT>(
            &fb_native,
            fake_enclave.as_mut_ptr() as *mut c_void,
            s!("test_export_func_helper"),
        );

        // Assert
        assert!(
            result.is_ok(),
            "call_vtl1_export_from_vtl0 failed with {:?}",
            result.err()
        );

        let unpacked_result = result.unwrap();
        assert_eq!(
            "This was added as a test".to_string(),
            unpacked_result.all_types.str_field
        );

        assert_eq!(
            "string returned by dev_enclave_func_impl".to_string(),
            unpacked_result.return_val
        );
    }

    #[test]
    fn call_vtl0_callback_from_vtl0_succeeds() {
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
            // simple mutation to verify roundtrip logic
            dev_type.str_field = "Updated via call_vtl0_callback_from_vtl0_succeeds".to_string();
        };

        // Act
        let void_context = &mut context as *mut _ as *mut c_void;
        let result = call_vtl0_callback_from_vtl0::<_, AllTypes, AllTypesT>(dev_func, void_context);

        // Assert
        assert!(
            result.is_ok(),
            "call_vtl0_callback_from_vtl0 failed with Hresult: {:?}",
            result.err().unwrap().to_hresult().0
        );

        let ret_buf = context.returned_parameters.buffer as *const u8;
        let ret_size = context.returned_parameters.buffer_size;

        let ret_slice = unsafe { core::slice::from_raw_parts(ret_buf, ret_size) };
        let new_all_types_data = AllTypesT::unpack(ret_slice).unwrap();
        assert_eq!(
            "Updated via call_vtl0_callback_from_vtl0_succeeds".to_string(),
            new_all_types_data.str_field
        );
    }
}
