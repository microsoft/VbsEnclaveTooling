// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern crate alloc;
use crate::enclave_ffi::{
    enclave_copy_buffer_in, enclave_copy_buffer_out, enclave_copy_into_enclave,
    enclave_copy_out_of_enclave,
};
use crate::memory_helpers::vtl0_function_map;
use crate::vtl0_pointers::Vtl0MemoryPtr;
use alloc::string::String;
use core::ffi::c_void;
use edlcodegen_core::{
    edl_core_ffi::{CallEnclaveInput, call_enclave},
    edl_core_types,
    edl_core_types::AbiError,
    edl_core_types::EnclaveFunctionContext,
    flatbuffer_support,
};

pub fn call_vtl1_export_from_vtl1<F, DevTypeT, FlatbufferT>(
    mut dev_impl_func: F,
    context: *mut c_void,
) -> Result<(), AbiError>
where
    F: FnMut(&mut DevTypeT) -> Result<(), AbiError>,
    DevTypeT: Clone + From<FlatbufferT> + Into<FlatbufferT>,
    FlatbufferT: for<'a> flatbuffer_support::FlatbufferPack<'a>,
{
    // Validate pointer.
    if context.is_null() {
        return Err(AbiError::Hresult(edl_core_types::E_INVALIDARG));
    }

    // Immediately copy it into enclave-local memory.
    let vtl0_context_ptr = context as *mut EnclaveFunctionContext;
    let mut copied_context = EnclaveFunctionContext::default();
    enclave_copy_into_enclave(&mut copied_context, vtl0_context_ptr)?;

    // Extract input params.
    let in_buf = copied_context.forwarded_parameters.buffer as *const u8;
    let in_size = copied_context.forwarded_parameters.buffer_size;
    if in_size > 0 && in_buf.is_null() || in_buf.is_null() {
        return Err(AbiError::Hresult(edl_core_types::E_INVALIDARG));
    }

    // Copy VTL0 buffer into enclave heap.
    let mut local_in = alloc::vec![0u8; in_size];
    enclave_copy_buffer_in(local_in.as_mut_ptr(), in_buf, in_size)?;

    // Unpack flatbuffer byte array into its native struct type and convert it to a developer type.
    let fb_input: FlatbufferT = FlatbufferT::unpack(&local_in)
        .map_err(|_| AbiError::Hresult(edl_core_types::E_INVALIDARG))?;
    let mut dev_input: DevTypeT = fb_input.into();

    // Call developer implementation.
    dev_impl_func(&mut dev_input)?;

    // Convert updated developer type back into its flatbuffer struct and pack it into an array of bytes.
    let fb_output: FlatbufferT = dev_input.into();
    let fb_builder = flatbuffer_support::pack_flatbuffer(&fb_output);
    let fb_output_slice: &[u8] = fb_builder.finished_data();

    // Allocate VTL0 memory for the return buffer.
    let vtl0_output_params_ptr = vtl0_function_map()
        .read()
        .allocate_vtl0_memory::<u8>(fb_output_slice.len())?;

    enclave_copy_buffer_out(
        vtl0_output_params_ptr.as_mut_ptr(),
        fb_output_slice.as_ptr(),
        fb_output_slice.len(),
    )?;

    // Copy flatbuffer byte array into return buffer.
    enclave_copy_out_of_enclave(
        // SAFETY:
        // We are obtaining a raw pointer to the VTL0 `buffer_size` field inside
        // the context struct and copying the size of the slice into it.
        // This is unsafe since we're dereferencing a raw pointer to access the
        // buffer_size .
        unsafe { &raw mut (*vtl0_context_ptr).returned_parameters.buffer_size },
        &fb_output_slice.len(),
    )?;

    enclave_copy_out_of_enclave(
        // SAFETY:
        // We are obtaining a raw pointer to the buffer field and copying the raw
        // vtl0 memory ptr into it.
        // This is unsafe since we're dereferencing a raw pointer to access the
        // buffer field.
        unsafe { &raw mut (*vtl0_context_ptr).returned_parameters.buffer },
        vtl0_output_params_ptr.as_const_mut_void_ptr(),
    )?;

    // Release output pointer. VTL0 will free it.
    _ = vtl0_output_params_ptr.into_raw();

    Ok(())
}

pub fn call_vtl0_callback_from_vtl1<DevTypeT, FlatbufferT>(
    fb_input: &FlatbufferT,
    func_name: &str,
) -> Result<DevTypeT, AbiError>
where
    DevTypeT: Clone + From<FlatbufferT> + Into<FlatbufferT>,
    FlatbufferT: for<'a> flatbuffer_support::FlatbufferPack<'a>,
{
    // Pack input flatbuffer.
    let fb_builder = flatbuffer_support::pack_flatbuffer(fb_input);
    let fb_input_slice: &[u8] = fb_builder.finished_data();

    // Get allocate vtl0 function pointer from global table
    let table_read_access = vtl0_function_map().read();
    let vtl0_function = table_read_access
        .try_get_function(func_name)
        .ok_or(AbiError::Hresult(edl_core_types::E_INVALIDARG))?;

    // Copy flatbuffer input into VTL0 buffer.
    let vtl0_input_params_ptr =
        table_read_access.allocate_vtl0_memory::<u8>(fb_input_slice.len())?;

    enclave_copy_buffer_out(
        vtl0_input_params_ptr.as_mut_ptr(),
        fb_input_slice.as_ptr(),
        fb_input_slice.len(),
    )?;

    // Create context so flatbuffer input can be passed to the host.
    let mut vtl1_outgoing_context_obj = EnclaveFunctionContext::default();
    vtl1_outgoing_context_obj.forwarded_parameters.buffer =
        vtl0_input_params_ptr.as_mut_ptr() as *mut c_void;

    vtl1_outgoing_context_obj.forwarded_parameters.buffer_size = fb_input_slice.len();

    let vtl0_input_context_ptr = table_read_access
        .allocate_vtl0_memory::<EnclaveFunctionContext>(size_of::<EnclaveFunctionContext>())?;

    enclave_copy_out_of_enclave(
        vtl0_input_context_ptr.as_mut_ptr(),
        &vtl1_outgoing_context_obj,
    )?;

    let call_enclave_input = CallEnclaveInput::new(
        vtl0_function,
        vtl0_input_context_ptr.as_ptr() as *const c_void,
    );
    // Call into VTL0 function.
    call_enclave::<()>(call_enclave_input)?;

    // Copy result context back into enclave.
    let mut vtl1_incoming_context_obj = EnclaveFunctionContext::default();
    enclave_copy_into_enclave(
        &mut vtl1_incoming_context_obj,
        vtl0_input_context_ptr.as_ptr(),
    )?;

    // Copy the returned buffer into enclave memory.
    let ret_buf = vtl1_incoming_context_obj.returned_parameters.buffer as *const u8;
    let ret_size = vtl1_incoming_context_obj.returned_parameters.buffer_size;
    if ret_size > 0 && ret_buf.is_null() || ret_buf.is_null() {
        return Err(AbiError::Hresult(edl_core_types::E_INVALIDARG));
    }

    // Make sure we free the returned buffer before we exit
    let _return_buffer_ptr =
        Vtl0MemoryPtr::from_raw(vtl1_incoming_context_obj.returned_parameters.buffer);

    let mut local_buf = alloc::vec![0u8; ret_size];
    enclave_copy_buffer_in(local_buf.as_mut_ptr(), ret_buf, ret_size)?;

    // Unpack the flatbuffer and return updated developer type back to the caller.
    let fb_result: FlatbufferT = FlatbufferT::unpack(&local_buf)
        .map_err(|_| AbiError::Hresult(edl_core_types::E_INVALIDARG))?;

    let dev_result: DevTypeT = fb_result.into();

    Ok(dev_result)
}

pub fn register_vtl0_callouts(
    callback_addresses: &[u64],
    callback_names: &[String],
) -> Result<(), AbiError> {
    vtl0_function_map()
        .write()
        .add_functions(callback_addresses, callback_names)
}
