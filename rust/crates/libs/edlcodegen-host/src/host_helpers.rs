// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::host_ffi::get_enclave_function;
use core::{ffi::c_void, ptr};
use edlcodegen_core::{
    edl_core_ffi::call_enclave,
    edl_core_types::{AbiError, EnclaveFunctionContext, EnclaveHandle},
    flatbuffer_support,
    heap_pointer::HeapPtr,
    helpers::proc_address_to_isize,
};

use windows::Win32::Foundation::E_INVALIDARG;

fn context_as_mut<'a, T>(context: *mut c_void) -> Result<&'a mut T, AbiError> {
    if context.is_null() {
        Err(AbiError::Hresult(E_INVALIDARG.0))
    } else {
        // SAFETY: Checked not null, but type correctness is still caller's responsibility.
        // This is only used when passing input data from vtl1 to vtl0. We expect the
        // *mut c_void to be valid vtl0 memory created by our framework inside the enclave.
        Ok(unsafe { &mut *(context as *mut T) })
    }
}

pub fn call_vtl0_callback_from_vtl0<F, DevTypeT, FlatbufferT>(
    mut dev_impl_func: F,
    context: *mut c_void,
) -> Result<(), AbiError>
where
    F: FnMut(&mut DevTypeT),
    DevTypeT: Clone + From<FlatbufferT> + Into<FlatbufferT>,
    FlatbufferT: for<'a> flatbuffer_support::FlatbufferPack<'a>,
{
    let context_ref = context_as_mut::<EnclaveFunctionContext>(context)?;

    // Extract input params.
    let in_buf = context_ref.forwarded_parameters.buffer as *const u8;
    let in_size = context_ref.forwarded_parameters.buffer_size;
    if in_size > 0 && in_buf.is_null() || in_buf.is_null() {
        return Err(AbiError::Hresult(E_INVALIDARG.0));
    }

    // Unpack flatbuffer byte array into its native struct type and convert it to a developer type.
    let local_in = unsafe { core::slice::from_raw_parts(in_buf, in_size) };
    let fb_input: FlatbufferT =
        FlatbufferT::unpack(local_in).map_err(|_| AbiError::Hresult(E_INVALIDARG.0))?;
    let mut dev_input: DevTypeT = fb_input.into();

    // Call developer implementation.
    dev_impl_func(&mut dev_input);

    // Convert updated developer type back into its flatbuffer struct and pack it into an array of bytes.
    let fb_output: FlatbufferT = dev_input.into();
    let fb_builder = flatbuffer_support::pack_flatbuffer(&fb_output);
    let fb_output_slice: &[u8] = fb_builder.finished_data();

    // VTL1 will free this memory.
    context_ref.returned_parameters.buffer_size = fb_output_slice.len();
    let heap_ptr = HeapPtr::from_slice(fb_output_slice)?;
    context_ref.returned_parameters.buffer = heap_ptr.into_raw() as *mut c_void;

    Ok(())
}

pub fn call_vtl1_export_from_vtl0<DevTypeT, FlatbufferT>(
    fb_input: &FlatbufferT,
    enclave_instance: *mut c_void,
    func_name: windows::core::PCSTR,
) -> Result<DevTypeT, AbiError>
where
    DevTypeT: Clone + From<FlatbufferT> + Into<FlatbufferT>,
    FlatbufferT: for<'a> flatbuffer_support::FlatbufferPack<'a>,
{
    // Pack input flatbuffer.
    let fb_builder = flatbuffer_support::pack_flatbuffer(fb_input);
    let fb_input_slice: &[u8] = fb_builder.finished_data();

    // Create context so flatbuffer input can be passed to the enclave.
    let mut context = EnclaveFunctionContext::default();
    context.forwarded_parameters.buffer = fb_input_slice.as_ptr() as *mut c_void;
    context.forwarded_parameters.buffer_size = fb_input_slice.len();
    let enclave_handle = EnclaveHandle(enclave_instance);

    let proc_address = get_enclave_function(&enclave_handle, func_name)?;

    // Call into VTL0 function.
    let mut call_result: *mut c_void = ptr::null_mut();

    unsafe {
        call_enclave(
            proc_address_to_isize(proc_address),
            &raw const context as *const c_void,
            &mut call_result as *mut *mut c_void,
        )?;
    }

    // Copy the returned buffer into enclave memory.
    let ret_buf = context.returned_parameters.buffer as *const u8;
    let ret_size = context.returned_parameters.buffer_size;

    if ret_size > 0 && ret_buf.is_null() || ret_buf.is_null() {
        return Err(AbiError::Hresult(E_INVALIDARG.0));
    }

    // Make sure we free the returned buffer before we exit
    let _return_buffer_ptr = unsafe { HeapPtr::from_raw(context.returned_parameters.buffer) };

    // Unpack the flatbuffer and return updated developer type back to the caller.
    let ret_slice = unsafe { core::slice::from_raw_parts(ret_buf, ret_size) };
    let fb_result =
        FlatbufferT::unpack(ret_slice).map_err(|_| AbiError::Hresult(E_INVALIDARG.0))?;

    Ok(fb_result.into())
}
