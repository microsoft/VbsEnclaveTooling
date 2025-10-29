// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern crate alloc;
use crate::enclave_ffi::enclave_get_enclave_information;
use crate::vtl0_pointers::Vtl0MemoryPtr;
use alloc::{collections::BTreeMap, string::String};
use core::{ffi::c_void, ptr};
use edlcodegen_core::{edl_core_ffi, edl_core_types::AbiError, helpers::pvoid_to_hresult};
use spin::{Once, RwLock};

/// Global registry of VTL0 host callout functions (allocation/deallocation etc.)
#[derive(Default)]
pub struct Vtl0FunctionMap {
    table: BTreeMap<String, u64>,
    alloc_func: Option<edl_core_ffi::EnclaveRoutine>,
    dealloc_func: Option<edl_core_ffi::EnclaveRoutine>,
    enclave_memory_begin: usize,
    enclave_memory_end: usize,
}

const ALLOC_FUNC_NAME: &str = "VbsEnclaveABI::HostApp::AllocateVtl0MemoryCallback";
const DEALLOC_FUNC_NAME: &str = "VbsEnclaveABI::HostApp::DeallocateVtl0MemoryCallback";

impl Vtl0FunctionMap {
    pub const fn new() -> Self {
        Self {
            table: BTreeMap::new(),
            alloc_func: None,
            dealloc_func: None,
            enclave_memory_begin: 0_usize,
            enclave_memory_end: 0_usize,
        }
    }

    /// Adds host callouts and updates allocation/deallocation pointers.
    pub fn add_functions(&mut self, addresses: &[u64], names: &[String]) -> Result<(), AbiError> {
        if names.len() != addresses.len() || names.len() < 2 {
            return Err(AbiError::Hresult(edl_core_ffi::E_INVALIDARG));
        }

        if self.enclave_memory_begin == 0_usize || self.enclave_memory_end == 0_usize {
            self.update_enclave_memory_bounds();
        }

        for (name, addr) in names.iter().zip(addresses.iter()) {
            self.check_for_vtl0_function(*addr as usize);

            if !self.table.contains_key(name) {
                self.table.insert(name.clone(), *addr);
            }
        }

        if self.alloc_func.is_none() {
            self.alloc_func = self
                .table
                .get(ALLOC_FUNC_NAME)
                .map(|a| *a as edl_core_ffi::EnclaveRoutine);
        }

        if self.dealloc_func.is_none() {
            self.dealloc_func = self
                .table
                .get(DEALLOC_FUNC_NAME)
                .map(|a| *a as edl_core_ffi::EnclaveRoutine);
        }

        if self.alloc_func.is_none() || self.dealloc_func.is_none() {
            return Err(AbiError::Hresult(edl_core_ffi::E_INVALIDARG));
        }

        Ok(())
    }

    fn update_enclave_memory_bounds(&mut self) {
        let info = enclave_get_enclave_information().unwrap_or_else(|err| {
            panic!(
                "Unable to retrieve enclave information: Hresult: {:X}",
                err.to_hresult().0
            );
        });

        self.enclave_memory_begin = info.BaseAddress as usize;
        self.enclave_memory_end = self
            .enclave_memory_begin
            .checked_add(info.Size)
            .unwrap_or_else(|| {
                panic!(
                    "Could not get end of enclave address range: Hresult: {:X}",
                    edl_core_ffi::E_FAIL
                );
            });
    }

    /// Verifies that a function pointer points to VTL0 (outside enclave memory).
    fn check_for_vtl0_function(&self, func_addr: usize) {
        if let Some(res) = self
            .check_for_vtl0_buffer(func_addr, size_of_val(&func_addr))
            .err()
        {
            panic!(
                "Unable to validate that pointer lies in vtl0 memory space. HRESULT: {:X}",
                res.to_hresult().0
            );
        }
    }

    /// Verifies that a buffer lies entirely outside enclave memory (VTL0).
    fn check_for_vtl0_buffer(&self, buffer_start: usize, length: usize) -> Result<(), AbiError> {
        if length == 0 {
            return Err(AbiError::Hresult(edl_core_ffi::E_INVALIDARG));
        }

        let buffer_end = buffer_start
            .checked_add(length)
            .ok_or(AbiError::Hresult(edl_core_ffi::E_INVALIDARG))?;

        if buffer_start >= self.enclave_memory_end || buffer_end <= self.enclave_memory_begin {
            return Ok(());
        }

        Err(AbiError::Hresult(edl_core_ffi::E_FAIL))
    }

    /// Calls into the host’s allocation routine through CallEnclave.
    pub fn allocate_vtl0_memory<T>(&self, size: usize) -> Result<Vtl0MemoryPtr<T>, AbiError> {
        let func = self.alloc_func.ok_or(AbiError::Hresult(edl_core_ffi::E_INVALIDARG))?;
        let mut memory_output: *mut c_void = ptr::null_mut();

        unsafe {
            edl_core_ffi::call_enclave(
                func,
                size as *const c_void,
                &mut memory_output as *mut *mut c_void,
            )?;
        }

        if memory_output.is_null() {
            // memory_output should never be null unless host's memory is exhausted.
            panic!("memory_output from CallEnclaves allocate_vtl0_memory was null");
        }

        // SAFETY:
        // The host allocated this buffer through a verified enclave ABI callback.
        // It is valid for the specified size and must later be deallocated through
        // the corresponding VTL0 free callback.
        Ok(unsafe { Vtl0MemoryPtr::from_raw(memory_output as *mut T) })
    }

    /// Calls into the host’s deallocation routine through CallEnclave.
    ///
    /// # Safety
    /// This function performs a cross-VTL call into the host’s memory space using the
    /// Win32 `CallEnclave` API. Rust cannot verify pointer validity or the safety of
    /// this external call. The following invariants must be upheld by the caller:
    /// - `ptr` must point to a valid VTL0-allocated buffer previously returned from
    ///   `allocate_vtl0_memory`.
    /// - The host callback registered in `self.dealloc_func` must be a trusted
    ///   function pointer matching the expected signature `fn(*mut c_void) -> *mut c_void`.
    ///
    /// The unsafe block exists because `CallEnclave` is an external C API that
    /// cannot be memory- or type-checked by the Rust compiler.
    pub unsafe fn deallocate_vtl0_memory(&self, ptr: *mut c_void) -> Result<(), AbiError> {
        let func = self.dealloc_func.ok_or(AbiError::Hresult(edl_core_ffi::E_INVALIDARG))?;
        let mut returned_hr_ptr: *mut c_void = ptr::null_mut();

        unsafe {
            edl_core_ffi::call_enclave(func, ptr, &mut returned_hr_ptr as *mut *mut c_void)?;
        }

        let hr = pvoid_to_hresult(returned_hr_ptr);

        if hr != edl_core_ffi::S_OK {
            return Err(AbiError::Hresult(hr));
        }

        Ok(())
    }

    /// Looks up a registered host function pointer by name.
    pub fn try_get_function(&self, name: &str) -> Option<edl_core_ffi::EnclaveRoutine> {
        self.table
            .get(name)
            .copied()
            .map(|a| a as edl_core_ffi::EnclaveRoutine)
    }
}

pub fn vtl0_function_map() -> &'static RwLock<Vtl0FunctionMap> {
    static VTL0_FUNCTION_MAP: Once<RwLock<Vtl0FunctionMap>> = Once::new();
    VTL0_FUNCTION_MAP.call_once(|| RwLock::new(Vtl0FunctionMap::new()))
}
