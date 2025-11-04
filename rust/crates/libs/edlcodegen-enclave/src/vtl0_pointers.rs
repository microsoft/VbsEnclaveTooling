// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern crate alloc;

use crate::memory_helpers::vtl0_function_map;
use core::ffi::c_void;

/// Smart pointer that takes ownership of raw vtl0 memory.
pub struct Vtl0MemoryPtr<T> {
    ptr: *mut T,
}

impl<T> Vtl0MemoryPtr<T> {
    /// Creates a wrapper around an existing pointer allocated by the host.
    ///
    /// # Safety
    /// The pointer must be valid and allocated through the enclave host ABI.
    pub const unsafe fn from_raw(ptr: *mut T) -> Self {
        Self { ptr }
    }

    pub const fn as_ptr(&self) -> *const T {
        self.ptr
    }

    pub const fn as_mut_ptr(&self) -> *mut T {
        self.ptr
    }

    /// Consumes the wrapper and returns the raw pointer, skipping deallocation.
    pub fn into_raw(self) -> *mut T {
        let raw = self.ptr;
        core::mem::forget(self);
        raw
    }

    #[inline]
    pub const fn as_const_mut_void_ptr(&self) -> *const *mut c_void {
        &raw const self.ptr as *const *mut c_void
    }

    /// Returns `true` if the internal pointer is null.
    pub const fn is_null(&self) -> bool {
        self.ptr.is_null()
    }
}

impl<T> Drop for Vtl0MemoryPtr<T> {
    fn drop(&mut self) {
        if self.is_null() {
            return;
        }

        // TODO: Should figure out how we can Log somehow.
        let _ = unsafe {
            vtl0_function_map()
                .read()
                .deallocate_vtl0_memory(self.ptr as *mut c_void)
        };
    }
}
