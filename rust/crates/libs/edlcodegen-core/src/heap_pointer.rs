// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern crate alloc;

use crate::{
    edl_core_types::AbiError,
    helpers::{allocate_memory, copy_slice_to_buffer, deallocate_memory},
};
use core::ffi::c_void;

/// light weight smart pointer that owns memory using HeapAlloc and HeapFree
/// as it's allocation and deallocation mechanisms.
pub struct HeapPtr<T> {
    ptr: *mut T,
}

impl<T> HeapPtr<T> {
    pub fn new(size: usize) -> Self {
        Self {
            ptr: allocate_memory(size) as *mut T,
        }
    }

    pub const fn from_raw(ptr: *mut T) -> Self {
        Self { ptr }
    }

    pub fn from_slice(slice: &[T]) -> Result<Self, AbiError> {
        let heap_ptr = Self::new(slice.len());
        copy_slice_to_buffer(heap_ptr.as_mut_ptr() as *mut c_void, slice)?;
        Ok(heap_ptr)
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

    /// Returns `true` if the internal pointer is null.
    pub const fn is_null(&self) -> bool {
        self.ptr.is_null()
    }
}

impl<T> Drop for HeapPtr<T> {
    fn drop(&mut self) {
        if self.is_null() {
            return;
        }

        // TODO: Should figure out how we can Log somehow.
        let _ = deallocate_memory(self.ptr as *mut c_void);
    }
}
