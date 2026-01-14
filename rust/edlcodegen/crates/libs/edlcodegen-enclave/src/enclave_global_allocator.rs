// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use alloc::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use edlcodegen_core::helpers::{allocate_memory, deallocate_memory};

/// Global heap allocator for `no_std` enclave environments.
///
/// Since the Rust standard allocator is unavailable inside enclaves,
/// this allocator routes all heap operations through our custom
/// `allocate_memory` and `deallocate_memory` functions, which internally
/// call `HeapAlloc` and `HeapFree` from **vertdll.dll**.
pub struct EnclaveHeapAllocator;

unsafe impl GlobalAlloc for EnclaveHeapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = allocate_memory(layout.size());

        if ptr.is_null() {
            panic!("HeapAlloc of {} bytes failed", layout.size());
        }

        ptr as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if !ptr.is_null() {
            let _ = deallocate_memory(ptr as *mut c_void);
        }
    }
}

/// Registers the custom enclave allocator as the global allocator.
///
/// This ensures that all dynamic memory operations inside the enclave
/// (`Box`, `Vec`, `String`, etc.) use our alloc and dealloc methods.
#[global_allocator]
static HEAP_ALLOCATOR: EnclaveHeapAllocator = EnclaveHeapAllocator;
