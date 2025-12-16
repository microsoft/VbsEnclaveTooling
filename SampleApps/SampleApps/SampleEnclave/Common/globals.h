// Copyright (c) Microsoft Corporation.
//

#pragma once

#include <wil/resource.h>
#include <wil/win32_helpers.h>

// Global runtime policy for enclave operations
// 
// ENCLAVE_RUNTIME_POLICY_ALLOW_FULL_DEBUG:
//   - **DEBUG ONLY** - Allows debugger to attach and inspect enclave state
//   - **SECURITY WARNING**: Reduces isolation guarantees in debug builds
//   - Production builds should use 0 (no debug policy) for maximum security
#ifdef _DEBUG
    constexpr UINT32 g_runtimePolicy = ENCLAVE_RUNTIME_POLICY_ALLOW_FULL_DEBUG;
#else
    // Production: No debug policy - maximum security and isolation
    constexpr UINT32 g_runtimePolicy = 0;
#endif

// Global encryption key management
extern wil::unique_bcrypt_key g_encryptionKey;
extern wil::srwlock g_encryptionKeyLock;

// Thread-safe helper functions for encryption key management
bool IsUBKLoaded();
BCRYPT_KEY_HANDLE GetEncryptionKeyHandle();
void SetEncryptionKey(wil::unique_bcrypt_key&& newKey);
