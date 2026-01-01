// Copyright (c) Microsoft Corporation.
//

#include <pch.h>
#include "globals.h"

// Store the actual key object, not just the handle
wil::unique_bcrypt_key g_encryptionKey;

// SRW lock to protect access to g_encryptionKey (enclave-compatible)
wil::srwlock g_encryptionKeyLock;

bool IsUBKLoaded()
{
    // Thread-safe check if the key object is valid
    auto lock = g_encryptionKeyLock.lock_shared();
    return static_cast<bool>(g_encryptionKey);
}

// Helper function to safely get a copy of the key handle for use in crypto operations
// Returns nullptr if key is not loaded
BCRYPT_KEY_HANDLE GetEncryptionKeyHandle()
{
    auto lock = g_encryptionKeyLock.lock_shared();
    return g_encryptionKey.get();
}

// Helper function to safely set the encryption key
void SetEncryptionKey(wil::unique_bcrypt_key&& newKey)
{
    auto lock = g_encryptionKeyLock.lock_exclusive();
    g_encryptionKey = std::move(newKey);
}

// Global signature key management (separate from encryption key)
wil::unique_bcrypt_key g_signaturePrivateKey;
wil::srwlock g_signatureKeyLock;

// Thread-safe helper functions for signature key management
bool IsSignatureKeyLoaded()
{
    auto lock = g_signatureKeyLock.lock_shared();
    return g_signaturePrivateKey.is_valid();
}

BCRYPT_KEY_HANDLE GetSignatureKeyHandle()
{
    auto lock = g_signatureKeyLock.lock_shared();
    return g_signaturePrivateKey.get();
}

void SetSignatureKey(wil::unique_bcrypt_key&& newKey)
{
    auto lock = g_signatureKeyLock.lock_exclusive();
    g_signaturePrivateKey = std::move(newKey);
}
