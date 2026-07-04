// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <windows.h>

#define TLS_SAMPLE_ENCLAVE_FAMILY_ID \
    { \
        0x52, 0x58, 0x4f, 0x6d, 0xb7, 0xc6, 0x4e, 0x4b, \
        0x9d, 0x93, 0xe7, 0x27, 0x18, 0x1d, 0x2b, 0x10, \
    }

#define TLS_SAMPLE_ENCLAVE_IMAGE_ID \
    { \
        0x7d, 0x9d, 0x7d, 0xe9, 0x51, 0x1e, 0x4a, 0xbe, \
        0x81, 0xf4, 0x8e, 0x31, 0x43, 0x2e, 0x36, 0x66, \
    }

extern "C" const IMAGE_ENCLAVE_CONFIG __enclave_config = {
    sizeof(IMAGE_ENCLAVE_CONFIG),
    IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    IMAGE_ENCLAVE_POLICY_STRICT_MEMORY | IMAGE_ENCLAVE_POLICY_DEBUGGABLE,
    0,
    0,
    0,
    TLS_SAMPLE_ENCLAVE_FAMILY_ID,
    TLS_SAMPLE_ENCLAVE_IMAGE_ID,
    0x00010000,
    1,
    0x20000000,
    4,
    IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE};

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID)
{
    return TRUE;
}
