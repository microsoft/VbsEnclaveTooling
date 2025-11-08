// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <array>

#define SAMPLE_ENCLAVE_FAMILY_ID \
    { \
        0xED, 0X1D, 0xD0, 0x21, 0xC1, 0xB3, 0x42, 0x4C, \
        0x96, 0x49, 0xF6, 0xE9, 0x18, 0x18, 0x70, 0x36, \
    }

#define SAMPLE_ENCLAVE_IMAGE_ID \
    { \
        0x9B, 0x9B, 0x50, 0xDD, 0x83, 0x2F, 0x44, 0xFD, \
        0xB3, 0x8D, 0xAD, 0x87, 0x92, 0xD6, 0x9F, 0x42, \
    }

// version, let's match Windows version, 10.0.26100.0 -> A.0.65F4.00
#define SAMPLE_ENCLAVE_IMAGE_VERSION 0xA065F400 

#define SAMPLE_ENCLAVE_SVN 1000

// The expected virtual size of the private address range for the enclave, in bytes, 512MB
#define SAMPLE_ENCLAVE_ADDRESS_SPACE_SIZE 0x20000000 

// Enclave image creation policies
#ifndef ENCLAVE_MAX_THREADS
#define SAMPLE_ENCLAVE_MAX_THREADS 16
#endif

constexpr int EnclavePolicy_EnableDebuggingForDebugBuildsOnly
{
#ifdef _DEBUG
        IMAGE_ENCLAVE_POLICY_DEBUGGABLE
#endif
};

// VBS enclave configuration - included statically
extern "C" const IMAGE_ENCLAVE_CONFIG __enclave_config = {
    sizeof(IMAGE_ENCLAVE_CONFIG),
    IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    EnclavePolicy_EnableDebuggingForDebugBuildsOnly,
    0,
    0,
    0,
    SAMPLE_ENCLAVE_FAMILY_ID,
    SAMPLE_ENCLAVE_IMAGE_ID,
    SAMPLE_ENCLAVE_IMAGE_VERSION,
    SAMPLE_ENCLAVE_SVN,
    SAMPLE_ENCLAVE_ADDRESS_SPACE_SIZE,
    SAMPLE_ENCLAVE_MAX_THREADS,
    IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE };

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    default:
        break;
    }
    return TRUE;
}
