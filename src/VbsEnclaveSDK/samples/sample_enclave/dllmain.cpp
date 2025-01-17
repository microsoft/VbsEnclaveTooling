// <copyright placeholder>

#include "pch.h"

#include <array>

#include "enclave_interface.vtl1.h"

#define SAMPLE_ENCLAVE_FAMILY_ID \
    { \
        0xED, 0X1D, 0xD0, 0x21, 0xC1, 0xB3, 0x42, 0x4C, \
        0x96, 0x49, 0xF6, 0xE9, 0x18, 0x18, 0x70, 0x36, \
    }

#define SAMPLE_ENCLAVE_SNAPSHOT_IMAGE_ID \
    { \
        0x9B, 0x9B, 0x50, 0xDD, 0x83, 0x2F, 0x44, 0xFD, \
        0xB3, 0x8D, 0xAD, 0x87, 0x92, 0xD6, 0x9F, 0x42, \
    }

#define ENCLAVE_IMAGE_VERSION 0xA065F400 // version - 10.0.26100.0

#define SAMPLE_SNAPSHOT_ENCLAVE_SVN 1000

#define ENCLAVE_ADDRESS_SPACE_SIZE \
    0x20000000 // The expected virtual size of the private address range for the enclave, in bytes, 512MB

// Enclave image creation policies
#ifndef ENCLAVE_MAX_THREADS
#define ENCLAVE_MAX_THREADS 16
#endif

// VBS enclave configuration - included statically
extern "C" const IMAGE_ENCLAVE_CONFIG __enclave_config = {
    sizeof(IMAGE_ENCLAVE_CONFIG),
    IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    IMAGE_ENCLAVE_POLICY_DEBUGGABLE,
    0,
    0,
    0,
    SAMPLE_ENCLAVE_FAMILY_ID,
    SAMPLE_ENCLAVE_SNAPSHOT_IMAGE_ID,
    ENCLAVE_IMAGE_VERSION,
    SAMPLE_SNAPSHOT_ENCLAVE_SVN,
    ENCLAVE_ADDRESS_SPACE_SIZE,
    ENCLAVE_MAX_THREADS,
    IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE};

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
