// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#define ENCLAVE_FUNCTION extern "C" PVOID WINAPI

// Enclave image creation policies
#ifndef ENCLAVE_MAX_THREADS
#define ENCLAVE_MAX_THREADS 16
#endif

// Structures
struct AiEnclaveInputBlob
{
    PVOID Data;
    SIZE_T Size;
};
static_assert(std::is_standard_layout_v<AiEnclaveInputBlob>, "Structures that are passed to CallEnclave must be memcpy'able");

struct AiEnclaveOutputBlob
{
    PVOID Data;
    SIZE_T Capacity; // Total bytes available in Data
    SIZE_T Size;     // Bytes written to Data
};
static_assert(std::is_standard_layout_v<AiEnclaveOutputBlob>, "Structures that are passed to CallEnclave must be memcpy'able");

