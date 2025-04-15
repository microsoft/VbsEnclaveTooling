// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "pch.h"

#include <span>
#include <vector>

#include <wil/resource.h>
#include <wil/token_helpers.h>

#include "utils.vtl0.h"

namespace veil::vtl0
{
    // Lifetime
    namespace implementation
    {
        inline void terminate_and_delete(void* enclave) noexcept
        {
            // fWait = TRUE means that we wait for all threads in the enclave to terminate.
            // This is necessary because you cannot delete an enclave if it still has
            // running threads.
            LOG_IF_WIN32_BOOL_FALSE(::TerminateEnclave(enclave, TRUE));

            // Delete the enclave.
            LOG_IF_WIN32_BOOL_FALSE(::DeleteEnclave(enclave));
        }
    }

    using unique_enclave = wil::unique_any<void*, decltype(&implementation::terminate_and_delete), implementation::terminate_and_delete>;

    namespace appmodel
    {
        inline std::vector<uint8_t> owner_id()
        {
            // todo
            return {};
        }
    }

    namespace enclave
    {
        inline size_t megabytes(unsigned long long megabytes) noexcept
        {
            return megabytes * 0x100000;
        }

        inline unique_enclave create(DWORD enclaveType, std::span<const uint8_t> ownerId, DWORD flags, size_t size, size_t initialCommitment = 0, LPDWORD lpEnclaveError = nullptr)
        {
            if (enclaveType != ENCLAVE_TYPE_VBS)
            {
                THROW_HR(E_FAIL);
            }

            if (!::IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS))
            {
                printf("VBS Enclave not supported\n");
                THROW_HR_MSG(E_ACCESSDENIED, "VBS enclave type not supported");
            }

            ENCLAVE_CREATE_INFO_VBS createInfo;
            createInfo.Flags = flags;
            std::memcpy(
                createInfo.OwnerID, ownerId.data(),
                ownerId.size() > IMAGE_ENCLAVE_LONG_ID_LENGTH ? IMAGE_ENCLAVE_LONG_ID_LENGTH : ownerId.size());

            auto enclave = unique_enclave{ ::CreateEnclave(
                GetCurrentProcess(),
                nullptr,    // Preferred base address
                size, // Size
                initialCommitment,          // Initial commit
                ENCLAVE_TYPE_VBS,
                &createInfo,
                sizeof(ENCLAVE_CREATE_INFO_VBS),
                lpEnclaveError) }; // EnclaveError
            THROW_LAST_ERROR_IF_NULL(enclave);

            return enclave;
        }

        inline void load_image(void* enclave, PCWSTR image)
        {
            // Load enclave module with SEM_FAILCRITICALERRORS enabled to suppress
            // the error message dialog.
            DWORD previousMode = GetThreadErrorMode();
            ::SetThreadErrorMode(previousMode | SEM_FAILCRITICALERRORS, nullptr);
            auto restoreErrorMode = wil::scope_exit([&]
            {
                ::SetThreadErrorMode(previousMode, nullptr);
            });
            THROW_IF_WIN32_BOOL_FALSE(::LoadEnclaveImageW(enclave, image));
        }

        inline void initialize(void* enclave, DWORD threadCount = 1)
        {
            ENCLAVE_INIT_INFO_VBS initializationInfo{};
            initializationInfo.Length = sizeof(ENCLAVE_INIT_INFO_VBS);
            initializationInfo.ThreadCount = threadCount;

            THROW_IF_WIN32_BOOL_FALSE(::InitializeEnclave(GetCurrentProcess(), enclave, &initializationInfo, initializationInfo.Length, nullptr));
        }
    }
}

namespace veil::vtl0::enclave_api
{
    void register_callbacks(void* enclave);
}
