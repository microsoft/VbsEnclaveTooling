// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "pch.h"

#include <array>
#include <iostream>
#include <span>
#include <sstream>
#include <vector>

#include <wil/resource.h>
#include <wil/token_helpers.h>

#include "veil.any.h"
#include "veil_arguments.any.h"

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


namespace veil::vtl0::enclave::implementation
{
    template <typename T>
    inline HRESULT call_enclave_function(void* enclave, veil::implementation::export_ordinals ordinal, T& io);
}

namespace veil::vtl0::enclave
{
    template <typename DataT>
    inline HRESULT call_enclave(void* enclave, LPCSTR name, DataT& data) try
    {
        auto routine = reinterpret_cast<PENCLAVE_ROUTINE>(::GetProcAddress(reinterpret_cast<HMODULE>(enclave), name));
        THROW_LAST_ERROR_IF_NULL(routine);

        void* output = hr_to_pvoid(E_UNEXPECTED);
        THROW_IF_WIN32_BOOL_FALSE(::CallEnclave(routine, reinterpret_cast<void*>(&data), TRUE, reinterpret_cast<void**>(&output)));

        return pvoid_to_hr(output);
    }
    CATCH_RETURN()

    inline std::wstring format_enclave_error(const enclave_error& error)
    {
        wchar_t szErrorText[256]{};
        ::FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            error.hr,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            szErrorText,
            ARRAYSIZE(szErrorText),
            nullptr);

        std::wstringstream ss;
        static int s_errorId{};
        //ss << L"[Error: " << (s_errorId++) << L"] " << error.wmessage << L" " << szErrorText;
        ss << L"[Error:" << (s_errorId++) << L" Thread:" << std::hex << error.threadId << L"] " << error.wmessage << L" " << szErrorText;
        return ss.str();
    }

    inline void print_enclave_errors(const std::vector<enclave_error>& errors)
    {
        for (const auto& error : errors)
        {
            auto msg = format_enclave_error(error);
            std::wcout << L"  " << msg << std::endl;
        }
    }

    inline std::vector<enclave_error> retrieve_enclave_errors(void* enclave, DWORD threadId)
    {
        auto errors = std::vector<enclave_error>{};
        while (true)
        {
            enclave_arguments_with_hr<DWORD> threadError;
            threadError.data = threadId;
            if (SUCCEEDED(implementation::call_enclave_function(enclave, veil::implementation::export_ordinals::retrieve_enclave_error_for_thread, threadError)))
            {
                auto& error = threadError.error;
                if (SUCCEEDED(error.hr))
                {
                    break;
                }
                errors.push_back(error);
            }
            else
            {
                break;
            }
        }
        return errors;
    }
}

namespace veil::vtl0::enclave::implementation
{
    template <typename T>
    inline HRESULT call_enclave_function(void* enclave, veil::implementation::export_ordinals ordinal, T& io)
    {
        constexpr auto name = "VeilEnclaveSdkEntrypoint";

        enclave_ordinal_call_wrapping<T> ordinalCall{};
        ordinalCall.ordinal = static_cast<UINT32>(ordinal);

        auto& result = ordinalCall.argumentsWithHr;
        result.data = io; // shallow copy - debug-mode-only - doesn't work in general
        HRESULT hr = call_enclave(enclave, name, ordinalCall);
        if (FAILED(hr))
        {
#if 1
            // todo: remove this printing code and move to a wil::SetResultLoggingCallback style of logging
            auto threadId = result.error.threadId;

            auto lock = std::scoped_lock<std::mutex>(veil::vtl0::implementation::g_printMutex);

            std::wcout << std::endl;
            std::wcout << "[Error-chain] Routine: " << name << ", " << (uint32_t)ordinal << "." << std::endl << std::endl;
            auto errors = retrieve_enclave_errors(enclave, threadId);
            print_enclave_errors(errors);
            std::wcout << "[/Error-chain]" << std::endl << std::endl;
#endif
            RETURN_HR(hr);
        }
        io = result.data; // shallow copy in reverse - debug-mode-only - doesn't work in general
        return S_OK;
    }
}

namespace veil::vtl0::enclave_api
{
    void unlock_for_app_user(void* enclave);
    void register_callbacks(void* enclave);
}
