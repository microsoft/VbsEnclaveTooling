// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <stdint.h>

#ifndef ENCLAVE_FUNCTION
#define ENCLAVE_FUNCTION extern "C" PVOID WINAPI
#endif

#ifndef HRESULT_TO_PVOID
#define HRESULT_TO_PVOID(hr) ((PVOID)((ULONG_PTR)(hr) & 0x00000000FFFFFFFF))
#endif

#ifndef PVOID_TO_HRESULT
#define PVOID_TO_HRESULT(p) ((HRESULT)((ULONG_PTR)(p) & 0x00000000FFFFFFFF))
#endif

#ifndef RETURN_HR_AS_PVOID
#define RETURN_HR_AS_PVOID(x) return veil::hr_to_pvoid(x);
#endif

#ifndef RETURN_PVOID_AS_HR
#define RETURN_PVOID_AS_HR(x) return veil::pvoid_to_hr(x);
#endif

namespace veil
{
    inline constexpr HRESULT pvoid_to_hr(void* ptr) noexcept
    {
        return PVOID_TO_HRESULT(ptr);
    }

    inline constexpr void* hr_to_pvoid(HRESULT hr) noexcept
    {
        return HRESULT_TO_PVOID(hr);
    }
}

#define VEIL_ABI_FUNCTION(__name, __args, __funcbody) \
    void* __name(void* __args) noexcept \
    try \
    { \
        HRESULT __hr = ([&]() noexcept \
            { \
                __funcbody \
            } \
        )(); \
        LOG_IF_FAILED(__hr); \
        return hr_to_pvoid(__hr); \
    } \
    catch (...) \
    { \
        HRESULT __hr = wil::ResultFromCaughtException(); \
        LOG_IF_FAILED(__hr); \
        return hr_to_pvoid(__hr); \
    } \

#define VEIL_ABI_FUNCTION_SIMPLIFIED(__name) \
    void* __name(void* __args) noexcept \
    try \
    { \
        simplified::__name(reinterpret_cast<veil::any::implementation::args::__name*>(__args)); \
        return hr_to_pvoid(S_OK); \
    } \
    catch (...) \
    { \
        HRESULT __hr = wil::ResultFromCaughtException(); \
        LOG_IF_FAILED(__hr); \
        return hr_to_pvoid(__hr); \
    } \

#define ENCLAVE_RESULT_WMESSAGE_SIZE 512

namespace veil
{
    namespace implementation
    {
        enum class export_ordinals : uint32_t
        {
            register_callbacks = 1,
            retrieve_enclave_error_for_thread,
            taskpool_run_task,
        };

        using callback_t = void* (*)(void*);

        enum class callback_id : uint32_t
        {
            malloc,
            free,
            printf,
            wprintf,
            taskpool_make,
            taskpool_delete,
            taskpool_schedule_task,
            taskpool_cancel_queued_tasks,
            hellokeys_create_or_open_hello_key,
            hellokeys_close_handle_vtl1_ncrypt_key,
            hellokeys_get_challenge,
            hellokeys_send_attestation_report,
            hellokeys_finalize_key,
            hellokeys_send_ngc_request,
            add_log,
            __count__ // keep as last entry
        };

        // Total number of callbacks
        constexpr size_t callback_id_count = static_cast<size_t>(callback_id::__count__);
    }

    struct enclave_error
    {
        HRESULT hr{};
        int lineNumber{};
        DWORD threadId{};
        wchar_t wmessage[ENCLAVE_RESULT_WMESSAGE_SIZE]{};
    };

    template <typename T>
    struct enclave_arguments_with_hr
    {
        enclave_error error;
        T data{};
    };

#pragma warning(push)
#pragma warning(disable : 4324)
    template <typename T>
    struct enclave_ordinal_call_wrapping
    {
        UINT32 ordinal;
        alignas(64) enclave_arguments_with_hr<T> argumentsWithHr;
    };

    struct enclave_ordinal_call_unwrapping
    {
        UINT32 ordinal;
        alignas(64) void* argumentsWithHr;
    };
#pragma warning(pop)
}
