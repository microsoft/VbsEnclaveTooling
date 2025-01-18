#pragma once

#include <stdint.h>

#ifndef ENCLAVE_FUNCTION
#define ENCLAVE_FUNCTION extern "C" PVOID WINAPI
#endif

#define HRESULT_TO_PVOID(hr) ((PVOID)((ULONG_PTR)(hr) & 0x00000000FFFFFFFF))
#define PVOID_TO_HRESULT(p) ((HRESULT)((ULONG_PTR)(p) & 0x00000000FFFFFFFF))

#define RETURN_HR_AS_PVOID(x) return veil::hr_to_pvoid(x);
#define RETURN_PVOID_AS_HR(x) return veil::pvoid_to_hr(x);

namespace veil
{
    inline constexpr HRESULT pvoid_to_hr(void* ptr)
    {
#pragma warning(push)
#pragma warning(disable: 4302)
#pragma warning(push)
#pragma warning(disable: 4311)
        return PVOID_TO_HRESULT(ptr);
#pragma warning(pop)
#pragma warning(pop)
    }

    inline constexpr void* hr_to_pvoid(HRESULT hr)
    {
#pragma warning(push)
#pragma warning(disable: 4312)
        return HRESULT_TO_PVOID(hr);
#pragma warning(pop)
    }
}

#define VEIL_ABI_FUNCTION(__name, __args, __funcbody) \
    void* __name(void* __args) \
    try \
    { \
        HRESULT __hr = ([&]() \
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

#define ENCLAVE_RESULT_WMESSAGE_SIZE 512

namespace veil
{
    namespace implementation
    {
        enum class export_ordinals : uint32_t
        {
            retrieve_enclave_error_for_thread = 100,
            register_callbacks,
            threadpool_run_task,
        };

        using callback_t = void* (*)(void*);

        enum class callback_id : uint32_t
        {
            malloc,
            printf,
            wprintf,
            get_per_thread_buffer,
            threadpool_make,
            threadpool_delete,
            threadpool_schedule_task,
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
        T data{};
        enclave_error error;
        void* crumb{};
        UINT32 crumb2{};
    };

    //
    // todo: fix alignment
    //
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


namespace veil::any::implementation
{
    // threadpool
    struct threadpool_task_handle
    {
        void* threadpool_instance;
        UINT64 task_handle;
    };
}

