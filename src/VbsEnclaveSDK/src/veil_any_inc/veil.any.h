#pragma once

#include <stdint.h>

#ifndef ENCLAVE_FUNCTION
#define ENCLAVE_FUNCTION extern "C" PVOID WINAPI
#endif

#define RETURN_HR_AS_PVOID(x) return (hr_to_pvoid(x));

#define HRESULT_TO_PVOID(hr) (PVOID)((ULONG_PTR)(hr) & 0x00000000FFFFFFFF)

#ifndef RETURN_HR_AS_PVOID
#define RETURN_HR_AS_PVOID(hr) return HRESULT_TO_PVOID(hr);
#endif
#define PVOID_TO_HRESULT(p) ((HRESULT)((ULONG_PTR)(p) & 0x00000000FFFFFFFF))
#define RETURN_PVOID_AS_HR(p) return PVOID_TO_HRESULT(p);

#define NCRYPT_NGC_SESSION_CHALLENGE_PROPERTY L"NgcSessionChallenge"
#define NCRYPT_NGC_CLIENT_ATTESTATION_PROPERTY L"NgcClientAttestation"
#define NCRYPT_NGC_CONTAINER_SECURE_ID_PROPERTY L"NgcContainerSecureId"
#define NCRYPT_NGC_IS_SECURE_ID_OWNER_ID_PROPERTY L"NgcIsSecureIdOwnerId"

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


//
// Enclave complex HRESULT return type
//
#define ENCLAVE_RESULT_WMESSAGE_SIZE 512





//#define veil_EXPORT(name, ordinal) \


//veil_EXPORT_ORDINAL(StartHelloSession, 8);

enum class export_ordinals : uint32_t
{
    StartHelloSession = 101,
    GenerateEncryptionKeySecuredByHello,
    LoadEncryptionKeySecuredByHello,
    ExportKey,
    GetPackagedEnclaveIdentityProofChallenge,
    CreateAttestationReport,
    ValidatePackagedEnclaveIdentityProof,
    retrieve_enclave_error_for_thread,
    RegisterCallbacks,
    EnclaveImplementationFramework_Vtl1_Threadpool_RunTask,
};

namespace veil
{
    using callback_t = void*(*)(void*);

    enum class callback_id : uint32_t
    {
        malloc,
        printf,
        wprintf,
        get_per_thread_buffer,
        threadpool_make,
        threadpool_delete,
        threadpool_schedule_task,
        COUNT // keep as last entry
    };

    // Total number of callbacks
    constexpr size_t CALLBACK_COUNT = static_cast<size_t>(callback_id::COUNT);

    namespace vtl0::implementation::callbacks
    {
        extern callback_t callback_addresses[CALLBACK_COUNT];
    }
}




namespace veil
{
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
    // todo:jw fix alignment
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

