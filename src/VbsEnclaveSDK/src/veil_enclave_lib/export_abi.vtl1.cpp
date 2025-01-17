// © Microsoft Corporation. All rights reserved.

#include "pch.h"

#include "export_helpers.vtl1.h"
#include "exports.vtl1.h"
#include "threadpool.vtl1.h"

#include "veil.any.h"
#include "veil_arguments.any.h"

// todo:revisit

namespace veil::vtl1
{
    namespace implementation
    {
        // Traits
        namespace traits
        {
            struct StartHelloSessionT {};

            template <typename T>
            struct atype;

            template <>
            struct atype<StartHelloSessionT>
            {
                using args = veil::any::implementation::args::StartHelloSession;
                static HRESULT func(_Inout_ args* a) { return veil::vtl1::implementation::exports::StartHelloSession(a);
                }
            };
        }

        template <typename T>
        void* CallImplementation(_In_ void* params)
        {
            auto eawh = static_cast<enclave_arguments_with_hr<typename veil::vtl1::implementation::traits::atype<T>::args>*>(params);
            auto errorPopulator = veil::vtl1::implementation::export_helpers::enclave_error_populator(eawh->error);
            RETURN_HR_AS_PVOID(veil::vtl1::implementation::traits::atype<T>::func(&eawh->data));
        }

        ENCLAVE_FUNCTION StartHelloSession(_In_ PVOID params)
        {
            auto eawh = static_cast<enclave_arguments_with_hr<veil::any::implementation::args::StartHelloSession>*>(params);
            auto errorPopulator = veil::vtl1::implementation::export_helpers::enclave_error_populator(eawh->error);
            //eawh->crumb = & eawh->data.challengeByteCount;

            eawh->crumb = &eawh->data;
            eawh->crumb = &(eawh->data.challengeByteCount);
            eawh->crumb2 = (eawh->data.challengeByteCount);

            RETURN_HR_AS_PVOID(veil::vtl1::implementation::exports::StartHelloSession(&eawh->data));
        }

        ENCLAVE_FUNCTION GenerateEncryptionKeySecuredByHello(_In_ PVOID params)
        {
            auto eawh = static_cast<enclave_arguments_with_hr<veil::any::implementation::args::GenerateEncryptionKeySecuredByHello>*>(params);
            auto errorPopulator = veil::vtl1::implementation::export_helpers::enclave_error_populator(eawh->error);

            RETURN_HR_AS_PVOID(veil::vtl1::implementation::exports::GenerateEncryptionKeySecuredByHello(static_cast<veil::any::implementation::args::GenerateEncryptionKeySecuredByHello*>(params)));
        }

        ENCLAVE_FUNCTION LoadEncryptionKeySecuredByHello(_In_ PVOID params)
        {
            auto eawh = static_cast<enclave_arguments_with_hr<veil::any::implementation::args::LoadEncryptionKeySecuredByHello>*>(params);
            auto errorPopulator = veil::vtl1::implementation::export_helpers::enclave_error_populator(eawh->error);

            RETURN_HR_AS_PVOID(veil::vtl1::implementation::exports::LoadEncryptionKeySecuredByHello(&eawh->data));
        }

        ENCLAVE_FUNCTION ExportKey(_In_ PVOID params)
        {
            auto eawh = static_cast<enclave_arguments_with_hr<veil::any::implementation::args::ExportKey>*>(params);
            auto errorPopulator = veil::vtl1::implementation::export_helpers::enclave_error_populator(eawh->error);

            RETURN_HR_AS_PVOID(veil::vtl1::implementation::exports::ExportKey(&eawh->data));
        }

        ENCLAVE_FUNCTION GetPackagedEnclaveIdentityProofChallenge(_In_ PVOID params)
        {
            auto eawh = static_cast<enclave_arguments_with_hr<veil::any::implementation::args::GetPackagedEnclaveIdentityProofChallenge>*>(params);
            auto errorPopulator = veil::vtl1::implementation::export_helpers::enclave_error_populator(eawh->error);

            RETURN_HR_AS_PVOID(veil::vtl1::implementation::exports::GetPackagedEnclaveIdentityProofChallenge(&eawh->data));
        }

        ENCLAVE_FUNCTION CreateAttestationReport(_In_ PVOID params)
        {
            auto eawh = static_cast<enclave_arguments_with_hr<veil::any::implementation::args::CreateAttestationReport>*>(params);
            auto errorPopulator = veil::vtl1::implementation::export_helpers::enclave_error_populator(eawh->error);

            RETURN_HR_AS_PVOID(veil::vtl1::implementation::exports::CreateAttestationReport(&eawh->data));
        }

        ENCLAVE_FUNCTION ValidatePackagedEnclaveIdentityProof(_In_ PVOID params)
        {
            auto eawh = static_cast<enclave_arguments_with_hr<veil::any::implementation::args::ValidatePackagedEnclaveIdentityProof>*>(params);
            auto errorPopulator = veil::vtl1::implementation::export_helpers::enclave_error_populator(eawh->error);

            RETURN_HR_AS_PVOID(veil::vtl1::implementation::exports::ValidatePackagedEnclaveIdentityProof(&eawh->data));
        }

        PVOID retrieve_enclave_error_for_thread(_In_ PVOID params)
        {
            auto eawh = reinterpret_cast<enclave_arguments_with_hr<DWORD>*>(params);
            auto threadId = eawh->data;

            if (auto error = veil::vtl1::implementation::export_helpers::pop_back_thread_enclave_error(threadId))
            {
                veil::vtl1::implementation::export_helpers::copy_enclave_error(eawh->error, error.value());
            }
            RETURN_HR_AS_PVOID(S_OK);
        }

        ENCLAVE_FUNCTION RegisterCallbacks(_In_ PVOID params)
        {
            static int i = 0;
            if (i == 1)
                RETURN_HR_AS_PVOID(E_INVALIDARG);
            i++;
            auto eawh = static_cast<enclave_arguments_with_hr<veil::any::implementation::args::RegisterCallbacks>*>(params);
            auto errorPopulator = veil::vtl1::implementation::export_helpers::enclave_error_populator(eawh->error);

            RETURN_HR_AS_PVOID(veil::vtl1::implementation::exports::RegisterCallbacks(&eawh->data));
        }

        ENCLAVE_FUNCTION threadpool_run_task(_In_ PVOID params)
        {
            auto eawh = static_cast<enclave_arguments_with_hr<veil::any::implementation::args::threadpool_run_task>*>(params);
            auto errorPopulator = veil::vtl1::implementation::export_helpers::enclave_error_populator(eawh->error);

            RETURN_HR_AS_PVOID(veil::vtl1::implementation::call_ins::threadpool_run_task(&eawh->data));
        }

    }
}

namespace veil::vtl1
{
    namespace enclave_interface
    {
        namespace details
        {
    // todo:jw generify
#define ENCLAVE_SDK_EXPORT_ORDINAL(_name, _ordinal) \
    if (_x->ordinal == _ordinal) { return veil::vtl1::implementation:: ## _name(&_x->argumentsWithHr); }

#define ENCLAVE_SDK_EXPORT_ORDINAL_TRAITS(_name, _ordinal) \
    if (_x->ordinal == _ordinal) { return veil::vtl1::implementation::CallImplementation<veil::vtl1::implementation::traits:: ## _name ## T>(&_x->argumentsWithHr); }

            PVOID call_by_ordinal(_In_ PVOID ordinalStruct)
            {
                auto _x = reinterpret_cast<enclave_ordinal_call_unwrapping*>(ordinalStruct);
                uint32_t i = 101;
                //ENCLAVE_SDK_EXPORT_ORDINAL(StartHelloSession, i++);
                ENCLAVE_SDK_EXPORT_ORDINAL_TRAITS(StartHelloSession, i++);
                ENCLAVE_SDK_EXPORT_ORDINAL(GenerateEncryptionKeySecuredByHello, i++);
                ENCLAVE_SDK_EXPORT_ORDINAL(LoadEncryptionKeySecuredByHello, i++);
                ENCLAVE_SDK_EXPORT_ORDINAL(ExportKey, i++);
                ENCLAVE_SDK_EXPORT_ORDINAL(GetPackagedEnclaveIdentityProofChallenge, i++);
                ENCLAVE_SDK_EXPORT_ORDINAL(CreateAttestationReport, i++);
                ENCLAVE_SDK_EXPORT_ORDINAL(ValidatePackagedEnclaveIdentityProof, i++);
                ENCLAVE_SDK_EXPORT_ORDINAL(retrieve_enclave_error_for_thread, i++);
                ENCLAVE_SDK_EXPORT_ORDINAL(RegisterCallbacks, i++);
                //int x2 = 5;
                //if (x2 == 5)
                //RETURN_HR_AS_PVOID(E_APPLICATION_EXITING);
                ENCLAVE_SDK_EXPORT_ORDINAL(threadpool_run_task, i++);
                //RETURN_HR_AS_PVOID(E_HANDLE);
                RETURN_HR_AS_PVOID(E_INVALIDARG);
            }
        }

        namespace exports
        {
            PVOID call_by_ordinal(_In_ PVOID params)
            {
                return veil::vtl1::enclave_interface::details::call_by_ordinal(params);
            }
        }
    }
}

// The "call funnel" export for all veil calls to pass through - user app enclave must export this in .def file!
extern "C" PVOID __declspec(dllexport) WINAPI VeilEnclaveSdkEntrypoint(_In_ PVOID params)
{
    // Forward the call to the framework
    return veil::vtl1::enclave_interface::exports::call_by_ordinal(params);
}
