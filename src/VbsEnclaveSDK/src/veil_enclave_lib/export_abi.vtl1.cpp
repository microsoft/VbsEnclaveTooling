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
            struct threadpool_run_task_t {};

            template <typename T>
            struct atype;

            template <>
            struct atype<threadpool_run_task_t>
            {
                using args = veil::any::implementation::args::threadpool_run_task;
                static HRESULT func(_Inout_ args* a) { return veil::vtl1::implementation::exports::threadpool_run_task(a);
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

        //
        // Framework exports
        //

        ENCLAVE_FUNCTION register_callbacks(_In_ PVOID params)
        {
            auto eawh = static_cast<enclave_arguments_with_hr<veil::any::implementation::args::register_callbacks>*>(params);
            auto errorPopulator = veil::vtl1::implementation::export_helpers::enclave_error_populator(eawh->error);

            RETURN_HR_AS_PVOID(veil::vtl1::implementation::exports::register_callbacks(&eawh->data));
        }

        ENCLAVE_FUNCTION retrieve_enclave_error_for_thread(_In_ PVOID params)
        {
            auto eawh = static_cast<enclave_arguments_with_hr<veil::any::implementation::args::retrieve_enclave_error_for_thread>*>(params);
            auto errorPopulator = veil::vtl1::implementation::export_helpers::enclave_error_populator(eawh->error);

            RETURN_HR_AS_PVOID(veil::vtl1::implementation::exports::retrieve_enclave_error_for_thread(&eawh->data));
        }

        ENCLAVE_FUNCTION threadpool_run_task(_In_ PVOID params)
        {
            auto eawh = static_cast<enclave_arguments_with_hr<veil::any::implementation::args::threadpool_run_task>*>(params);
            auto errorPopulator = veil::vtl1::implementation::export_helpers::enclave_error_populator(eawh->error);

            RETURN_HR_AS_PVOID(veil::vtl1::implementation::exports::threadpool_run_task(&eawh->data));
        }

    }
}

namespace veil::vtl1
{
    namespace enclave_interface
    {
        namespace details
        {
#define ENCLAVE_SDK_EXPORT_ORDINAL(_name, _ordinal) \
    if (_x->ordinal == _ordinal) { return veil::vtl1::implementation:: ## _name(&_x->argumentsWithHr); }

#define ENCLAVE_SDK_EXPORT_ORDINAL_TRAITS(_name, _ordinal) \
    if (_x->ordinal == _ordinal) { return veil::vtl1::implementation::CallImplementation<veil::vtl1::implementation::traits:: ## _name ## _t>(&_x->argumentsWithHr); }

            PVOID call_by_ordinal(_In_ PVOID ordinalStruct)
            {
                auto _x = reinterpret_cast<enclave_ordinal_call_unwrapping*>(ordinalStruct);
                uint32_t i = 100;
                ENCLAVE_SDK_EXPORT_ORDINAL(register_callbacks, i++);
                ENCLAVE_SDK_EXPORT_ORDINAL(retrieve_enclave_error_for_thread, i++);
                ENCLAVE_SDK_EXPORT_ORDINAL(threadpool_run_task, i++);
                RETURN_HR_AS_PVOID(HRESULT_FROM_WIN32(ERROR_INVALID_FUNCTION));
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
