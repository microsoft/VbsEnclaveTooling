// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include "export_helpers.vtl1.h"
#include "exports.vtl1.h"

#include "veil.any.h"
#include "veil_arguments.any.h"

namespace veil::vtl1
{
    namespace implementation
    {
        //
        // Framework exports
        //

        ENCLAVE_FUNCTION register_callbacks(_In_ PVOID params) noexcept
        {
            auto argsWithHr = reinterpret_cast<enclave_arguments_with_hr<veil::any::implementation::args::register_callbacks>*>(params);
            auto errorPopulator = veil::vtl1::implementation::export_helpers::enclave_error_populator(argsWithHr->error);

            RETURN_HR_AS_PVOID(veil::vtl1::implementation::exports::register_callbacks(&argsWithHr->data));
        }

        ENCLAVE_FUNCTION retrieve_enclave_error_for_thread(_In_ PVOID params) noexcept
        {
            auto argsWithHr = reinterpret_cast<enclave_arguments_with_hr<veil::any::implementation::args::retrieve_enclave_error_for_thread>*>(params);
            auto errorPopulator = veil::vtl1::implementation::export_helpers::enclave_error_populator(argsWithHr->error);

            RETURN_HR_AS_PVOID(veil::vtl1::implementation::exports::retrieve_enclave_error_for_thread(&argsWithHr->data));
        }

    }
}

#define ENCLAVE_SDK_EXPORT_ORDINAL(_x, _name, _ordinal) \
    if (_x->ordinal == _ordinal) { return veil::vtl1::implementation:: ## _name(&_x->argumentsWithHr); }

namespace veil::vtl1
{
    namespace enclave_interface
    {
        namespace details
        {
            PVOID call_by_ordinal(_In_ PVOID ordinalStruct) noexcept
            {
                auto x = reinterpret_cast<enclave_ordinal_call_unwrapping*>(ordinalStruct);
                uint32_t i = 1;
                ENCLAVE_SDK_EXPORT_ORDINAL(x, register_callbacks, i++);
                ENCLAVE_SDK_EXPORT_ORDINAL(x, retrieve_enclave_error_for_thread, i++);
                RETURN_HR_AS_PVOID(HRESULT_FROM_WIN32(ERROR_INVALID_FUNCTION));
            }
        }

        namespace exports
        {
            PVOID call_by_ordinal(_In_ PVOID params) noexcept
            {
                return veil::vtl1::enclave_interface::details::call_by_ordinal(params);
            }
        }
    }
}

// The "call funnel" export for all veil calls to pass through - user app enclave must export this in .def file!
extern "C" PVOID __declspec(dllexport) WINAPI VeilEnclaveSdkEntrypoint(_In_ PVOID params) noexcept
{
    // Forward the call to the framework
    return veil::vtl1::enclave_interface::exports::call_by_ordinal(params);
}
