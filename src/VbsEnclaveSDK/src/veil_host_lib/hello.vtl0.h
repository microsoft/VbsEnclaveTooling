// Copyright (c) Microsoft Corporation.  
// Licensed under the MIT License.  

#pragma once  
#include <string>
 
namespace veil::vtl0::implementation::callins
{
    void enclave_load_user_bound_key(_In_ void* enclave, _In_ std::wstring keyName, _In_ std::wstring flags, _In_ std::wstring cache);
}

/*
namespace veil::vtl0::implementation
{
    namespace hello
    {
        inline void enclave_load_user_bound_key(void* enclave, std::wstring keyName, std::wstring flags, std::wstring cache)
        {
            veil::vtl0::implementation::callins::enclave_load_user_bound_key(enclave, keyName, flags, cache);
        }
    }
}
*/
