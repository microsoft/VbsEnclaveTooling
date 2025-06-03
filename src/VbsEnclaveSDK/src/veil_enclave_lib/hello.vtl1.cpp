// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#define VEIL_IMPLEMENTATION

#include <string>

#include <VbsEnclave\Enclave\Implementations.h>
#include "hello.vtl1.h"

// call ins
namespace veil_abi
{
    namespace VTL1_Declarations
    {
        void enclave_load_user_bound_key(_In_ std::wstring keyName, _In_ std::wstring flags, _In_ std::wstring cache)
        {
            /*
            NewClass::GetChallengeCallback();

            NewClass::CreateRecallKeyCallback(std::async a, std::promise p2, std::future f3);

            NewClass::StorageCallback(sealEnc, pubECDH);
            */
        }
    }
}


