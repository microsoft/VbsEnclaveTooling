// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "BaseHeader.h"
#include <VbsEnclaveGenerated\Enclave\VTL1_Implementations.h>

using namespace VbsEnclaveGenerated_CodeGenTestFunctions::Enclave::VTL1_Implementations;

// Place Holder definitions for function declarations.
// TODO: AS vtl1 -> vtl0 codegen is completed these functions should
// should return an actual value/manipulate out/inout params respectively.
std::uint64_t* DeveloperDeclarations::RetChar()
{
    return {};
}

void DeveloperDeclarations::TrustedWithBasicTypes(
    _In_ char arg1,
    _In_ wchar_t arg2,
    _Inout_ float arg3,
    _Out_ double** arg4,
    _In_ size_t arg5,
    _In_ std::int8_t arg6,
    _In_ std::int16_t arg7,
    _In_ std::int32_t arg8,
    _In_ std::int64_t arg9,
    _In_ std::uint8_t arg10,
    _In_ std::uint16_t arg11,
    _In_ std::uint32_t arg12,
    _In_ std::uint64_t arg13)
{

    return;
}

MyStruct1* DeveloperDeclarations::TrustedGetStruct1(_In_ MyStruct1 arg1,
    _In_ std::array<MyStruct1, 5> arg2,
    _Inout_ MyStruct1* arg3,
    _Out_ MyStruct1** arg4)
{
    return {};
}

void DeveloperDeclarations::ArrayChar(_In_ std::array<char, 2> arg1,
    _Inout_ std::array<std::array<char, 2>, 2> arg2,
    _Out_ std::array<char, 3>** arg3)
{
    return;
}
