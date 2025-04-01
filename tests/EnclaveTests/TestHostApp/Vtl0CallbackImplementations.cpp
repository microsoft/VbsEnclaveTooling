// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <windows.h> 
#include <enclaveapi.h>
#include <wil\result_macros.h>
#include <wil\resource.h>
#include "TestHelpers.h"

#include <VbsEnclave\HostApp\Stubs.h>

using namespace VbsEnclave::VTL0_Stubs;

// Note about tests, we return Hresults for some of the tests just as an extra test
// to confirm the abi handles returning them properly. However we throw in those
// tests so we can identify where the error occured faster.

#pragma region VTL0 (HostApp) Callback implementations

Int8PtrAndSize TestEnclave::ReturnInt8ValPtr_From_HostApp_callback()
{
    Int8PtrAndSize ret {};
    ret.int8_val = std::make_shared<std::int8_t>();
    *ret.int8_val = std::numeric_limits<std::int8_t>::max();

    return ret;
}

std::uint64_t TestEnclave::ReturnUint64Val_From_HostApp_callback()
{
    return std::numeric_limits<std::uint64_t>::max();
}

StructWithNoPointers TestEnclave::ReturnStructWithValues_From_HostApp_callback()
{
    return CreateStructWithNoPointers();
}

HRESULT TestEnclave::TestPassingPrimitivesAsValues_To_HostApp_callback(
    _In_ const bool bool_val,
    _In_ const DecimalEnum enum_val,
    _In_ const std::int8_t int8_val)
{
    // Confirm vtl1 parameters were correctly copied to vtl0 memory.
    THROW_HR_IF(E_INVALIDARG, bool_val != true);
    THROW_HR_IF(E_INVALIDARG, enum_val != DecimalEnum::Deci_val2);
    THROW_HR_IF(E_INVALIDARG, int8_val != std::numeric_limits<std::int8_t>::max());

    return S_OK;
}

HRESULT TestEnclave::TestPassingPrimitivesAsInPointers_To_HostApp_callback(
    _In_ const std::uint8_t* uint8_val,
    _In_ const std::uint16_t* uint16_val,
    _In_ const std::uint32_t* uint32_val)
{
    // Confirm vtl1 parameters were correctly copied to vtl0 memory.
    THROW_IF_NULL_ALLOC(uint8_val);
    THROW_IF_NULL_ALLOC(uint16_val);
    THROW_IF_NULL_ALLOC(uint32_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *uint8_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *uint16_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *uint32_val);

    return S_OK;
}

HRESULT TestEnclave::TestPassingPrimitivesAsInOutPointers_To_HostApp_callback(
    _Inout_ std::int8_t* int8_val,
    _Inout_ std::int16_t* int16_val,
    _Inout_ std::int32_t* int32_val)
{
    // Confirm vtl1 parameters were correctly copied to vtl0 memory.
    THROW_IF_NULL_ALLOC(int8_val);
    THROW_IF_NULL_ALLOC(int16_val);
    THROW_IF_NULL_ALLOC(int32_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *int8_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *int16_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *int32_val);

    // Copy data into the in-out buffers. Abi will copy these into vtl01 memory and return
    // them to caller.
    *int8_val = std::numeric_limits<std::int8_t>::max();
    *int16_val = std::numeric_limits<std::int16_t>::max();
    *int32_val = std::numeric_limits<std::int32_t>::max();

    return S_OK;
}

HRESULT TestEnclave::TestPassingPrimitivesAsOutPointers_To_HostApp_callback(
    _Out_ std::shared_ptr<bool>& bool_val,
    _Out_ std::shared_ptr<DecimalEnum>& enum_val,
    _Out_ std::shared_ptr<std::uint64_t>& uint64_val)
{
    bool_val = nullptr;
    enum_val = nullptr;
    uint64_val = nullptr;

    bool_val = std::make_shared<bool>(true);
    enum_val = std::make_shared<DecimalEnum>(DecimalEnum::Deci_val3);
    uint64_val = std::make_shared<std::uint64_t>(std::numeric_limits<std::uint64_t>::max());

    return S_OK;
}

StructWithNoPointers TestEnclave::ComplexPassingofTypes_To_HostApp_callback(
    _In_ const StructWithNoPointers& arg1,
    _Inout_ StructWithNoPointers& arg2,
    _Out_ std::shared_ptr<StructWithNoPointers>& arg3,
    _Out_ StructWithNoPointers& arg4,
    _Out_ std::shared_ptr<std::uint64_t>& uint64_val)
{
    arg3 = nullptr;
    uint64_val = nullptr;
    auto struct_to_return = CreateStructWithNoPointers();

    // check in parm is expected value
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithNoPointers(arg1, struct_to_return));
    arg2 = struct_to_return;

    arg3 = std::make_shared<StructWithNoPointers>();
    *arg3 = CreateStructWithNoPointers();
    arg4 = CreateStructWithNoPointers();
    uint64_val = std::make_shared<std::uint64_t>(std::numeric_limits<std::uint64_t>::max());

    return struct_to_return;
}

void TestEnclave::ReturnNoParams_From_HostApp_callback()
{
    // No body, test just here to make sure we have coverage for void returns
}

#pragma endregion
