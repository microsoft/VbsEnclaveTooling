// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <windows.h> 
#include <enclaveapi.h>
#include <wil\result_macros.h>
#include <wil\resource.h>
#include "TestHelpers.h"

#include <VbsEnclave\HostApp\Stubs.h>

using namespace VbsEnclave::VTL0_Stubs;

#pragma region VTL0 (HostApp) Callback implementations

Int8PtrAndSize TestEnclave::ReturnInt8ValPtr_From_HostApp_callback()
{
    auto int8s = CreateVector<std::int8_t>(c_data_size);
    size_t size_for_int8s = sizeof(std::int8_t) * c_data_size;
    Int8PtrAndSize ret {};
    ret.int8_val = reinterpret_cast<std::int8_t*>(AllocateMemory(size_for_int8s));
    memcpy(ret.int8_val, int8s.data(), size_for_int8s);
    ret.size_field = size_for_int8s;

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
    _In_ const bool& bool_val,
    _In_ const DecimalEnum& enum_val,
    _In_ const std::int8_t& int8_val)
{
    RETURN_HR_IF(E_INVALIDARG, bool_val != true);
    RETURN_HR_IF(E_INVALIDARG, enum_val != DecimalEnum::Deci_val2);
    RETURN_HR_IF(E_INVALIDARG, int8_val != std::numeric_limits<std::int8_t>::max());

    return S_OK;
}

HRESULT TestEnclave::TestPassingPrimitivesAsInPointers_To_HostApp_callback(
    _In_ const std::uint8_t* uint8_val,
    _In_ const std::uint16_t* uint16_val,
    _In_ const std::uint32_t* uint32_val,
    _In_ const size_t& abitrary_size_1,
    _In_ const size_t& abitrary_size_2)
{
    RETURN_IF_FAILED(CompareArrays(uint8_val, c_uint8_array.data(), c_uint8_array.size()));
    RETURN_IF_FAILED(CompareArrays(uint16_val, c_uint16_array.data(), c_uint16_array.size()));
    RETURN_IF_FAILED(CompareArrays(uint32_val, c_uint32_array.data(), c_uint32_array.size()));
    RETURN_HR_IF(E_INVALIDARG, abitrary_size_1 != c_arbitrary_size_1);
    RETURN_HR_IF(E_INVALIDARG, abitrary_size_2 != c_arbitrary_size_2);

    return S_OK;
}

HRESULT TestEnclave::TestPassingPrimitivesAsInOutPointers_To_HostApp_callback(
    _Inout_ std::int8_t* int8_val,
    _Inout_ std::int16_t* int16_val,
    _Inout_ std::int32_t* int32_val,
    _In_ const size_t& abitrary_size_1,
    _In_ const size_t& abitrary_size_2)
{
    RETURN_IF_FAILED(CompareArrays(int8_val, c_int8_array.data(), c_int8_array.size()));
    RETURN_IF_FAILED(CompareArrays(int16_val, c_int16_array.data(), c_int16_array.size()));
    RETURN_IF_FAILED(CompareArrays(int32_val, c_int32_array.data(), c_int32_array.size()));
    RETURN_HR_IF(E_INVALIDARG, abitrary_size_1 != c_arbitrary_size_1);
    RETURN_HR_IF(E_INVALIDARG, abitrary_size_2 != c_arbitrary_size_2);

    auto int8_data = CreateVector<std::int8_t>(abitrary_size_1);
    memcpy(int8_val, int8_data.data(), int8_data.size() * sizeof(std::int8_t));

    auto int16_data = CreateVector<std::int16_t>(abitrary_size_2);
    memcpy(int16_val, int16_data.data(), int16_data.size() * sizeof(std::int16_t));

    auto int32_data = CreateVector<std::int32_t>(abitrary_size_1);
    memcpy(int32_val, int32_data.data(), int32_data.size() * sizeof(std::int32_t));

    return S_OK;
}

// Function creates heap memory but does not free it since it needs to be used by the caller
// in the abi who will then copy it without freeing it.
// TODO: for developer facing functions where they need to return memory via return value/InOut/Out param
// generate the function to use smart pointers for these parameters via the codegen.
HRESULT TestEnclave::TestPassingPrimitivesAsOutPointers_To_HostApp_callback(
    _Out_ bool** bool_val,
    _Out_ DecimalEnum** enum_val,
    _Out_ std::uint64_t** uint64_val,
    _In_ const size_t& abitrary_size_1,
    _In_ const size_t& abitrary_size_2)
{
    auto bool_data = CreateBoolReturnPtr(abitrary_size_1);
    size_t size_for_bools = sizeof(bool) * abitrary_size_1;

    *bool_val = reinterpret_cast<bool*>(AllocateMemory(size_for_bools));
    memcpy(*bool_val, bool_data.get(), size_for_bools);

    auto enums = CreateVector<DecimalEnum>(abitrary_size_2);
    size_t size_for_enums = sizeof(DecimalEnum) * abitrary_size_2;

    *enum_val = reinterpret_cast<DecimalEnum*>(AllocateMemory(size_for_enums));
    memcpy(*enum_val, enums.data(), size_for_enums);

    auto uint64s = CreateVector<std::uint64_t>(abitrary_size_1);
    size_t size_for_uint64s = sizeof(std::uint64_t) * abitrary_size_1;

    *uint64_val = reinterpret_cast<std::uint64_t*>(AllocateMemory(size_for_uint64s));
    memcpy(*uint64_val, uint64s.data(), size_for_uint64s);
    return S_OK;
}

// Function creates heap memory but does not free it since it needs to be used by the caller
// in the abi who will then copy it without freeing it.
// TODO: for developer facing functions where they need to return memory via return value/InOut/Out param
// generate the function to use smart pointers for these parameters via the codegen.
StructWithNoPointers TestEnclave::ComplexPassingofTypes_To_HostApp_callback(
    _In_ const StructWithNoPointers& arg1,
    _Inout_ StructWithNoPointers& arg2,
    _Out_ StructWithNoPointers** arg3,
    _Out_ StructWithNoPointers& arg4,
    _Out_ std::uint64_t** uint64_val,
    _In_ const size_t& abitrary_size_1)
{
    auto struct_to_return = CreateStructWithNoPointers();
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithNoPointers(arg1, struct_to_return));
    arg2 = struct_to_return;

    *arg3 = reinterpret_cast<StructWithNoPointers*>(AllocateMemory(sizeof(StructWithNoPointers)));
    memcpy(*arg3, &struct_to_return, sizeof(StructWithNoPointers));

    memcpy(&arg4, &struct_to_return, sizeof(StructWithNoPointers));

    std::uint64_t uint64_max = std::numeric_limits<std::uint64_t>::max();

    *uint64_val = reinterpret_cast<std::uint64_t*>(AllocateMemory(abitrary_size_1));
    memcpy(*uint64_val, &uint64_max, abitrary_size_1);

    return struct_to_return;
}

#pragma endregion
