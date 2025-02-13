// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <VbsEnclave\Enclave\Implementations.h>
#include "..\TestHostApp\TestHelpers.h"

using namespace VbsEnclave;

template <typename T>
HRESULT VerifyNumericArray(T* data, size_t size)
{
    RETURN_HR_IF_NULL(E_INVALIDARG, data);
    for (T i = 0; i < size; ++i)
    {
        RETURN_HR_IF(E_INVALIDARG, data[i] != i);
    }

    return S_OK;
}
template <typename T>
HRESULT VerifyContainsSameValuesArray(T* data, size_t size, T value)
{
    RETURN_HR_IF_NULL(E_INVALIDARG, data);
    for (size_t i = 0; i < size; ++i)
    {
        RETURN_HR_IF(E_INVALIDARG, data[i] != value);
    }

    return S_OK;
}

#pragma region VTL1 Enclave developer implementation functions

Int8PtrAndSize VTL1_Declarations::ReturnInt8ValPtr_From_Enclave()
{
    auto int8s = CreateVector<std::int8_t>(c_data_size);
    size_t size_for_int8s = sizeof(std::int8_t) * c_data_size;
    Int8PtrAndSize ret_vtl1 {};
    THROW_IF_FAILED(AllocateVtl0Memory(&ret_vtl1.int8_val, size_for_int8s));
    vtl0_memory_ptr<std::int8_t> mem_ptr (ret_vtl1.int8_val);
    THROW_IF_FAILED(EnclaveCopyOutOfEnclave(ret_vtl1.int8_val, int8s.data(), size_for_int8s));
    ret_vtl1.size_field = size_for_int8s;
    mem_ptr.release();
    return ret_vtl1;
}

std::uint64_t VTL1_Declarations::ReturnUint64Val_From_Enclave()
{
    return std::numeric_limits<std::uint64_t>::max();
}

StructWithNoPointers VTL1_Declarations::ReturnStructWithValues_From_Enclave()
{
    return CreateStructWithNoPointers();
}

HRESULT VTL1_Declarations::TestPassingPrimitivesAsValues_To_Enclave(
    _In_ const bool& bool_val, 
    _In_ const DecimalEnum& enum_val, 
    _In_ const std::int8_t& int8_val)
{
    RETURN_HR_IF(E_INVALIDARG, bool_val != true);
    RETURN_HR_IF(E_INVALIDARG, enum_val != DecimalEnum::Deci_val2);
    RETURN_HR_IF(E_INVALIDARG, int8_val != std::numeric_limits<std::int8_t>::max());

    return S_OK;
}

HRESULT VTL1_Declarations::TestPassingPrimitivesAsInPointers_To_Enclave(
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

HRESULT VTL1_Declarations::TestPassingPrimitivesAsInOutPointers_To_Enclave(
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
HRESULT VTL1_Declarations::TestPassingPrimitivesAsOutPointers_To_Enclave(
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
StructWithNoPointers VTL1_Declarations::ComplexPassingofTypes_To_Enclave(
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

#pragma region Enclave to HostApp Tests

// For testing vtl0 callbacks we use HRESULTS as our success/failure metrics since we can't use TAEF in the
// enclave.

HRESULT VTL1_Declarations::Start_TestPassingPrimitivesAsInPointers_To_HostApp_Callback_Test()
{
    std::uint8_t uint8_val[c_arbitrary_size_1];
    std::copy(c_uint8_array.begin(), c_uint8_array.end(), uint8_val);
    std::uint16_t uint16_val[c_arbitrary_size_2];
    std::copy(c_uint16_array.begin(), c_uint16_array.end(), uint16_val);
    std::uint32_t uint32_val[c_arbitrary_size_1];
    std::copy(c_uint32_array.begin(), c_uint32_array.end(), uint32_val);
    RETURN_IF_FAILED(VTL0_Callbacks::TestPassingPrimitivesAsInPointers_To_HostApp_callback(
        uint8_val,
        uint16_val,
        uint32_val,
        c_arbitrary_size_1,
        c_arbitrary_size_2));

    return S_OK;
}
HRESULT VTL1_Declarations::Start_TestPassingPrimitivesAsValues_To_HostApp_Callback_Test()
{
    RETURN_IF_FAILED(VTL0_Callbacks::TestPassingPrimitivesAsValues_To_HostApp_callback(
        true,
        DecimalEnum::Deci_val2,
        std::numeric_limits<std::int8_t>::max()));

    return S_OK;
}
HRESULT VTL1_Declarations::Start_TestPassingPrimitivesAsInOutPointers_To_HostApp_Callback_Test()
{
    std::int8_t int8_val[c_arbitrary_size_1];
    std::copy(c_int8_array.begin(), c_int8_array.end(), int8_val);
    std::int16_t int16_val[c_arbitrary_size_2];
    std::copy(c_int16_array.begin(), c_int16_array.end(), int16_val);
    std::int32_t int32_val[c_arbitrary_size_1];
    std::copy(c_int32_array.begin(), c_int32_array.end(), int32_val);

    RETURN_IF_FAILED(VTL0_Callbacks::TestPassingPrimitivesAsInOutPointers_To_HostApp_callback(
        int8_val,
        int16_val,
        int32_val,
        c_arbitrary_size_1,
        c_arbitrary_size_2));

    RETURN_IF_FAILED(VerifyNumericArray(int8_val, c_arbitrary_size_1));
    RETURN_IF_FAILED(VerifyNumericArray(int16_val, c_arbitrary_size_2));
    RETURN_IF_FAILED(VerifyNumericArray(int32_val, c_arbitrary_size_1));

    return S_OK;
}
HRESULT VTL1_Declarations::Start_TestPassingPrimitivesAsOutPointers_To_HostApp_Callback_Test()
{
    // TODO: once flatbuffers are implemented: Out parameters will rely on flatbuffer serializing
    // and deserializing the data and recreating it on the other side.

    return S_OK;
}
HRESULT VTL1_Declarations::Start_ReturnInt8ValPtr_From_HostApp_Callback_Test()
{
    Int8PtrAndSize result = VTL0_Callbacks::ReturnInt8ValPtr_From_HostApp_callback();
    RETURN_HR_IF_NULL(E_INVALIDARG, result.int8_val);
    RETURN_HR_IF(E_INVALIDARG, result.size_field != (sizeof(std::int8_t) * c_data_size));
    RETURN_IF_FAILED(VerifyNumericArray(result.int8_val, result.size_field));
    vtl0_memory_ptr<std::int8_t> int8_ptr (result.int8_val);

    return S_OK;
}
HRESULT VTL1_Declarations::Start_ReturnUint64Val_From_HostApp_Callback_Test()
{
    std::uint64_t result = VTL0_Callbacks::ReturnUint64Val_From_HostApp_callback();
    RETURN_HR_IF(E_INVALIDARG, result != std::numeric_limits<std::uint64_t>::max());

    return S_OK;
}
HRESULT VTL1_Declarations::Start_ReturnStructWithValues_From_HostApp_Callback_Test()
{
    StructWithNoPointers result = VTL0_Callbacks::ReturnStructWithValues_From_HostApp_callback();
    RETURN_HR_IF(E_INVALIDARG, !(CompareStructWithNoPointers(result, CreateStructWithNoPointers())));

    return S_OK;
}
HRESULT VTL1_Declarations::Start_ComplexPassingofTypes_To_HostApp_Callback_Test()
{
    // TODO: once flatbuffers are implemented: Out parameters will rely on flatbuffer serializing
    // and deserializing the data and recreating it on the other side.

    return S_OK;
}

#pragma endregion
