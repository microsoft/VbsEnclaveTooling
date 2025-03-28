// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <VbsEnclave\Enclave\Implementations.h>
#include "..\TestHostApp\TestHelpers.h"

using namespace VbsEnclave;

// Note about tests, we return Hresults for some of the tests just as an extra test
// to confirm the abi handles returning them properly. However we throw in those
// tests so we can identify where the error occured faster.

template <typename T>
HRESULT inline VerifyNumericArray(T* data, size_t size)
{
    THROW_HR_IF_NULL(E_INVALIDARG, data);
    for (T i = 0; i < size; ++i)
    {
        THROW_HR_IF(E_INVALIDARG, data[i] != i);
    }

    return S_OK;
}
template <typename T>
HRESULT inline VerifyContainsSameValuesArray(T* data, size_t size, T value)
{
    THROW_HR_IF_NULL(E_INVALIDARG, data);
    for (size_t i = 0; i < size; ++i)
    {
        THROW_HR_IF(E_INVALIDARG, data[i] != value);
    }

    return S_OK;
}

#pragma region VTL1 Enclave developer implementation functions

Int8PtrAndSize VTL1_Declarations::ReturnInt8ValPtr_From_Enclave()
{
    Int8PtrAndSize ret {};
    ret.int8_val = std::make_shared<std::int8_t>();
    *ret.int8_val = std::numeric_limits<std::int8_t>::max();

    return ret;
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
    _In_ const bool bool_val, 
    _In_ const DecimalEnum enum_val, 
    _In_ const std::int8_t int8_val)
{
    // Confirm vtl0 parameters were correctly copied to vtl1 memory.
    THROW_HR_IF(E_INVALIDARG, bool_val != true);
    THROW_HR_IF(E_INVALIDARG, enum_val != DecimalEnum::Deci_val2);
    THROW_HR_IF(E_INVALIDARG, int8_val != std::numeric_limits<std::int8_t>::max());

    return S_OK;
}

HRESULT VTL1_Declarations::TestPassingPrimitivesAsInPointers_To_Enclave(
    _In_ const std::uint8_t* uint8_val,
    _In_ const std::uint16_t* uint16_val,
    _In_ const std::uint32_t* uint32_val)
{
    // Confirm vtl0 parameters were correctly copied to vtl1 memory.
    THROW_HR_IF_NULL(E_INVALIDARG, uint8_val);
    THROW_HR_IF_NULL(E_INVALIDARG, uint16_val);
    THROW_HR_IF_NULL(E_INVALIDARG, uint32_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *uint8_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *uint16_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *uint32_val);

    return S_OK;
}

HRESULT VTL1_Declarations::TestPassingPrimitivesAsInOutPointers_To_Enclave(
    _Inout_ std::int8_t* int8_val,
    _Inout_ std::int16_t* int16_val,
    _Inout_ std::int32_t* int32_val)
{
    // Confirm vtl0 parameters were correctly copied to vtl1 memory.
    THROW_HR_IF_NULL(E_INVALIDARG, int8_val);
    THROW_HR_IF_NULL(E_INVALIDARG, int16_val);
    THROW_HR_IF_NULL(E_INVALIDARG, int32_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *int8_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *int16_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *int32_val);

    // Copy data into the in-out buffers. Abi will copy these into vtl0 memory and return
    // them to caller.
    *int8_val = std::numeric_limits<std::int8_t>::max();
    *int16_val = std::numeric_limits<std::int16_t>::max();
    *int32_val = std::numeric_limits<std::int32_t>::max();

    return S_OK;
}

HRESULT VTL1_Declarations::TestPassingPrimitivesAsOutPointers_To_Enclave(
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

StructWithNoPointers VTL1_Declarations::ComplexPassingofTypes_To_Enclave(
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
    uint64_val = std::make_shared<std::uint64_t>();
    *uint64_val = std::numeric_limits<std::uint64_t>::max();

    return struct_to_return;
}
#pragma endregion

#pragma region Enclave to HostApp Tests

// For testing vtl0 callbacks we use HRESULTS as our success/failure metrics since we can't use TAEF in the
// enclave.

HRESULT VTL1_Declarations::Start_ReturnInt8ValPtr_From_HostApp_Callback_Test()
{
    // Note: struct is returned by vtl1, and copied to vtl0 then returned to this function.
    Int8PtrAndSize result = VTL0_Callbacks::ReturnInt8ValPtr_From_HostApp_callback();
    THROW_HR_IF_NULL(E_INVALIDARG, result.int8_val);
    THROW_HR_IF(E_INVALIDARG, *result.int8_val != std::numeric_limits<std::int8_t>::max());

    return S_OK;
}

HRESULT VTL1_Declarations::Start_ReturnUint64Val_From_HostApp_Callback_Test()
{
    // Note: std::uint64_t is returned by vtl0, and copied to vtl1 then returned to this function.
    std::uint64_t result = VTL0_Callbacks::ReturnUint64Val_From_HostApp_callback();
    THROW_HR_IF(E_INVALIDARG, result != std::numeric_limits<std::uint64_t>::max());

    return S_OK;
}

HRESULT VTL1_Declarations::Start_ReturnStructWithValues_From_HostApp_Callback_Test()
{
    // Note: struct is returned by vtl0, and copied to vtl1 then returned to this function.
    StructWithNoPointers result = VTL0_Callbacks::ReturnStructWithValues_From_HostApp_callback();
    THROW_HR_IF(E_INVALIDARG, !(CompareStructWithNoPointers(result, CreateStructWithNoPointers())));

    return S_OK;
}

HRESULT VTL1_Declarations::Start_TestPassingPrimitivesAsValues_To_HostApp_Callback_Test()
{
    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    auto in_bool = true;
    auto in_enum = DecimalEnum::Deci_val2;
    auto in_int8 = std::numeric_limits<std::int8_t>::max();

    THROW_IF_FAILED(VTL0_Callbacks::TestPassingPrimitivesAsValues_To_HostApp_callback(in_bool, in_enum, in_int8));

    return S_OK;
}

HRESULT VTL1_Declarations::Start_TestPassingPrimitivesAsInPointers_To_HostApp_Callback_Test()
{
    std::uint8_t uint8_val = 100;
    std::uint16_t uint16_val = 100;
    std::uint32_t uint32_val = 100;

    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    THROW_IF_FAILED(VTL0_Callbacks::TestPassingPrimitivesAsInPointers_To_HostApp_callback(
        &uint8_val,
        &uint16_val,
        &uint32_val));

    return S_OK;
}

HRESULT VTL1_Declarations::Start_TestPassingPrimitivesAsInOutPointers_To_HostApp_Callback_Test()
{
    std::int8_t int8_val = 100;
    std::int16_t int16_val = 100;
    std::int32_t int32_val = 100;

    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    THROW_IF_FAILED(VTL0_Callbacks::TestPassingPrimitivesAsInOutPointers_To_HostApp_callback(
        &int8_val,
        &int16_val,
        &int32_val));

    // The in-out parameters should have been filled in by the abi in vtl1 based on the result from
    // the vtl0 version of the function
    THROW_HR_IF(E_INVALIDARG, std::numeric_limits<std::int8_t>::max() != int8_val);
    THROW_HR_IF(E_INVALIDARG, std::numeric_limits<std::int16_t>::max() != int16_val);
    THROW_HR_IF(E_INVALIDARG, std::numeric_limits<std::int32_t>::max() != int32_val);

    return S_OK;
}
HRESULT VTL1_Declarations::Start_TestPassingPrimitivesAsOutPointers_To_HostApp_Callback_Test()
{
    std::shared_ptr<bool> bool_val = nullptr;
    std::shared_ptr<DecimalEnum> enum_val = nullptr;
    std::shared_ptr<std::uint64_t> uint64_val = nullptr;

    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    THROW_IF_FAILED(VTL0_Callbacks::TestPassingPrimitivesAsOutPointers_To_HostApp_callback(
        bool_val,
        enum_val,
        uint64_val));

    // The out parameters should have been filled in by the abi in vtl1 based on the result from
    // the vtl0 version of the function
    THROW_HR_IF_NULL(E_INVALIDARG, bool_val);
    THROW_HR_IF_NULL(E_INVALIDARG, enum_val);
    THROW_HR_IF_NULL(E_INVALIDARG, uint64_val);
    THROW_HR_IF(E_INVALIDARG, *bool_val != true);
    THROW_HR_IF(E_INVALIDARG, *enum_val != DecimalEnum::Deci_val3);
    THROW_HR_IF(E_INVALIDARG, *uint64_val != std::numeric_limits<std::uint64_t>::max());

    return S_OK;
}

HRESULT VTL1_Declarations::Start_ComplexPassingofTypes_To_HostApp_Callback_Test()
{
    auto expected_struct_values = CreateStructWithNoPointers();
    StructWithNoPointers struct_no_pointers_1 = expected_struct_values;
    StructWithNoPointers struct_no_pointers_2 {};
    std::shared_ptr<StructWithNoPointers> struct_no_pointers_3;
    StructWithNoPointers struct_no_pointers_4 {};
    std::shared_ptr<std::uint64_t> uint64_val = nullptr;

    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    auto result = VTL0_Callbacks::ComplexPassingofTypes_To_HostApp_callback(
        struct_no_pointers_1,
        struct_no_pointers_2,
        struct_no_pointers_3,
        struct_no_pointers_4,
        uint64_val);

    // The out parameters should have been filled in by the abi in vtl1 based on the result from
    // the vtl0 version of the function
    THROW_HR_IF(E_INVALIDARG, !(CompareStructWithNoPointers(result, CreateStructWithNoPointers())));
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithNoPointers(result, expected_struct_values));
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithNoPointers(struct_no_pointers_2, expected_struct_values));
    THROW_HR_IF_NULL(E_INVALIDARG, struct_no_pointers_3);
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithNoPointers(*struct_no_pointers_3, expected_struct_values));
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithNoPointers(struct_no_pointers_4, expected_struct_values));
    THROW_HR_IF_NULL(E_INVALIDARG, uint64_val);
    THROW_HR_IF(E_INVALIDARG, *uint64_val != std::numeric_limits<std::uint64_t>::max());

    return S_OK;
}

#pragma endregion
