// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "TestHelpers.h"
#include "HostTestHelpers.h"

using namespace VbsEnclave::VTL0_Stubs;

// Note about tests, we return Hresults for some of the tests just as an extra test
// to confirm the abi handles returning them properly. However we throw in those
// tests so we can identify where the error occured faster.

#pragma region VTL0 (HostApp) Callback implementations

std::uint64_t TestEnclave::ReturnUint64Val_From_HostApp_callback()
{
    return std::numeric_limits<std::uint64_t>::max();
}

TestStruct1 TestEnclave::ReturnStructWithValues_From_HostApp_callback()
{
    return CreateTestStruct1();
}

HRESULT TestEnclave::PassingPrimitivesAsValues_To_HostApp_callback(
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

std::vector<TestStruct1> TestEnclave::ReturnObjectInVector_From_HostApp_callback()
{
    return { 5 , CreateTestStruct1() };
}

HRESULT TestEnclave::PassingPrimitivesInVector_To_HostApp_callback(
    _In_ const std::vector<std::int8_t>& arg1,
    _In_ const std::vector<std::int16_t>& arg2,
    _In_ const std::vector<std::int32_t>& arg3,
    _Inout_  std::vector<std::int8_t>& arg4,
    _Inout_  std::vector<std::int16_t>& arg5,
    _Inout_  std::vector<std::int32_t>& arg6,
    _Out_  std::vector<std::int8_t>& arg7,
    _Out_  std::vector<std::int16_t>& arg8,
    _Out_  std::vector<std::int32_t>& arg9)
{
    // Confirm vtl1 parameters were correctly copied to vtl0 memory.
    VerifyContainsSameValuesArray(arg1.data(), c_data_size, std::numeric_limits<std::int8_t>::max()); // in param shouldn't have changed.
    VerifyContainsSameValuesArray(arg2.data(), c_data_size, std::numeric_limits<std::int16_t>::max());// in param shouldn't have changed.
    VerifyContainsSameValuesArray(arg3.data(), c_data_size, std::numeric_limits<std::int32_t>::max());// in param shouldn't have changed.
    VerifyContainsSameValuesArray(arg4.data(), c_data_size, std::numeric_limits<std::int8_t>::max()); // in param shouldn't have changed.
    VerifyContainsSameValuesArray(arg5.data(), c_data_size, std::numeric_limits<std::int16_t>::max());// in param shouldn't have changed.
    VerifyContainsSameValuesArray(arg6.data(), c_data_size, std::numeric_limits<std::int32_t>::max());// in param shouldn't have changed.

    // Copy data into the in-out buffers. Abi will copy these into vtl01 memory and return
    // them to caller.
    auto int8_data = CreateVector<int8_t>(c_arbitrary_size_1);
    arg4.assign(int8_data.begin(), int8_data.end());
    arg7.assign(int8_data.begin(), int8_data.end());

    auto int16_data = CreateVector<std::int16_t>(c_arbitrary_size_2);
    arg5.assign(int16_data.begin(), int16_data.end());
    arg8.assign(int16_data.begin(), int16_data.end());

    auto int32_data = CreateVector<std::int32_t>(c_arbitrary_size_1);
    arg6.assign(int32_data.begin(), int32_data.end());
    arg9.assign(int32_data.begin(), int32_data.end());

    return S_OK;
}

TestStruct2 TestEnclave::ComplexPassingofTypes_To_HostApp_callback(
    _In_ const TestStruct1& arg1, 
    _Inout_  TestStruct2& arg2, 
    _Out_  TestStruct3& arg3, 
    _In_ const std::vector<TestStruct1>& arg4,
    _Inout_  std::vector<TestStruct2>& arg5, 
    _Out_  std::vector<TestStruct3>& arg6)
{
    return CreateTestStruct2();
}

std::string TestEnclave::PassingStringTypes_To_HostApp_callback(
    _In_ const std::string& arg1,
    _Inout_  std::string& arg2,
    _Out_  std::string& arg3,
    _In_ const std::vector<std::string>& arg4,
    _Inout_  std::vector<std::string>& arg5,
    _Out_  std::vector<std::string>& arg6)
{
    return {};
}

std::wstring TestEnclave::PassingWStringTypes_To_HostApp_callback(
    _In_ const std::wstring& arg1,
    _Inout_  std::wstring& arg2,
    _Out_  std::wstring& arg3,
    _In_ const std::vector<std::wstring>& arg4,
    _Inout_  std::vector<std::wstring>& arg5,
    _Out_  std::vector<std::wstring>& arg6)
{
    return {};
}

NestedStructWithArray TestEnclave::PassingArrayTypes_To_HostApp_callback(
    _In_ const std::array<TestStruct1, 2>& arg1,
    _Inout_  std::array<std::string, 2>& arg2,
    _Out_  std::array<std::wstring, 2>& arg3,
    _Inout_  std::array<TestStruct2, 2>& arg4,
    _Out_  std::array<TestStruct3, 2>& arg5)
{
    return CreateNestedStructWithArray();
}

#pragma endregion
