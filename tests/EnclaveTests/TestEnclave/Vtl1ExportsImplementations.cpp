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

template <typename T>
HRESULT inline VerifyContainsSameValuesArray(const T* data, size_t size, T value)
{
    THROW_HR_IF_NULL(E_INVALIDARG, data);
    for (size_t i = 0; i < size; ++i)
    {
        THROW_HR_IF(E_INVALIDARG, data[i] != value);
    }

    return S_OK;
}

#pragma region VTL1 Enclave developer implementation functions

std::uint64_t VTL1_Declarations::ReturnUint64Val_From_Enclave()
{
    return std::numeric_limits<std::uint64_t>::max();
}

TestStruct1 VTL1_Declarations::ReturnStructWithValues_From_Enclave()
{
    return CreateTestStruct1();
}

HRESULT VTL1_Declarations::PassingPrimitivesAsValues_To_Enclave(
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

std::vector<TestStruct1> VTL1_Declarations::ReturnObjectInVector_From_Enclave()
{
    return {5 , CreateTestStruct1()};
}

HRESULT VTL1_Declarations::PassingPrimitivesInVector_To_Enclave(
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

TestStruct2 VTL1_Declarations::ComplexPassingofTypes_To_Enclave(
    _In_ const TestStruct1& arg1,
    _Inout_  TestStruct2& arg2,
    _Out_  TestStruct3& arg3,
    _In_ const std::vector<TestStruct1>& arg4,
    _Inout_  std::vector<TestStruct2>& arg5,
    _Out_  std::vector<TestStruct3>& arg6)
{
    return CreateTestStruct2();
}

std::string VTL1_Declarations::PassingStringTypes_To_Enclave(
    _In_ const std::string& arg1,
    _Inout_  std::string& arg2,
    _Out_  std::string& arg3,
    _In_ const std::vector<std::string>& arg4,
    _Inout_  std::vector<std::string>& arg5,
    _Out_  std::vector<std::string>& arg6)
{
    return {};
}

std::wstring VTL1_Declarations::PassingWStringTypes_To_Enclave(
    _In_ const std::wstring& arg1,
    _Inout_  std::wstring& arg2,
    _Out_  std::wstring& arg3,
    _In_ const std::vector<std::wstring>& arg4,
    _Inout_  std::vector<std::wstring>& arg5,
    _Out_  std::vector<std::wstring>& arg6)
{
    return {};
}

NestedStructWithArray VTL1_Declarations::PassingArrayTypes_To_Enclave(
    _In_ const std::array<TestStruct1, 2>& arg1,
    _Inout_  std::array<std::string, 2>& arg2,
    _Out_  std::array<std::wstring, 2>& arg3,
    _Inout_  std::array<TestStruct2, 2>& arg4,
    _Out_  std::array<TestStruct3, 2>& arg5)
{
    return CreateNestedStructWithArray();
}

#pragma endregion

#pragma region Enclave to HostApp Tests

// For testing vtl0 callbacks we use HRESULTS as our success/failure metrics since we can't use TAEF in the
// enclave.

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
    TestStruct1 result = VTL1_Declarations::ReturnStructWithValues_From_Enclave();
    auto expected = CreateTestStruct1();
    THROW_HR_IF(E_INVALIDARG, CompareTestStruct1(result, expected));

    return S_OK;
}

HRESULT VTL1_Declarations::Start_PassingPrimitivesAsValues_To_HostApp_Callback_Test()
{
    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    auto in_bool = true;
    auto in_enum = DecimalEnum::Deci_val2;
    auto in_int8 = std::numeric_limits<std::int8_t>::max();

    THROW_IF_FAILED(VTL0_Callbacks::PassingPrimitivesAsValues_To_HostApp_callback(in_bool, in_enum, in_int8));

    return S_OK;
}

HRESULT VTL1_Declarations::Start_ReturnObjectInVector_From_HostApp_Callback_Test()
{
    std::vector<TestStruct1> result_expected(5, CreateTestStruct1());

    auto result = VTL0_Callbacks::ReturnObjectInVector_From_HostApp_callback();
    THROW_HR_IF(E_INVALIDARG, result.size() != 5);
    THROW_HR_IF(E_INVALIDARG, !std::equal(result.begin(), result.end(), result_expected.begin(), CompareTestStruct1));
    return S_OK;
}

HRESULT VTL1_Declarations::Start_PassingPrimitivesInVector_To_HostApp_Callback_Test()
{
    std::vector<std::int8_t> arg1(c_data_size, std::numeric_limits<std::int8_t>::max());
    std::vector<std::int16_t> arg2(c_data_size, std::numeric_limits<std::int16_t>::max());
    std::vector<std::int32_t> arg3(c_data_size, std::numeric_limits<std::int32_t>::max());
    std::vector<std::int8_t> arg4(c_data_size, std::numeric_limits<std::int8_t>::max());
    std::vector<std::int16_t> arg5(c_data_size, std::numeric_limits<std::int16_t>::max());
    std::vector<std::int32_t> arg6(c_data_size, std::numeric_limits<std::int32_t>::max());
    std::vector<std::int8_t> arg7;
    std::vector<std::int16_t> arg8;
    std::vector<std::int32_t> arg9;

    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    THROW_IF_FAILED(VTL0_Callbacks::PassingPrimitivesInVector_To_HostApp_callback(
        arg1,
        arg2,
        arg3,
        arg4,
        arg5,
        arg6,
        arg7,
        arg8,
        arg9));

    // The in-out parameters should have been filled in by the abi in vtl1 based on the result from
    // the vtl0 version of the function
    VerifyContainsSameValuesArray(arg1.data(), c_data_size, std::numeric_limits<std::int8_t>::max()); // in param shouldn't have changed.
    VerifyContainsSameValuesArray(arg2.data(), c_data_size, std::numeric_limits<std::int16_t>::max());// in param shouldn't have changed.
    VerifyContainsSameValuesArray(arg3.data(), c_data_size, std::numeric_limits<std::int32_t>::max());// in param shouldn't have changed.
    VerifyNumericArray(arg4.data(), c_arbitrary_size_1); // inout param updated.
    VerifyNumericArray(arg5.data(), c_arbitrary_size_2); // inout param updated.
    VerifyNumericArray(arg6.data(), c_arbitrary_size_1); // inout param updated.
    VerifyContainsSameValuesArray(arg7.data(), c_data_size, std::numeric_limits<std::int8_t>::max()); // out param updated.
    VerifyContainsSameValuesArray(arg8.data(), c_data_size, std::numeric_limits<std::int16_t>::max());// out param updated.
    VerifyContainsSameValuesArray(arg9.data(), c_data_size, std::numeric_limits<std::int32_t>::max());// out param updated.

    return S_OK;
}

HRESULT VTL1_Declarations::Start_ComplexPassingofTypes_To_HostApp_Callback_Test()
{
    auto expect_val1 = CreateTestStruct1();
    auto expect_val2 = CreateTestStruct2();
    auto expect_val3 = CreateTestStruct3();
    TestStruct1 arg1 = expect_val1;
    TestStruct2 arg2 {};
    TestStruct3 arg3 {};
    std::vector<TestStruct1> arg4_expected(5, expect_val1);
    std::vector<TestStruct1> arg4 = arg4_expected;
    std::vector<TestStruct2> arg5_expected(5, expect_val2);
    std::vector<TestStruct2> arg5(1, expect_val2);
    std::vector<TestStruct3> arg6_expected(5, expect_val3);
    std::vector<TestStruct3> arg6 {};

    // Note: TestStruct2 is returned by vtl0, and copied to vtl1 then returned to this function.
    auto result = VTL0_Callbacks::ComplexPassingofTypes_To_HostApp_callback(
        arg1,
        arg2,
        arg3,
        arg4,
        arg5,
        arg6);

    // The out parameters should have been filled in by the abi in vtl1 based on the result from
    // the vtl0 version of the function
    THROW_HR_IF(E_INVALIDARG, !CompareTestStruct1(arg1, expect_val1));
    THROW_HR_IF(E_INVALIDARG, !CompareTestStruct2(arg2, expect_val2));
    THROW_HR_IF(E_INVALIDARG, !CompareTestStruct3(arg3, expect_val3));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg4.begin(), arg4.end(), arg4_expected.begin(), CompareTestStruct1));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg5.begin(), arg5.end(), arg5_expected.begin(), CompareTestStruct2));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg6.begin(), arg6.end(), arg6_expected.begin(), CompareTestStruct3));

    return S_OK;
}

HRESULT VTL1_Declarations::Start_PassingStringTypes_To_HostApp_Callback_Test()
{
    std::string arg1 = "test";
    std::string arg2 = "test2";
    std::string arg3 {};
    std::vector<std::string> arg4_expected(5, "test");
    std::vector<std::string> arg4 = arg4_expected;
    std::vector<std::string> arg5_expected(5, "test2 was updated");
    std::vector<std::string> arg5(5, "test2");
    std::vector<std::string> arg6_expected(5, "test3 was returned as out");

    std::vector<std::string> arg6 {};

    // Note: string is returned by vtl0, and copied to vtl1 then returned to this function.
    auto result = VTL0_Callbacks::PassingStringTypes_To_HostApp_callback(
         arg1,
        arg2,
        arg3,
        arg4,
        arg5,
        arg6);

    // The out parameters should have been filled in by the abi in vtl1 based on the result from
    // the vtl0 version of the function
    THROW_HR_IF(E_INVALIDARG, "return result" != result);
    THROW_HR_IF(E_INVALIDARG, "test" != arg1);
    THROW_HR_IF(E_INVALIDARG, "test2 updated" != arg2);
    THROW_HR_IF(E_INVALIDARG, "test3 returned" != arg3);
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg4.begin(), arg4.end(), arg4_expected.begin()));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg5.begin(), arg5.end(), arg5_expected.begin()));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg6.begin(), arg6.end(), arg6_expected.begin()));

    return S_OK;
}

HRESULT VTL1_Declarations::Start_PassingWStringTypes_To_HostApp_Callback_Test()
{
    std::wstring arg1 = L"test";
    std::wstring arg2 = L"test2";
    std::wstring arg3 {};
    std::vector<std::wstring> arg4_expected(5, L"test");
    std::vector<std::wstring> arg4 = arg4_expected;
    std::vector<std::wstring> arg5_expected(5, L"test2 was updated");
    std::vector<std::wstring> arg5(5, L"test2");
    std::vector<std::wstring> arg6_expected(5, L"test3 was returned as out");

    std::vector<std::wstring> arg6 {};

    // Note: wstring is returned by vtl0, and copied to vtl1 then returned to this function.
    auto result = VTL0_Callbacks::PassingWStringTypes_To_HostApp_callback(
         arg1,
        arg2,
        arg3,
        arg4,
        arg5,
        arg6);

    // The out parameters should have been filled in by the abi in vtl1 based on the result from
    // the vtl0 version of the function
    THROW_HR_IF(E_INVALIDARG, L"return result" != result);
    THROW_HR_IF(E_INVALIDARG, L"test" != arg1);
    THROW_HR_IF(E_INVALIDARG, L"test2 updated" != arg2);
    THROW_HR_IF(E_INVALIDARG, L"test3 returned"!= arg3);
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg4.begin(), arg4.end(), arg4_expected.begin()));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg5.begin(), arg5.end(), arg5_expected.begin()));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg6.begin(), arg6.end(), arg6_expected.begin()));

    return S_OK;
}

HRESULT VTL1_Declarations::Start_PassingArrayTypes_To_HostApp_Callback_Test()
{
    std::array<TestStruct1, 2> arg1 = {CreateTestStruct1(), CreateTestStruct1()};
    std::array<TestStruct1, 2> arg1_expected = {CreateTestStruct1(), CreateTestStruct1()};
    std::array<std::string, 2> arg2 = {"test2", "test2"};
    std::array<std::string, 2> arg2_expected = {"test2 updated", "test2 updated"};
    std::array<std::wstring, 2> arg3 {};
    std::array<std::wstring, 2> arg3_expected = {L"test2 updated", L"test2 updated"};
    std::array<TestStruct2, 2> arg4 = {CreateTestStruct2(), CreateTestStruct2()};
    auto arg4_expect_val = CreateTestStruct2();
    arg4_expect_val.field1.array1 = {10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    std::array<TestStruct2, 2> arg4_expected = {arg4_expect_val, arg4_expect_val};
    std::array<TestStruct3, 2> arg5 {};
    std::array<TestStruct3, 2> arg5_expected = {CreateTestStruct3(), CreateTestStruct3()};
    NestedStructWithArray nested_array_result = CreateNestedStructWithArray();

    // Note: NestedStructWithArray is returned by vtl1, and copied to vtl0 then returned to this function.
    auto result = VTL0_Callbacks::PassingArrayTypes_To_HostApp_callback(
         arg1,
        arg2,
        arg3,
        arg4,
        arg5);

    // The out parameters should have been filled in by the abi in vtl1 based on the result from
    // the vtl1 version of the function
    THROW_HR_IF(E_INVALIDARG, !CompareNestedStructWithArray(result, nested_array_result));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg1.begin(), arg1.end(), arg1_expected.begin(), CompareTestStruct1));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg2.begin(), arg2.end(), arg2_expected.begin()));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg3.begin(), arg3.end(), arg3_expected.begin()));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg4.begin(), arg4.end(), arg4_expected.begin(), CompareTestStruct2));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg5.begin(), arg5.end(), arg5_expected.begin(), CompareTestStruct3));
    
    return S_OK;
}
#pragma endregion
