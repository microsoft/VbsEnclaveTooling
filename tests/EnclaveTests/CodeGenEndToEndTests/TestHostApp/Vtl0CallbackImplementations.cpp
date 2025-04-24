// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <windows.h> 
#include <enclaveapi.h>
#include <wil\result_macros.h>
#include <wil\resource.h>
#include "TestHelpers.h"
#include "HostTestHelpers.h"
#include <VbsEnclave\HostApp\Stubs.h>

using namespace VbsEnclave::VTL0_Stubs;

// Note about tests, we return Hresults for some of the tests just as an extra test
// to confirm the abi handles returning them properly. However we throw in those
// tests so we can identify where the error occured faster.

#pragma region VTL0 (HostApp) Callback implementations

Int8PtrAndSize TestEnclave::ReturnInt8ValPtr_From_HostApp_callback()
{
    Int8PtrAndSize ret {};
    ret.int8_val = std::make_unique<std::int8_t>();
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
    _In_ bool bool_val,
    _In_ DecimalEnum enum_val,
    _In_ std::int8_t int8_val)
{
    // Confirm vtl1 parameters were correctly copied to vtl0 memory.
    THROW_HR_IF(E_INVALIDARG, bool_val != true);
    THROW_HR_IF(E_INVALIDARG, enum_val != DecimalEnum::Deci_val2);
    THROW_HR_IF(E_INVALIDARG, int8_val != std::numeric_limits<std::int8_t>::max());

    return S_OK;
}

HRESULT TestEnclave::TestPassingPrimitivesAsInOutValues_To_HostApp_callback(
    _Inout_ bool& bool_val,
    _Inout_ HexEnum& enum_val,
    _Inout_ std::int8_t& int8_val)
{
    // Confirm vtl1 parameters were correctly copied to vtl0 memory.
    THROW_HR_IF(E_INVALIDARG, bool_val != true);
    THROW_HR_IF(E_INVALIDARG, enum_val != HexEnum::Hex_val4);
    THROW_HR_IF(E_INVALIDARG, int8_val != std::numeric_limits<std::int8_t>::max());

    bool_val = false;
    enum_val = HexEnum::Hex_val3;
    int8_val = 100;

    return S_OK;
}

HRESULT TestEnclave::TestPassingPrimitivesAsOutValues_To_HostApp_callback(
    _Out_ bool& bool_val,
    _Out_ HexEnum& enum_val,
    _Out_ std::int8_t& int8_val)
{
    // Confirm vtl1 parameters were correctly copied to vtl0 memory.
    THROW_HR_IF(E_INVALIDARG, bool_val != false);
    THROW_HR_IF(E_INVALIDARG, enum_val != HexEnum::Hex_val1);
    THROW_HR_IF(E_INVALIDARG, int8_val != 0);

    bool_val = true;
    enum_val = HexEnum::Hex_val4;
    int8_val = std::numeric_limits<std::int8_t>::max();

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
    _Out_ std::unique_ptr<bool>& bool_val,
    _Out_ std::unique_ptr<DecimalEnum>& enum_val,
    _Out_ std::unique_ptr<std::uint64_t>& uint64_val)
{
    bool_val = nullptr;
    enum_val = nullptr;
    uint64_val = nullptr;

    bool_val = std::make_unique<bool>(true);
    enum_val = std::make_unique<DecimalEnum>(DecimalEnum::Deci_val3);
    uint64_val = std::make_unique<std::uint64_t>(std::numeric_limits<std::uint64_t>::max());

    return S_OK;
}

StructWithNoPointers TestEnclave::ComplexPassingofTypes_To_HostApp_callback(
    _In_ const StructWithNoPointers& arg1,
    _Inout_ StructWithNoPointers& arg2,
    _Out_ std::unique_ptr<StructWithNoPointers>& arg3,
    _Out_ StructWithNoPointers& arg4,
    _Out_ std::unique_ptr<std::uint64_t>& uint64_val)
{
    arg3 = nullptr;
    uint64_val = nullptr;
    auto struct_to_return = CreateStructWithNoPointers();

    // check in parm is expected value
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithNoPointers(arg1, struct_to_return));
    arg2 = struct_to_return;

    arg3 = std::make_unique<StructWithNoPointers>();
    *arg3 = CreateStructWithNoPointers();
    arg4 = CreateStructWithNoPointers();
    uint64_val = std::make_unique<std::uint64_t>(std::numeric_limits<std::uint64_t>::max());

    return struct_to_return;
}

void TestEnclave::ReturnNoParams_From_HostApp_callback()
{
    // No body, test just here to make sure we have coverage for void returns
}

std::vector<TestStruct1> TestEnclave::ReturnObjectInVector_From_HostApp_callback()
{
    return {5 , CreateTestStruct1()};
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

TestStruct2 TestEnclave::ComplexPassingofTypesWithVectors_To_HostApp_callback(
    _In_ const TestStruct1& arg1,
    _Inout_  TestStruct2& arg2,
    _Out_  TestStruct3& arg3,
    _In_ const std::vector<TestStruct1>& arg4,
    _Inout_  std::vector<TestStruct2>& arg5,
    _Out_  std::vector<TestStruct3>& arg6)
{
    auto expect_test1 = CreateTestStruct1();
    THROW_HR_IF(E_INVALIDARG, !CompareTestStruct1(arg1, expect_test1));
    std::vector<TestStruct1> arg4_expected(5, CreateTestStruct1());
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg4.begin(), arg4.end(), arg4_expected.begin(), CompareTestStruct1));
    arg2 = CreateTestStruct2();
    arg3 = CreateTestStruct3();
    arg5 = std::vector<TestStruct2>(5, CreateTestStruct2());
    auto expected_arg6 = std::vector<TestStruct3>(5, CreateTestStruct3());
    arg6 = expected_arg6;

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
    const std::string arg1_expected = "test";
    THROW_HR_IF(E_INVALIDARG, arg1 != arg1_expected);
    std::vector<std::string> arg4_expected(5, "test4");
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg4.begin(), arg4.end(), arg4_expected.begin()));
    arg2 = "test2 updated";
    arg3 = "test3 returned";
    std::vector<std::string> arg5_expected(5, "test5 was updated");
    arg5 = arg5_expected;
    std::vector<std::string> arg6_expected(5, "test6 was returned as out");
    arg6 = arg6_expected;

    return "return result";
}

std::wstring TestEnclave::PassingWStringTypes_To_HostApp_callback(
    _In_ const std::wstring& arg1,
    _Inout_  std::wstring& arg2,
    _Out_  std::wstring& arg3,
    _In_ const std::vector<std::wstring>& arg4,
    _Inout_  std::vector<std::wstring>& arg5,
    _Out_  std::vector<std::wstring>& arg6)
{
    const std::wstring arg1_expected = L"test";
    THROW_HR_IF(E_INVALIDARG, arg1 != arg1_expected);
    std::vector<std::wstring> arg4_expected(5, L"test4");
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg4.begin(), arg4.end(), arg4_expected.begin()));
    arg2 = L"test2 updated";
    arg3 = L"test3 returned";
    std::vector<std::wstring> arg5_expected(5, L"test5 was updated");
    arg5 = arg5_expected;
    std::vector<std::wstring> arg6_expected(5, L"test6 was returned as out");
    arg6 = arg6_expected;

    return L"return result";
}

NestedStructWithArray TestEnclave::PassingArrayTypes_To_HostApp_callback(
    _In_ const std::array<TestStruct1, 2>& arg1,
    _Inout_  std::array<std::string, 2>& arg2,
    _Out_  std::array<std::wstring, 2>& arg3,
    _Inout_  std::array<TestStruct2, 2>& arg4,
    _Out_  std::array<TestStruct3, 2>& arg5)
{
    std::array<TestStruct1, 2> arg1_expected = {CreateTestStruct1(), CreateTestStruct1()};
    std::array<TestStruct1, 2> temp_arg1 = arg1;
    THROW_HR_IF(E_INVALIDARG, !std::equal(temp_arg1.begin(), temp_arg1.end(), arg1_expected.begin(), CompareTestStruct1));

    std::array<std::string, 2> arg2_expected = {"test2 updated", "test2 updated"};
    arg2 = arg2_expected;
    std::array<std::wstring, 2> arg3_expected = {L"test2 updated", L"test2 updated"};
    arg3 = arg3_expected;
    auto arg4_expect_val = CreateTestStruct2();
    arg4_expect_val.field1.array1 = {10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    std::array<TestStruct2, 2> arg4_expected = {arg4_expect_val, arg4_expect_val};
    arg4 = arg4_expected;
    std::array<TestStruct3, 2> arg5_expected = {CreateTestStruct3(), CreateTestStruct3()};
    arg5 = arg5_expected;
    return CreateNestedStructWithArray();
}

#pragma endregion
