// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <windows.h> 
#include <enclaveapi.h>
#include <wil\result_macros.h>
#include <wil\resource.h>
#include "TestHelpers.h"
#include "HostTestHelpers.h"
#include <VbsEnclave\HostApp\Implementation\Untrusted.h>

using namespace VbsEnclave;

// Note about tests, we return Hresults for some of the tests just as an extra test
// to confirm the abi handles returning them properly. However we throw in those
// tests so we can identify where the error occured faster.

#pragma region VTL0 (HostApp) Callback implementations

std::optional<std::int32_t> Untrusted::Implementation::ReturnInt32Opt_From_HostApp()
{
    return std::make_optional<std::int32_t>(std::numeric_limits<std::int32_t>::max());
}

std::uint64_t Untrusted::Implementation::ReturnUint64Val_From_HostApp()
{
    return std::numeric_limits<std::uint64_t>::max();
}

StructWithNoOptionals Untrusted::Implementation::ReturnStructWithValues_From_HostApp()
{
    return CreateStructWithNoOptionals();
}

HRESULT Untrusted::Implementation::TestPassingPrimitivesAsValues_To_HostApp(
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

HRESULT Untrusted::Implementation::TestPassingPrimitivesAsInOutValues_To_HostApp(
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

HRESULT Untrusted::Implementation::TestPassingPrimitivesAsOutValues_To_HostApp(
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

HRESULT Untrusted::Implementation::TestPassingPrimitivesAsInOptionals_To_HostApp(
    _In_ const std::optional<std::uint8_t>& uint8_val,
    _In_ const std::optional<std::uint16_t>& uint16_val,
    _In_ const std::optional<std::uint32_t>& uint32_val,
    _In_ const std::optional<std::uint32_t>& empty_uint32_val)
{
    // Confirm vtl1 parameters were correctly copied to vtl0 memory.
    THROW_HR_IF(E_INVALIDARG, !uint8_val.has_value());
    THROW_HR_IF(E_INVALIDARG, !uint16_val.has_value());
    THROW_HR_IF(E_INVALIDARG, !uint32_val.has_value());
    THROW_HR_IF(E_INVALIDARG, 100 != *uint8_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *uint16_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *uint32_val);
    THROW_HR_IF(E_INVALIDARG, empty_uint32_val.has_value()); // should be nullopt

    return S_OK;
}

HRESULT Untrusted::Implementation::TestPassingPrimitivesAsInOutOptionals_To_HostApp(
    _Inout_ std::optional<std::int8_t>& int8_val,
    _Inout_ std::optional<std::int16_t>& int16_val,
    _Inout_ std::optional<std::int32_t>& int32_val)
{
    // Confirm vtl1 parameters were correctly copied to vtl0 memory.
    THROW_HR_IF(E_INVALIDARG, !int8_val.has_value());
    THROW_HR_IF(E_INVALIDARG, !int16_val.has_value());
    THROW_HR_IF(E_INVALIDARG, !int32_val.has_value());
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

HRESULT Untrusted::Implementation::TestPassingPrimitivesAsOutOptionals_To_HostApp(
    _Out_ std::optional<bool>& bool_val,
    _Out_ std::optional<DecimalEnum>& enum_val,
    _Out_ std::optional<std::uint64_t>& uint64_val)
{
    bool_val = std::make_optional<bool>(true);
    enum_val = std::make_optional<DecimalEnum>(DecimalEnum::Deci_val3);
    uint64_val = std::make_optional<std::uint64_t>(std::numeric_limits<std::uint64_t>::max());

    return S_OK;
}

StructWithNoOptionals Untrusted::Implementation::ComplexPassingOfTypes_To_HostApp(
    _In_ const StructWithNoOptionals& arg1,
    _Inout_ StructWithNoOptionals& arg2,
    _Out_ std::optional<StructWithNoOptionals>& arg3,
    _Out_ StructWithNoOptionals& arg4,
    _In_ const std::optional<StructWithNoOptionals>& arg5_empty,
    _In_ const std::optional<StructWithNoOptionals>& arg6,
    _Inout_ std::optional<StructWithNoOptionals>& arg7,
    _Out_ std::optional<std::uint64_t>& uint64_val)
{
    auto struct_to_return = CreateStructWithNoOptionals();

    // check in parm is expected value
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithNoOptionals(arg1, struct_to_return));
    THROW_HR_IF(E_INVALIDARG, arg5_empty.has_value()); // should be nullopt
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithNoOptionals(*arg6, struct_to_return));
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithNoOptionals(*arg7, {}));
    arg2 = struct_to_return;

    arg3 = std::make_optional<StructWithNoOptionals>();
    *arg3 = CreateStructWithNoOptionals();
    arg4 = CreateStructWithNoOptionals();
    uint64_val = std::make_optional<std::uint64_t>(std::numeric_limits<std::uint64_t>::max());
    *arg7 = CreateStructWithNoOptionals();

    return struct_to_return;
}

StructWithOptionals Untrusted::Implementation::ComplexPassingOfTypesThatContainOptionals_To_HostApp(
    _In_ const std::optional<StructWithOptionals>& arg1_empty,
    _In_ const std::optional<StructWithOptionals>& arg2,
    _Inout_ std::optional<StructWithOptionals>& arg3,
    _Out_ std::optional<StructWithOptionals>& arg4,
    _Inout_ std::vector<StructWithOptionals>& arg5,
    _Inout_ std::array<StructWithOptionals, 2>& arg6)
{
    auto struct_to_return = CreateStructWithOptionals();

    // check in parm is expected value
    THROW_HR_IF(E_INVALIDARG, arg1_empty.has_value()); // should be nullopt
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithOptionals(*arg2, struct_to_return));
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithOptionals(*arg3, {}));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg5.begin(), arg5.end(), c_struct_with_opts_vec_empty.begin(), CompareStructWithOptionals));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg6.begin(), arg6.end(), c_struct_with_opts_vec_empty.begin(), CompareStructWithOptionals));
    *arg3 = CreateStructWithOptionals();

    arg4 = std::make_optional<StructWithOptionals>();
    *arg4 = CreateStructWithOptionals();

    for (size_t i = 0; i < c_struct_with_opts_arr_initialize.size(); i++)
    {
        arg5[i] = CreateStructWithOptionals();
        arg6[i] = CreateStructWithOptionals();
    }

    return struct_to_return;
}

void Untrusted::Implementation::ReturnNoParams_From_HostApp()
{
    // No body, test just here to make sure we have coverage for void returns
}

std::vector<TestStruct1> Untrusted::Implementation::ReturnObjectInVector_From_HostApp()
{
    return {5 , CreateTestStruct1()};
}

HRESULT Untrusted::Implementation::PassingPrimitivesInVector_To_HostApp(
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

TestStruct2 Untrusted::Implementation::ComplexPassingOfTypesWithVectors_To_HostApp(
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

std::string Untrusted::Implementation::PassingStringTypes_To_HostApp(
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

std::wstring Untrusted::Implementation::PassingWStringTypes_To_HostApp(
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

NestedStructWithArray Untrusted::Implementation::PassingArrayTypes_To_HostApp(
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

void Untrusted::Implementation::Throw_Winrt_Exception_From_Host()
{
    throw winrt::hresult_not_implemented();
}

#pragma endregion
