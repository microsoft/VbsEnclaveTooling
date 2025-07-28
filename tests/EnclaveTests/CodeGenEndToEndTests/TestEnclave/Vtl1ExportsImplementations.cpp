// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <VbsEnclave\Enclave\Implementation\Trusted.h>
#include <VbsEnclave\Enclave\Stubs\Untrusted.h>
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

std::unique_ptr<std::int32_t> Trusted::Implementation::ReturnInt32Ptr_From_Enclave()
{
    return std::make_unique<std::int32_t>(std::numeric_limits<std::int32_t>::max());
}

std::uint64_t Trusted::Implementation::ReturnUint64Val_From_Enclave()
{
    return std::numeric_limits<std::uint64_t>::max();
}

StructWithNoPointers Trusted::Implementation::ReturnStructWithValues_From_Enclave()
{
    return CreateStructWithNoPointers();
}

HRESULT Trusted::Implementation::TestPassingPrimitivesAsValues_To_Enclave(
    _In_ bool bool_val,
    _In_ DecimalEnum enum_val,
    _In_ std::int8_t int8_val)
{
    // Confirm vtl0 parameters were correctly copied to vtl1 memory.
    THROW_HR_IF(E_INVALIDARG, bool_val != true);
    THROW_HR_IF(E_INVALIDARG, enum_val != DecimalEnum::Deci_val2);
    THROW_HR_IF(E_INVALIDARG, int8_val != std::numeric_limits<std::int8_t>::max());

    return S_OK;
}

HRESULT Trusted::Implementation::TestPassingPrimitivesAsInOutValues_To_Enclave(
    _Inout_ bool& bool_val,
    _Inout_ HexEnum& enum_val,
    _Inout_ std::int8_t& int8_val)
{
    // Confirm vtl0 parameters were correctly copied to vtl1 memory.
    THROW_HR_IF(E_INVALIDARG, bool_val != true);
    THROW_HR_IF(E_INVALIDARG, enum_val != HexEnum::Hex_val4);
    THROW_HR_IF(E_INVALIDARG, int8_val != std::numeric_limits<std::int8_t>::max());

    bool_val = false;
    enum_val = HexEnum::Hex_val3;
    int8_val = 100;

    return S_OK;
}

HRESULT Trusted::Implementation::TestPassingPrimitivesAsOutValues_To_Enclave(
    _Out_ bool& bool_val,
    _Out_ HexEnum& enum_val,
    _Out_ std::int8_t& int8_val)
{
    // Confirm vtl0 parameters were correctly copied to vtl1 memory.
    THROW_HR_IF(E_INVALIDARG, bool_val != false);
    THROW_HR_IF(E_INVALIDARG, enum_val != HexEnum::Hex_val1);
    THROW_HR_IF(E_INVALIDARG, int8_val != 0);

    bool_val = true;
    enum_val = HexEnum::Hex_val4;
    int8_val = std::numeric_limits<std::int8_t>::max();

    return S_OK;
}

HRESULT Trusted::Implementation::TestPassingPrimitivesAsInPointers_To_Enclave(
    _In_ const std::uint8_t* uint8_val,
    _In_ const std::uint16_t* uint16_val,
    _In_ const std::uint32_t* uint32_val,
    _In_ const uint32_t* null_uint32_val)
{
    // Confirm vtl0 parameters were correctly copied to vtl1 memory.
    THROW_HR_IF_NULL(E_INVALIDARG, uint8_val);
    THROW_HR_IF_NULL(E_INVALIDARG, uint16_val);
    THROW_HR_IF_NULL(E_INVALIDARG, uint32_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *uint8_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *uint16_val);
    THROW_HR_IF(E_INVALIDARG, 100 != *uint32_val);
    THROW_HR_IF(E_INVALIDARG, null_uint32_val != nullptr);

    return S_OK;
}

HRESULT Trusted::Implementation::TestPassingPrimitivesAsInOutPointers_To_Enclave(
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

HRESULT Trusted::Implementation::TestPassingPrimitivesAsOutPointers_To_Enclave(
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

StructWithNoPointers Trusted::Implementation::ComplexPassingOfTypes_To_Enclave(
    _In_ const StructWithNoPointers& arg1,
    _Inout_ StructWithNoPointers& arg2,
    _Out_ std::unique_ptr<StructWithNoPointers>& arg3,
    _Out_ StructWithNoPointers& arg4,
    _In_ const StructWithNoPointers* arg5_null,
    _In_ const StructWithNoPointers* arg6,
    _Inout_ StructWithNoPointers* arg7,
    _Out_ std::unique_ptr<std::uint64_t>& uint64_val)
{
    arg3 = nullptr;
    uint64_val = nullptr;
    auto struct_to_return = CreateStructWithNoPointers();

    // check in parm is expected value
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithNoPointers(arg1, struct_to_return));
    THROW_HR_IF(E_INVALIDARG, arg5_null != nullptr);
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithNoPointers(*arg6, struct_to_return));
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithNoPointers(*arg7, {}));
    arg2 = struct_to_return;

    arg3 = std::make_unique<StructWithNoPointers>();
    *arg3 = CreateStructWithNoPointers();
    arg4 = CreateStructWithNoPointers();
    uint64_val = std::make_unique<std::uint64_t>();
    *uint64_val = std::numeric_limits<std::uint64_t>::max();
    *arg7 = CreateStructWithNoPointers();

    return struct_to_return;
}

void Trusted::Implementation::ReturnNoParams_From_Enclave()
{
    // No body, test just here to make sure we have coverage for void returns
}


std::vector<TestStruct1> Trusted::Implementation::ReturnObjectInVector_From_Enclave()
{
    return {5 , CreateTestStruct1()};
}

HRESULT Trusted::Implementation::PassingPrimitivesInVector_To_Enclave(
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

TestStruct2 Trusted::Implementation::ComplexPassingOfTypesWithVectors_To_Enclave(
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

std::string Trusted::Implementation::PassingStringTypes_To_Enclave(
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

std::wstring Trusted::Implementation::PassingWStringTypes_To_Enclave(
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

NestedStructWithArray Trusted::Implementation::PassingArrayTypes_To_Enclave(
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

StructWithPointers Trusted::Implementation::ComplexPassingOfTypesThatContainPointers_To_Enclave(
    _In_ const StructWithPointers* arg1_null,
    _In_ const StructWithPointers* arg2,
    _Inout_ StructWithPointers* arg3,
    _Out_ std::unique_ptr<StructWithPointers>& arg4,
    _Inout_ std::vector<StructWithPointers>& arg5,
    _Inout_ std::array<StructWithPointers, 2>& arg6)
{
    arg4 = nullptr;
    auto struct_to_return = CreateStructWithPointers();

    // check in/inout parameters contain expected values
    THROW_HR_IF(E_INVALIDARG, arg1_null != nullptr);
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithPointers(*arg2, struct_to_return));
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithPointers(*arg3, {}));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg5.begin(), arg5.end(), c_struct_with_ptrs_vec_empty.begin(), CompareStructWithPointers));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg6.begin(), arg6.end(), c_struct_with_ptrs_vec_empty.begin(), CompareStructWithPointers));

    *arg3 = CreateStructWithPointers();
    arg4 = std::make_unique<StructWithPointers>();
    *arg4 = CreateStructWithPointers();

    for (size_t i = 0; i < c_struct_with_ptrs_arr_initialize.size(); i++)
    {
        arg5[i] = CreateStructWithPointers();
        arg6[i] = CreateStructWithPointers();
    }

    return struct_to_return;
}

#pragma endregion

#pragma region Enclave to HostApp Tests

// For testing vtl0 callbacks we use HRESULTS as our success/failure metrics since we can't use TAEF in the
// enclave.

HRESULT Trusted::Implementation::Start_ReturnInt32Ptr_From_HostApp_Callback_Test()
{
    // Note: struct is returned by vtl1, and copied to vtl0 then returned to this function.
    auto result = Untrusted::Stubs::ReturnInt32Ptr_From_HostApp();
    THROW_HR_IF_NULL(E_INVALIDARG, result.get());
    THROW_HR_IF(E_INVALIDARG, *result != std::numeric_limits<std::int32_t>::max());

    return S_OK;
}

HRESULT Trusted::Implementation::Start_ReturnUint64Val_From_HostApp_Callback_Test()
{
    // Note: std::uint64_t is returned by vtl0, and copied to vtl1 then returned to this function.
    std::uint64_t result = Untrusted::Stubs::ReturnUint64Val_From_HostApp();
    THROW_HR_IF(E_INVALIDARG, result != std::numeric_limits<std::uint64_t>::max());

    return S_OK;
}

HRESULT Trusted::Implementation::Start_ReturnStructWithValues_From_HostApp_Callback_Test()
{
    // Note: struct is returned by vtl0, and copied to vtl1 then returned to this function.
    StructWithNoPointers result = Untrusted::Stubs::ReturnStructWithValues_From_HostApp();
    THROW_HR_IF(E_INVALIDARG, !(CompareStructWithNoPointers(result, CreateStructWithNoPointers())));

    return S_OK;
}

HRESULT Trusted::Implementation::Start_TestPassingPrimitivesAsValues_To_HostApp_Callback_Test()
{
    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    auto in_bool = true;
    auto in_enum = DecimalEnum::Deci_val2;
    auto in_int8 = std::numeric_limits<std::int8_t>::max();

    THROW_IF_FAILED(Untrusted::Stubs::TestPassingPrimitivesAsValues_To_HostApp(in_bool, in_enum, in_int8));

    return S_OK;
}

HRESULT Trusted::Implementation::Start_TestPassingPrimitivesAsInOutValues_To_HostApp_Callback_Test()
{
    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    auto in_out_bool = true;
    auto in_out_enum = HexEnum::Hex_val4;
    auto in_out_int8 = std::numeric_limits<std::int8_t>::max();

    THROW_IF_FAILED(Untrusted::Stubs::TestPassingPrimitivesAsInOutValues_To_HostApp(
        in_out_bool,
        in_out_enum,
        in_out_int8));

    THROW_HR_IF(E_INVALIDARG, in_out_bool != false);
    THROW_HR_IF(E_INVALIDARG, static_cast<std::uint64_t>(HexEnum::Hex_val3) != static_cast<std::uint64_t>(in_out_enum));
    THROW_HR_IF(E_INVALIDARG, 100 != in_out_int8);

    return S_OK;
}

HRESULT Trusted::Implementation::Start_TestPassingPrimitivesAsOutValues_To_HostApp_Callback_Test()
{
    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    bool out_bool {};
    HexEnum out_enum {};
    std::int8_t out_int8 {};

    THROW_IF_FAILED(Untrusted::Stubs::TestPassingPrimitivesAsOutValues_To_HostApp(
        out_bool,
        out_enum,
        out_int8));

    THROW_HR_IF(E_INVALIDARG, out_bool != true);
    THROW_HR_IF(E_INVALIDARG, static_cast<std::uint64_t>(HexEnum::Hex_val4) != static_cast<std::uint64_t>(out_enum));
    THROW_HR_IF(E_INVALIDARG, std::numeric_limits<std::int8_t>::max() != out_int8);

    return S_OK;
}

HRESULT Trusted::Implementation::Start_TestPassingPrimitivesAsInPointers_To_HostApp_Callback_Test()
{
    std::uint8_t uint8_val = 100;
    std::uint16_t uint16_val = 100;
    std::uint32_t uint32_val = 100;
    std::uint32_t* null_uint32_val {};

    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    THROW_IF_FAILED(Untrusted::Stubs::TestPassingPrimitivesAsInPointers_To_HostApp(
        &uint8_val,
        &uint16_val,
        &uint32_val,
        null_uint32_val));

    return S_OK;
}

HRESULT Trusted::Implementation::Start_TestPassingPrimitivesAsInOutPointers_To_HostApp_Callback_Test()
{
    std::int8_t int8_val = 100;
    std::int16_t int16_val = 100;
    std::int32_t int32_val = 100;

    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    THROW_IF_FAILED(Untrusted::Stubs::TestPassingPrimitivesAsInOutPointers_To_HostApp(
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
HRESULT Trusted::Implementation::Start_TestPassingPrimitivesAsOutPointers_To_HostApp_Callback_Test()
{
    std::unique_ptr<bool> bool_val = nullptr;
    std::unique_ptr<DecimalEnum> enum_val = nullptr;
    std::unique_ptr<std::uint64_t> uint64_val = nullptr;

    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    THROW_IF_FAILED(Untrusted::Stubs::TestPassingPrimitivesAsOutPointers_To_HostApp(
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

HRESULT Trusted::Implementation::Start_ComplexPassingOfTypes_To_HostApp_Callback_Test()
{
    auto expected_struct_values = CreateStructWithNoPointers();
    StructWithNoPointers struct_no_pointers_1 = expected_struct_values;
    StructWithNoPointers struct_no_pointers_2 {};
    std::unique_ptr<StructWithNoPointers> struct_no_pointers_3;
    StructWithNoPointers struct_no_pointers_4 {};
    std::unique_ptr<std::uint64_t> uint64_val = nullptr;
    StructWithNoPointers* struct_no_pointers_5 {};
    StructWithNoPointers struct_no_pointers_6 = expected_struct_values;
    StructWithNoPointers struct_no_pointers_7 {};

    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    auto result = Untrusted::Stubs::ComplexPassingOfTypes_To_HostApp(
        struct_no_pointers_1,
        struct_no_pointers_2,
        struct_no_pointers_3,
        struct_no_pointers_4,
        struct_no_pointers_5,
        &struct_no_pointers_6,
        &struct_no_pointers_7,
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
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithNoPointers(struct_no_pointers_6, expected_struct_values));
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithNoPointers(struct_no_pointers_7, expected_struct_values));

    return S_OK;
}

HRESULT Trusted::Implementation::Start_ComplexPassingOfTypesThatContainPointers_To_HostApp_Callback_Test()
{
    auto expected_struct_with_ptrs = CreateStructWithPointers();
    StructWithPointers* struct_with_pointers_1_null {};
    StructWithPointers struct_with_pointers_2 = CreateStructWithPointers();
    StructWithPointers struct_with_pointers_3 = {};
    std::unique_ptr<StructWithPointers> struct_with_pointers_4 {};
    std::vector<StructWithPointers> struct_with_pointers_5(c_arbitrary_size_2);
    std::array<StructWithPointers, c_arbitrary_size_2> struct_with_pointers_6;

    // The inout and out parameters should have been filled in by the abi in vtl1 based on the result from
    // the vtl0 version of the function
    auto result = Untrusted::Stubs::ComplexPassingOfTypesThatContainPointers_To_HostApp(
        struct_with_pointers_1_null,
        &struct_with_pointers_2,
        &struct_with_pointers_3,
        struct_with_pointers_4,
        struct_with_pointers_5,
        struct_with_pointers_6);

    THROW_HR_IF(E_INVALIDARG, !(CompareStructWithPointers(result, expected_struct_with_ptrs)));
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithPointers(struct_with_pointers_3, expected_struct_with_ptrs));
    THROW_HR_IF_NULL(E_INVALIDARG, struct_with_pointers_4.get());
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithPointers(*struct_with_pointers_4, expected_struct_with_ptrs));
    THROW_HR_IF(E_INVALIDARG, !std::equal(struct_with_pointers_5.begin(), struct_with_pointers_5.end(), c_struct_with_ptrs_arr_initialize.begin(), CompareStructWithPointers));
    THROW_HR_IF(E_INVALIDARG, !std::equal(struct_with_pointers_6.begin(), struct_with_pointers_6.end(), c_struct_with_ptrs_arr_initialize.begin(), CompareStructWithPointers));

    return S_OK;
}

void Trusted::Implementation::Start_ReturnNoParams_From_HostApp_Callback_Test()
{
    // No body, test just here to make sure we have coverage for void returns
}

HRESULT Trusted::Implementation::Start_ReturnObjectInVector_From_HostApp_Callback_Test()
{
    std::vector<TestStruct1> result_expected(5, CreateTestStruct1());

    auto result = Untrusted::Stubs::ReturnObjectInVector_From_HostApp();
    THROW_HR_IF(E_INVALIDARG, result.size() != 5);
    THROW_HR_IF(E_INVALIDARG, !std::equal(result.begin(), result.end(), result_expected.begin(), CompareTestStruct1));
    return S_OK;
}

HRESULT Trusted::Implementation::Start_PassingPrimitivesInVector_To_HostApp_Callback_Test()
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
    THROW_IF_FAILED(Untrusted::Stubs::PassingPrimitivesInVector_To_HostApp(
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
    VerifyNumericArray(arg7.data(), c_arbitrary_size_1); // out param updated.
    VerifyNumericArray(arg8.data(), c_arbitrary_size_2);// out param updated.
    VerifyNumericArray(arg9.data(), c_arbitrary_size_1);// out param updated.

    return S_OK;
}

HRESULT Trusted::Implementation::Start_ComplexPassingOfTypesWithVectors_To_HostApp_Callback_Test()
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
    auto result = Untrusted::Stubs::ComplexPassingOfTypesWithVectors_To_HostApp(
        arg1,
        arg2,
        arg3,
        arg4,
        arg5,
        arg6);

    // The out parameters should have been filled in by the abi in vtl1 based on the result from
    // the vtl0 version of the function
    THROW_HR_IF(E_INVALIDARG, !CompareTestStruct2(result, expect_val2));
    THROW_HR_IF(E_INVALIDARG, !CompareTestStruct1(arg1, expect_val1));
    THROW_HR_IF(E_INVALIDARG, !CompareTestStruct2(arg2, expect_val2));
    THROW_HR_IF(E_INVALIDARG, !CompareTestStruct3(arg3, expect_val3));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg4.begin(), arg4.end(), arg4_expected.begin(), CompareTestStruct1));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg5.begin(), arg5.end(), arg5_expected.begin(), CompareTestStruct2));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg6.begin(), arg6.end(), arg6_expected.begin(), CompareTestStruct3));

    return S_OK;
}

HRESULT Trusted::Implementation::Start_PassingStringTypes_To_HostApp_Callback_Test()
{
    std::string arg1 = "test";
    std::string arg2 = "test2";
    std::string arg3 {};
    std::vector<std::string> arg4_expected(5, "test4");
    std::vector<std::string> arg4 = arg4_expected;
    std::vector<std::string> arg5_expected(5, "test5 was updated");
    std::vector<std::string> arg5(5, "test5");
    std::vector<std::string> arg6_expected(5, "test6 was returned as out");

    std::vector<std::string> arg6 {};

    // Note: string is returned by vtl0, and copied to vtl1 then returned to this function.
    auto result = Untrusted::Stubs::PassingStringTypes_To_HostApp(
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

HRESULT Trusted::Implementation::Start_PassingWStringTypes_To_HostApp_Callback_Test()
{
    std::wstring arg1 = L"test";
    std::wstring arg2 = L"test2";
    std::wstring arg3 {};
    std::vector<std::wstring> arg4_expected(5, L"test4");
    std::vector<std::wstring> arg4 = arg4_expected;
    std::vector<std::wstring> arg5_expected(5, L"test5 was updated");
    std::vector<std::wstring> arg5(5, L"test5");
    std::vector<std::wstring> arg6_expected(5, L"test6 was returned as out");

    std::vector<std::wstring> arg6 {};

    // Note: wstring is returned by vtl0, and copied to vtl1 then returned to this function.
    auto result = Untrusted::Stubs::PassingWStringTypes_To_HostApp(
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
    THROW_HR_IF(E_INVALIDARG, L"test3 returned" != arg3);
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg4.begin(), arg4.end(), arg4_expected.begin()));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg5.begin(), arg5.end(), arg5_expected.begin()));
    THROW_HR_IF(E_INVALIDARG, !std::equal(arg6.begin(), arg6.end(), arg6_expected.begin()));

    return S_OK;
}

HRESULT Trusted::Implementation::Start_PassingArrayTypes_To_HostApp_Callback_Test()
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
    auto result = Untrusted::Stubs::PassingArrayTypes_To_HostApp(
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
