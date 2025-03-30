// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <windows.h> 
#include <enclaveapi.h>
#include <wil\result_macros.h>
#include <wil\resource.h>
#include <WexTestClass.h>
#include "TestHelpers.h"
#include "HostTestHelpers.h"
#include <VbsEnclave\HostApp\Stubs.h>

using namespace VbsEnclave::VTL0_Stubs;
using namespace WEX::Common;
using namespace WEX::TestExecution;

// This is only to encapsulate the win32 api calls too create/load/initialize/terminate
// and delete the enclave. Note this doesn't use the SDK, to just focus on the codegen.
struct EnclaveTestClass
{
    TEST_CLASS(EnclaveTestClass)

        EnclaveTestClass()
    {
        PVOID enclave {};

        try
        {
            if (!IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS))
            {
                printf("VBS Enclave not supported\n");
                THROW_HR(E_NOTIMPL);
            }

            // Create the enclave
            constexpr ENCLAVE_CREATE_INFO_VBS CreateInfo
            {
                ENCLAVE_VBS_FLAG_DEBUG, // Flags
                { 0x10, 0x20, 0x30, 0x40, 0x41, 0x31, 0x21, 0x11 }, // OwnerID
            };

            enclave = CreateEnclave(GetCurrentProcess(),
                nullptr, // Preferred base address
                0x10000000, // size
                0,
                ENCLAVE_TYPE_VBS,
                &CreateInfo,
                sizeof(ENCLAVE_CREATE_INFO_VBS),
                nullptr);

            THROW_LAST_ERROR_IF_NULL(enclave);

            // Load enclave module with SEM_FAILCRITICALERRORS enabled to suppress
            // the error message dialog.
            {
                DWORD previousMode = GetThreadErrorMode();
                SetThreadErrorMode(previousMode | SEM_FAILCRITICALERRORS, nullptr);
                auto restoreErrorMode = wil::scope_exit([&]
                {
                    SetThreadErrorMode(previousMode, nullptr);
                });
                THROW_IF_WIN32_BOOL_FALSE(LoadEnclaveImageW(enclave, L"TestEnclave.dll"));
            }

            // Initialize the enclave with one thread.
            // Once initialized, no more DLLs can be loaded into the enclave.
            ENCLAVE_INIT_INFO_VBS InitInfo {};

            InitInfo.Length = sizeof(ENCLAVE_INIT_INFO_VBS);
            InitInfo.ThreadCount = 1;

            THROW_IF_WIN32_BOOL_FALSE(InitializeEnclave(
                GetCurrentProcess(),
                enclave,
                &InitInfo,
                InitInfo.Length,
                nullptr));

            m_enclave = enclave;
        }
        catch (...)
        {
            UnloadEnclave(enclave);
            throw;
        }
    }

    ~EnclaveTestClass()
    {
        UnloadEnclave(m_enclave);
    }

    static void UnloadEnclave(LPVOID enclave)
    {
        if (enclave)
        {
            LOG_IF_WIN32_BOOL_FALSE(TerminateEnclave(enclave, TRUE));
            LOG_IF_WIN32_BOOL_FALSE(DeleteEnclave(enclave));
        }
    }

    LPVOID m_enclave {};

    #pragma region HostApp to Enclave Tests

    TEST_METHOD_SETUP(Register_Callbacks_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        return VERIFY_SUCCEEDED(generated_enclave_class.RegisterVtl0Callbacks());
    }

    TEST_METHOD(ReturnInt8ValPtr_From_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: Int8PtrAndSize is returned by vtl1, and copied to vtl0 then returned to this function.
        Int8PtrAndSize result = generated_enclave_class.ReturnInt8ValPtr_From_Enclave();
        VERIFY_IS_NOT_NULL(result.int8_val.get());
        VERIFY_ARE_EQUAL(*result.int8_val, std::numeric_limits<std::int8_t>::max());
    }

    TEST_METHOD(ReturnUint64Val_From_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: std::uint64_t is returned by vtl1, and copied to vtl0 then returned to this function.
        std::uint64_t result = generated_enclave_class.ReturnUint64Val_From_Enclave();
        VERIFY_ARE_EQUAL(result, std::numeric_limits<std::uint64_t>::max());
    }

    TEST_METHOD(ReturnStructWithValues_From_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: struct is returned by vtl1, and copied to vtl0 then returned to this function.
        StructWithNoPointers result = generated_enclave_class.ReturnStructWithValues_From_Enclave();
        VERIFY_IS_TRUE(CompareStructWithNoPointers(result, CreateStructWithNoPointers()));
    }
    
    TEST_METHOD(TestPassingPrimitivesAsValues_To_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        auto in_bool = true;
        auto in_enum = DecimalEnum::Deci_val2;
        auto in_int8 = std::numeric_limits<std::int8_t>::max();

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.TestPassingPrimitivesAsValues_To_Enclave(in_bool, in_enum, in_int8));
    }

    TEST_METHOD(TestPassingPrimitivesAsInPointers_To_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        std::uint8_t uint8_val = 100;
        std::uint16_t uint16_val = 100;
        std::uint32_t uint32_val = 100;
      
        // Note: Hresult is return by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.TestPassingPrimitivesAsInPointers_To_Enclave(
            &uint8_val,
            &uint16_val,
            &uint32_val));
    }

    TEST_METHOD(TestPassingPrimitivesAsInOutPointers_To_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        std::int8_t int8_val = 100;
        std::int16_t int16_val = 100;
        std::int32_t int32_val = 100;

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.TestPassingPrimitivesAsInOutPointers_To_Enclave(
            &int8_val,
            &int16_val,
            &int32_val));

        // The in-out parameters should have been filled in by the abi in vtl1 based on the result from
        // the vtl1 version of the function
        VERIFY_ARE_EQUAL(std::numeric_limits<std::int8_t>::max(), int8_val);
        VERIFY_ARE_EQUAL(std::numeric_limits<std::int16_t>::max(), int16_val);
        VERIFY_ARE_EQUAL(std::numeric_limits<std::int32_t>::max(), int32_val);
    }

    TEST_METHOD(TestPassingPrimitivesAsOutPointers_To_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        std::shared_ptr<bool> bool_val = nullptr;
        std::shared_ptr<DecimalEnum> enum_val = nullptr;
        std::shared_ptr<std::uint64_t> uint64_val = nullptr;

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.TestPassingPrimitivesAsOutPointers_To_Enclave(
            bool_val,
            enum_val,
            uint64_val));

        // The out parameters should have been filled in by the abi in vtl1 based on the result from
        // the vtl1 version of the function
        VERIFY_IS_NOT_NULL(bool_val.get());
        VERIFY_IS_NOT_NULL(enum_val.get());
        VERIFY_IS_NOT_NULL(uint64_val.get());
        VERIFY_ARE_EQUAL(*bool_val, true);
        VERIFY_ARE_EQUAL(*enum_val, DecimalEnum::Deci_val3);
        VERIFY_ARE_EQUAL(*uint64_val, std::numeric_limits<std::uint64_t>::max());
    }

    TEST_METHOD(ComplexPassingofTypes_To_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        auto expected_struct_values = CreateStructWithNoPointers();
        StructWithNoPointers struct_no_pointers_1 = expected_struct_values;
        StructWithNoPointers struct_no_pointers_2 {};
        std::shared_ptr<StructWithNoPointers> struct_no_pointers_3;
        StructWithNoPointers struct_no_pointers_4 {};
        std::shared_ptr<std::uint64_t> uint64_val = nullptr;

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        auto result = generated_enclave_class.ComplexPassingofTypes_To_Enclave(
            struct_no_pointers_1,
            struct_no_pointers_2,
            struct_no_pointers_3,
            struct_no_pointers_4,
            uint64_val);

        // The out parameters should have been filled in by the abi in vtl1 based on the result from
        // the vtl1 version of the function
        VERIFY_IS_TRUE(CompareStructWithNoPointers(result, expected_struct_values));
        VERIFY_IS_TRUE(CompareStructWithNoPointers(struct_no_pointers_2, expected_struct_values));
        VERIFY_IS_NOT_NULL(struct_no_pointers_3.get());
        VERIFY_IS_TRUE(CompareStructWithNoPointers(*struct_no_pointers_3, expected_struct_values));
        VERIFY_IS_TRUE(CompareStructWithNoPointers(struct_no_pointers_4, expected_struct_values));
        VERIFY_IS_NOT_NULL(uint64_val.get());
        VERIFY_ARE_EQUAL(*uint64_val, std::numeric_limits<std::uint64_t>::max());
    }

    TEST_METHOD(ReturnObjectInVector_From_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        std::vector<TestStruct1> result_expected(5, CreateTestStruct1());

        // Note: Hresult is return by vtl1, and copied to vtl0 then returned to this function.
        auto result = generated_enclave_class.ReturnObjectInVector_From_Enclave();
        VERIFY_IS_TRUE(result.size() == 5);
        VERIFY_IS_TRUE(std::equal(result.begin(), result.end(), result_expected.begin(), CompareTestStruct1));
    }

    TEST_METHOD(PassingPrimitivesAsVector_To_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        std::vector<std::int8_t> arg1(c_data_size, std::numeric_limits<std::int8_t>::max());
        std::vector<std::int16_t> arg2(c_data_size, std::numeric_limits<std::int16_t>::max());
        std::vector<std::int32_t> arg3(c_data_size, std::numeric_limits<std::int32_t>::max());
        std::vector<std::int8_t> arg4(c_data_size, std::numeric_limits<std::int8_t>::max());
        std::vector<std::int16_t> arg5(c_data_size, std::numeric_limits<std::int16_t>::max());
        std::vector<std::int32_t> arg6(c_data_size, std::numeric_limits<std::int32_t>::max());
        std::vector<std::int8_t> arg7;
        std::vector<std::int16_t> arg8;
        std::vector<std::int32_t> arg9;

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.PassingPrimitivesInVector_To_Enclave(
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
        // the vtl1 version of the function
        VerifyContainsSameValuesArray(arg1.data(), c_data_size, std::numeric_limits<std::int8_t>::max()); // in param shouldn't have changed.
        VerifyContainsSameValuesArray(arg2.data(), c_data_size, std::numeric_limits<std::int16_t>::max());// in param shouldn't have changed.
        VerifyContainsSameValuesArray(arg3.data(), c_data_size, std::numeric_limits<std::int32_t>::max());// in param shouldn't have changed.
        VerifyNumericArray(arg4.data(), c_arbitrary_size_1); // inout param updated.
        VerifyNumericArray(arg5.data(), c_arbitrary_size_2); // inout param updated.
        VerifyNumericArray(arg6.data(), c_arbitrary_size_1); // inout param updated.
        VerifyNumericArray(arg7.data(), c_arbitrary_size_1); // out param updated.
        VerifyNumericArray(arg8.data(), c_arbitrary_size_2);// out param updated.
        VerifyNumericArray(arg9.data(), c_arbitrary_size_1);// out param updated.
    }

    TEST_METHOD(ComplexPassingofTypesWithVectors_To_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
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

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        auto result = generated_enclave_class.ComplexPassingofTypesWithVectors_To_Enclave(
            arg1,
            arg2,
            arg3,
            arg4,
            arg5,
            arg6);

        // The out parameters should have been filled in by the abi in vtl1 based on the result from
        // the vtl1 version of the function
        VERIFY_IS_TRUE(CompareTestStruct1(arg1, expect_val1));
        VERIFY_IS_TRUE(CompareTestStruct2(arg2, expect_val2));
        VERIFY_IS_TRUE(CompareTestStruct3(arg3, expect_val3));
        VERIFY_IS_TRUE(std::equal(arg4.begin(), arg4.end(), arg4_expected.begin(), CompareTestStruct1));
        VERIFY_IS_TRUE(std::equal(arg5.begin(), arg5.end(), arg5_expected.begin(), CompareTestStruct2));
        VERIFY_IS_TRUE(std::equal(arg6.begin(), arg6.end(), arg6_expected.begin(), CompareTestStruct3));
    }

    TEST_METHOD(PassingStringTypes_To_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        std::string arg1 = "test";
        std::string arg2 = "test2";
        std::string arg3 {};
        std::vector<std::string> arg4_expected(5, "test4");
        std::vector<std::string> arg4 = arg4_expected;
        std::vector<std::string> arg5_expected(5, "test5 was updated");
        std::vector<std::string> arg5(5, "test5");
        std::vector<std::string> arg6_expected(5, "test6 was returned as out");

        std::vector<std::string> arg6 {};

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        auto result = generated_enclave_class.PassingStringTypes_To_Enclave(
             arg1,
            arg2,
            arg3,
            arg4,
            arg5,
            arg6);

        // The out parameters should have been filled in by the abi in vtl1 based on the result from
        // the vtl1 version of the function
        VERIFY_ARE_EQUAL("return result", result);
        VERIFY_ARE_EQUAL("test", arg1);
        VERIFY_ARE_EQUAL("test2 updated", arg2);
        VERIFY_ARE_EQUAL("test3 returned", arg3);
        VERIFY_IS_TRUE(std::equal(arg4.begin(), arg4.end(), arg4_expected.begin()));
        VERIFY_IS_TRUE(std::equal(arg5.begin(), arg5.end(), arg5_expected.begin()));
        VERIFY_IS_TRUE(std::equal(arg6.begin(), arg6.end(), arg6_expected.begin()));
    }

    TEST_METHOD(PassingWStringTypes_To_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        std::wstring arg1 = L"test";
        std::wstring arg2 = L"test2";
        std::wstring arg3 {};
        std::vector<std::wstring> arg4_expected(5, L"test4");
        std::vector<std::wstring> arg4 = arg4_expected;
        std::vector<std::wstring> arg5_expected(5, L"test5 was updated");
        std::vector<std::wstring> arg5(5, L"test5");
        std::vector<std::wstring> arg6_expected(5, L"test6 was returned as out");

        std::vector<std::wstring> arg6 {};

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        auto result = generated_enclave_class.PassingWStringTypes_To_Enclave(
             arg1,
            arg2,
            arg3,
            arg4,
            arg5,
            arg6);

        // The out parameters should have been filled in by the abi in vtl1 based on the result from
        // the vtl1 version of the function
        VERIFY_ARE_EQUAL(L"return result", result);
        VERIFY_ARE_EQUAL(L"test", arg1);
        VERIFY_ARE_EQUAL(L"test2 updated", arg2);
        VERIFY_ARE_EQUAL(L"test3 returned", arg3);
        VERIFY_IS_TRUE(std::equal(arg4.begin(), arg4.end(), arg4_expected.begin()));
        VERIFY_IS_TRUE(std::equal(arg5.begin(), arg5.end(), arg5_expected.begin()));
        VERIFY_IS_TRUE(std::equal(arg6.begin(), arg6.end(), arg6_expected.begin()));
    }

    TEST_METHOD(PassingArrayTypes_To_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
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
        auto result = generated_enclave_class.PassingArrayTypes_To_Enclave(
             arg1,
            arg2,
            arg3,
            arg4,
            arg5);

        // The out parameters should have been filled in by the abi in vtl1 based on the result from
        // the vtl1 version of the function
        VERIFY_IS_TRUE(CompareNestedStructWithArray(result, nested_array_result));
        VERIFY_IS_TRUE(std::equal(arg1.begin(), arg1.end(), arg1_expected.begin(), CompareTestStruct1));
        VERIFY_IS_TRUE(std::equal(arg2.begin(), arg2.end(), arg2_expected.begin()));
        VERIFY_IS_TRUE(std::equal(arg3.begin(), arg3.end(), arg3_expected.begin()));
        VERIFY_IS_TRUE(std::equal(arg4.begin(), arg4.end(), arg4_expected.begin(), CompareTestStruct2));
        VERIFY_IS_TRUE(std::equal(arg5.begin(), arg5.end(), arg5_expected.begin(), CompareTestStruct3));

    }

    #pragma endregion // End of HostApp to Enclave Tests

    #pragma region Enclave to HostApp Tests

    // Start of Enclave -> HostApp tests.
    // Test call backs. Note the actual testing of parameters is done in the vtl1 function that we call
    // below, since Taef isnt available for the enclave. A return value of S_OK means the test succeeded.
    // Anything else means failure.

    TEST_METHOD(Start_TestPassingPrimitivesAsValues_To_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.Start_TestPassingPrimitivesAsValues_To_HostApp_Callback_Test());
    }

    TEST_METHOD(Start_TestPassingPrimitivesAsInPointers_To_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.Start_TestPassingPrimitivesAsInPointers_To_HostApp_Callback_Test());
    }

    TEST_METHOD(Start_TestPassingPrimitivesAsInOutPointers_To_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.Start_TestPassingPrimitivesAsInOutPointers_To_HostApp_Callback_Test());
    }

    TEST_METHOD(Start_TestPassingPrimitivesAsOutPointers_To_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.Start_TestPassingPrimitivesAsOutPointers_To_HostApp_Callback_Test());
    }

    TEST_METHOD(Start_ReturnInt8ValPtr_From_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.Start_ReturnInt8ValPtr_From_HostApp_Callback_Test());
    }

    TEST_METHOD(Start_ReturnUint64Val_From_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.Start_ReturnUint64Val_From_HostApp_Callback_Test());
    }

    TEST_METHOD(Start_ReturnStructWithValues_From_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.Start_ReturnStructWithValues_From_HostApp_Callback_Test());
    }

    TEST_METHOD(Start_ComplexPassingofTypes_To_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.Start_ComplexPassingofTypes_To_HostApp_Callback_Test());
    }

    TEST_METHOD(Start_ReturnObjectInVector_From_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.Start_ReturnObjectInVector_From_HostApp_Callback_Test());
    }

    TEST_METHOD(Start_PassingPrimitivesInVector_To_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.Start_PassingPrimitivesInVector_To_HostApp_Callback_Test());
    }

    TEST_METHOD(Start_ComplexPassingofTypesWithVectors_To_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.Start_ComplexPassingofTypesWithVectors_To_HostApp_Callback_Test());
    }

    TEST_METHOD(Start_PassingStringTypes_To_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.Start_PassingStringTypes_To_HostApp_Callback_Test());
    }

    TEST_METHOD(Start_PassingWStringTypes_To_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.Start_PassingWStringTypes_To_HostApp_Callback_Test());
    }

    TEST_METHOD(Start_PassingArrayTypes_To_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        // Note: Hresult is returned by vtl1, and copied to vtl0 then returned to this function.
        VERIFY_SUCCEEDED(generated_enclave_class.Start_PassingArrayTypes_To_HostApp_Callback_Test());
    }

    #pragma endregion // Enclave to HostApp tests happen in vtl1
};
