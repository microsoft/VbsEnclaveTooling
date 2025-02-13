// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <windows.h> 
#include <enclaveapi.h>
#include <wil\result_macros.h>
#include <wil\resource.h>
#include <WexTestClass.h>
#include "TestHelpers.h"

#include <VbsEnclave\HostApp\Stubs.h>

using namespace VbsEnclave::VTL0_Stubs;
using namespace WEX::Common;
using namespace WEX::TestExecution;

template <typename T>
void VerifyNumericArray(T* data, size_t size)
{
    VERIFY_IS_NOT_NULL(data);
    for (T i = 0; i < size; ++i)
    {
        VERIFY_ARE_EQUAL(data[i], i);
    }
}
template <typename T>
void VerifyContainsSameValuesArray(T* data, size_t size, T value)
{
    VERIFY_IS_NOT_NULL(data);
    for (size_t i = 0; i < size; ++i)
    {
        VERIFY_ARE_EQUAL(data[i], value);
    }
}

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
        Int8PtrAndSize result = generated_enclave_class.ReturnInt8ValPtr_From_Enclave();
        VERIFY_IS_NOT_NULL(result.int8_val);
        VERIFY_ARE_EQUAL(result.size_field, sizeof(std::int8_t) * c_data_size);
        VerifyNumericArray(result.int8_val, result.size_field);
        wil::unique_process_heap_ptr<std::int8_t> int8_ptr {result.int8_val};
    }

    TEST_METHOD(ReturnUint64Val_From_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        std::uint64_t result = generated_enclave_class.ReturnUint64Val_From_Enclave();
        VERIFY_ARE_EQUAL(result, std::numeric_limits<std::uint64_t>::max());
    }

    TEST_METHOD(ReturnStructWithValues_From_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        StructWithNoPointers result = generated_enclave_class.ReturnStructWithValues_From_Enclave();
        VERIFY_IS_TRUE(CompareStructWithNoPointers(result, CreateStructWithNoPointers()));
    }

    
    TEST_METHOD(TestPassingPrimitivesAsValues_To_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);

        VERIFY_SUCCEEDED(generated_enclave_class.TestPassingPrimitivesAsValues_To_Enclave(
            true,
            DecimalEnum::Deci_val2,
            std::numeric_limits<std::int8_t>::max()));
    }

    
    TEST_METHOD(TestPassingPrimitivesAsInPointers_To_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        std::uint8_t uint8_val[c_arbitrary_size_1];
        std::copy(c_uint8_array.begin(), c_uint8_array.end(), uint8_val);
        std::uint16_t uint16_val[c_arbitrary_size_2];
        std::copy(c_uint16_array.begin(), c_uint16_array.end(), uint16_val);
        std::uint32_t uint32_val[c_arbitrary_size_1];
        std::copy(c_uint32_array.begin(), c_uint32_array.end(), uint32_val);

        VERIFY_SUCCEEDED(generated_enclave_class.TestPassingPrimitivesAsInPointers_To_Enclave(
            uint8_val,
            uint16_val,
            uint32_val,
            c_arbitrary_size_1,
            c_arbitrary_size_2));
    }

    TEST_METHOD(TestPassingPrimitivesAsInOutPointers_To_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        std::int8_t int8_val[c_arbitrary_size_1];
        std::copy(c_int8_array.begin(), c_int8_array.end(), int8_val);
        std::int16_t int16_val[c_arbitrary_size_2];
        std::copy(c_int16_array.begin(), c_int16_array.end(), int16_val);
        std::int32_t int32_val[c_arbitrary_size_1];
        std::copy(c_int32_array.begin(), c_int32_array.end(), int32_val);

        VERIFY_SUCCEEDED(generated_enclave_class.TestPassingPrimitivesAsInOutPointers_To_Enclave(
            int8_val,
            int16_val,
            int32_val,
            c_arbitrary_size_1,
            c_arbitrary_size_2));

        VerifyNumericArray(int8_val, c_arbitrary_size_1);
        VerifyNumericArray(int16_val, c_arbitrary_size_2);
        VerifyNumericArray(int32_val, c_arbitrary_size_1);
    }

    TEST_METHOD(TestPassingPrimitivesAsOutPointers_To_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        bool* bool_val = nullptr;
        DecimalEnum* enum_val = nullptr;
        std::uint64_t* uint64_val = nullptr;
        VERIFY_SUCCEEDED(generated_enclave_class.TestPassingPrimitivesAsOutPointers_To_Enclave(
            &bool_val,
            &enum_val,
            &uint64_val,
            c_arbitrary_size_1,
            c_arbitrary_size_2));

        VerifyContainsSameValuesArray(bool_val, c_arbitrary_size_1, true);
        VerifyContainsSameValuesArray(enum_val, c_arbitrary_size_2, DecimalEnum::Deci_val3);
        VerifyNumericArray(uint64_val, c_arbitrary_size_1);
    }

    TEST_METHOD(ComplexPassingofTypes_To_Enclave_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        auto expected_struct_values = CreateStructWithNoPointers();
        StructWithNoPointers struct_no_pointers_1 = expected_struct_values;
        StructWithNoPointers struct_no_pointers_2 {};
        StructWithNoPointers* struct_no_pointers_3 = &struct_no_pointers_1;
        StructWithNoPointers struct_no_pointers_4 {};
        std::uint64_t* uint64_val = nullptr;
        size_t size_for_uint64_val = sizeof(std::uint64_t);
        auto result = generated_enclave_class.ComplexPassingofTypes_To_Enclave(
            struct_no_pointers_1,
            struct_no_pointers_2,
            &struct_no_pointers_3,
            struct_no_pointers_4,
            &uint64_val,
            size_for_uint64_val);

        VERIFY_IS_TRUE(CompareStructWithNoPointers(result, expected_struct_values));
        VERIFY_IS_TRUE(CompareStructWithNoPointers(struct_no_pointers_2, expected_struct_values));
        VERIFY_IS_NOT_NULL(struct_no_pointers_3);
        VERIFY_IS_TRUE(CompareStructWithNoPointers(*struct_no_pointers_3, expected_struct_values));
        VERIFY_IS_TRUE(CompareStructWithNoPointers(struct_no_pointers_4, expected_struct_values));
        VERIFY_IS_NOT_NULL(uint64_val);
        VERIFY_ARE_EQUAL(*uint64_val, std::numeric_limits<std::uint64_t>::max());
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
        VERIFY_SUCCEEDED(generated_enclave_class.Start_TestPassingPrimitivesAsValues_To_HostApp_Callback_Test());
    }
    TEST_METHOD(Start_TestPassingPrimitivesAsInPointers_To_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        VERIFY_SUCCEEDED(generated_enclave_class.Start_TestPassingPrimitivesAsInPointers_To_HostApp_Callback_Test());
    }
    TEST_METHOD(Start_TestPassingPrimitivesAsInOutPointers_To_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        VERIFY_SUCCEEDED(generated_enclave_class.Start_TestPassingPrimitivesAsInOutPointers_To_HostApp_Callback_Test());
    }
    TEST_METHOD(Start_TestPassingPrimitivesAsOutPointers_To_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        VERIFY_SUCCEEDED(generated_enclave_class.Start_TestPassingPrimitivesAsOutPointers_To_HostApp_Callback_Test());
    }
    TEST_METHOD(Start_ReturnInt8ValPtr_From_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        VERIFY_SUCCEEDED(generated_enclave_class.Start_ReturnInt8ValPtr_From_HostApp_Callback_Test());
    }
    TEST_METHOD(Start_ReturnUint64Val_From_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        VERIFY_SUCCEEDED(generated_enclave_class.Start_ReturnUint64Val_From_HostApp_Callback_Test());
    }
    TEST_METHOD(Start_ReturnStructWithValues_From_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        VERIFY_SUCCEEDED(generated_enclave_class.Start_ReturnStructWithValues_From_HostApp_Callback_Test());
    }
    TEST_METHOD(Start_ComplexPassingofTypes_To_HostApp_Callback_Test)
    {
        auto generated_enclave_class = TestEnclave(m_enclave);
        VERIFY_SUCCEEDED(generated_enclave_class.Start_ComplexPassingofTypes_To_HostApp_Callback_Test());
    }

    #pragma endregion // Enclave to HostApp tests happen in vtl1
};
