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

// TODO: when deep copy support is added for structs, the developer won't need
// to allocate vtl0 memory directly from within vtl1 for internal
// pointers inside structs. The ABI layer should be able to create
// the vtl0 memory, copy the vtl1 data into it and return it to vtl0.
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
    _In_ const std::uint32_t* uint32_val,
    _In_ const size_t abitrary_size_1,
    _In_ const size_t abitrary_size_2)
{
    // Confirm vtl0 parameters were correctly copied to vtl1 memory.
    THROW_IF_FAILED(CompareArrays(uint8_val, c_uint8_array.data(), c_uint8_array.size()));
    THROW_IF_FAILED(CompareArrays(uint16_val, c_uint16_array.data(), c_uint16_array.size()));
    THROW_IF_FAILED(CompareArrays(uint32_val, c_uint32_array.data(), c_uint32_array.size()));
    THROW_HR_IF(E_INVALIDARG, abitrary_size_1 != c_arbitrary_size_1);
    THROW_HR_IF(E_INVALIDARG, abitrary_size_2 != c_arbitrary_size_2);

    return S_OK;
}

HRESULT VTL1_Declarations::TestPassingPrimitivesAsInOutPointers_To_Enclave(
    _Inout_ std::int8_t* int8_val,
    _Inout_ std::int16_t* int16_val,
    _Inout_ std::int32_t* int32_val_ptr, 
    _In_ const size_t abitrary_size_1,
    _In_ const size_t abitrary_size_2)
{
    // Confirm vtl0 parameters were correctly copied to vtl1 memory.
    THROW_IF_FAILED(CompareArrays(int8_val, c_int8_array.data(), c_int8_array.size()));
    THROW_IF_FAILED(CompareArrays(int16_val, c_int16_array.data(), c_int16_array.size()));
    THROW_HR_IF(E_INVALIDARG, c_expected_int32_val != *int32_val_ptr);
    THROW_HR_IF(E_INVALIDARG, abitrary_size_1 != c_arbitrary_size_1);
    THROW_HR_IF(E_INVALIDARG, abitrary_size_2 != c_arbitrary_size_2);

    // Copy data into the in-out buffers. Abi will copy these into vtl0 memory and return
    // them to caller.
    auto int8_data = CreateVector<std::int8_t>(abitrary_size_1);
    memcpy(int8_val, int8_data.data(), int8_data.size() * sizeof(std::int8_t));

    auto int16_data = CreateVector<std::int16_t>(abitrary_size_2);
    memcpy(int16_val, int16_data.data(), int16_data.size() * sizeof(std::int16_t));

    *int32_val_ptr = std::numeric_limits<std::int32_t>::max();

    return S_OK;
}

HRESULT VTL1_Declarations::TestPassingPrimitivesAsOutPointers_To_Enclave(
    _Out_ bool** bool_val,
    _Out_ DecimalEnum** enum_val,
    _Out_ std::uint64_t** uint64_val,
    _In_  const size_t abitrary_size_1,
    _In_  const size_t abitrary_size_2)
{
    *bool_val = nullptr;
    *enum_val = nullptr;
    *uint64_val = nullptr;

    auto bool_data = CreateBoolReturnPtr(abitrary_size_1);
    size_t size_for_bools = sizeof(bool) * abitrary_size_1;

    // Make sure we create out parameters inner pointer. Abi will free, but developer must
    // free the vtl0 copy of this out parameter when it returns to original caller
    *bool_val = reinterpret_cast<bool*>(AllocateMemory(sizeof(StructWithNoPointers)));
    memcpy(*bool_val, bool_data.get(), size_for_bools);
    auto enums = CreateVector<DecimalEnum>(abitrary_size_2);
    size_t size_for_enums = sizeof(DecimalEnum) * abitrary_size_2;

    // Make sure we create out parameters inner pointer. Abi will free, but developer must
    // free the vtl0 copy of this out parameter when it returns to original caller
    *enum_val = reinterpret_cast<DecimalEnum*>(AllocateMemory(sizeof(StructWithNoPointers)));
    memcpy(*enum_val, enums.data(), size_for_enums);

    // Make sure we create out parameters inner pointer. Abi will free, but developer must
    // free the vtl0 copy of this out parameter when it returns to original caller
    *uint64_val = reinterpret_cast<std::uint64_t*>(AllocateMemory(sizeof(StructWithNoPointers)));
    auto uint64s = CreateVector<std::uint64_t>(abitrary_size_1);
    size_t size_for_uint64s = sizeof(std::uint64_t) * abitrary_size_1;

    memcpy(*uint64_val, uint64s.data(), size_for_uint64s);
    return S_OK;
}

StructWithNoPointers VTL1_Declarations::ComplexPassingofTypes_To_Enclave(
    _In_ const StructWithNoPointers& arg1,
    _Inout_ StructWithNoPointers& arg2,
    _Out_ StructWithNoPointers** arg3,
    _Out_ StructWithNoPointers& arg4,
    _Out_ std::uint64_t** uint64_val,
    _In_ const size_t abitrary_size_1)
{
    *arg3 = nullptr;
    *uint64_val = nullptr;

    auto struct_to_return = CreateStructWithNoPointers();
    THROW_HR_IF(E_INVALIDARG, !CompareStructWithNoPointers(arg1, struct_to_return));
    arg2 = struct_to_return;

    // Make sure we create out parameters inner pointer. Abi will free, but developer must
    // free the vtl0 copy of this out parameter when it returns to original caller
    *arg3 = reinterpret_cast<StructWithNoPointers*>(AllocateMemory(sizeof(StructWithNoPointers)));
    memcpy(*arg3, &struct_to_return, sizeof(StructWithNoPointers));
    memcpy(&arg4, &struct_to_return, sizeof(StructWithNoPointers));

    std::uint64_t uint64_max = std::numeric_limits<std::uint64_t>::max();

    // Make sure we create out parameters inner pointer. Abi will free, but developer must
    // free the vtl0 copy of this out parameter when it returns to original caller
    *uint64_val = reinterpret_cast<std::uint64_t*>(AllocateMemory(abitrary_size_1));
    memcpy(*uint64_val, &uint64_max, abitrary_size_1);

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
    THROW_HR_IF(E_INVALIDARG, result.size_field != (sizeof(std::int8_t) * c_data_size));
    THROW_IF_FAILED(VerifyNumericArray(result.int8_val, result.size_field));

    // Make sure the vtl0 memory is freed.
    // TODO: when deep copy support is added, we shouldn't need to free the vtl0 memory since
    // all callbacks should only return vtl1 memory as the ABi will copy the vtl0 memory returned
    // by the callback into vtl1 memory and return the copy instead. So in the end this will
    // use the wil::unique_process_heap_ptr to free vtl1 memory instead of vtl0_memory_ptr.
    vtl0_memory_ptr<std::int8_t> int8_ptr(result.int8_val);

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
    std::uint8_t uint8_val[c_arbitrary_size_1];
    std::copy(c_uint8_array.begin(), c_uint8_array.end(), uint8_val);
    std::uint16_t uint16_val[c_arbitrary_size_2];
    std::copy(c_uint16_array.begin(), c_uint16_array.end(), uint16_val);
    std::uint32_t uint32_val[c_arbitrary_size_1];
    std::copy(c_uint32_array.begin(), c_uint32_array.end(), uint32_val);

    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    THROW_IF_FAILED(VTL0_Callbacks::TestPassingPrimitivesAsInPointers_To_HostApp_callback(
        uint8_val,
        uint16_val,
        uint32_val,
        c_non_const_arbitrary_size_1,
        c_non_const_arbitrary_size_2));

    return S_OK;
}
EnclaveString TrustedExample(_Out_ std::int8_t** int8_array, _In_ size_t int8_array_size)
{
    *int8_array = nullptr;
    int8_array_size = 10;
    size_t array_size_in_bytes = sizeof(std::int8_t) * int8_array_size;
    std::vector<std::int8_t> int8_vector(int8_array_size);
    std::iota(int8_vector.begin(), int8_vector.end(), 0);

    // Abi provided function to allocate vtl1/vtl0 memory depending on which side of the trust boundary its called.
    // in this case it will allocate vtl1 memory.
    // The abi layer is responsible for freeing this memory and coping it into the vtl0 memory of the caller.
    *int8_array = reinterpret_cast<std::int8_t*>(AllocateMemory(array_size_in_bytes));
    memcpy_s(*int8_array, array_size_in_bytes, int8_vector.data(), array_size_in_bytes);

    // TODO: when deep copy of internal structs support is added, we shouldn't need to allocate vtl0 memory
    // directly, and should be able to allocate only vtl1 memory and have the abi layer take care of the conversion 
    // for us. So, the developer shouldn't need to use the 'EnclaveCopyOutOfEnclave' Win32 api directly.

    std::string return_from_enclave = "We returned this string from the enclave.";
    char* ret_char_array = nullptr;
    size_t str_size_in_bytes = sizeof(char) * return_from_enclave.size();

    // The abi layer catches exceptions, but the developer can catch them too.
    THROW_IF_FAILED(AllocateVtl0Memory(&ret_char_array, str_size_in_bytes));
    THROW_IF_NULL_ALLOC(ret_char_array);

    // free memory if the line below throws. vtl0_memory_ptr smart pointer is provided by the abi.
    vtl0_memory_ptr<char> str_mem_ptr {ret_char_array};
    THROW_IF_FAILED(EnclaveCopyOutOfEnclave(ret_char_array, return_from_enclave.data(), str_size_in_bytes));
    str_mem_ptr.release(); // vtl0 caller to free

    // Abi layer will handle copying the struct (not data of internal pointers, see note about deep copy support above)
    // to vtl0 memory.
    return EnclaveString {ret_char_array, str_size_in_bytes};

}
HRESULT VTL1_Declarations::Start_TestPassingPrimitivesAsInOutPointers_To_HostApp_Callback_Test()
{
    std::int8_t int8_val[c_arbitrary_size_1];
    std::copy(c_int8_array.begin(), c_int8_array.end(), int8_val);
    std::int16_t int16_val[c_arbitrary_size_2];
    std::copy(c_int16_array.begin(), c_int16_array.end(), int16_val);
    std::int32_t int32_val = c_expected_int32_val;
    std::int32_t* int32_val_ptr = &int32_val;

    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    THROW_IF_FAILED(VTL0_Callbacks::TestPassingPrimitivesAsInOutPointers_To_HostApp_callback(
        int8_val,
        int16_val,
        int32_val_ptr,
        c_non_const_arbitrary_size_1,
        c_non_const_arbitrary_size_2));

    // The in-out parameters should have been filled in by the abi in vtl1 based on the result from
    // the vtl0 version of the function
    THROW_IF_FAILED(VerifyNumericArray(int8_val, c_arbitrary_size_1));
    THROW_IF_FAILED(VerifyNumericArray(int16_val, c_arbitrary_size_2));
    THROW_HR_IF(E_INVALIDARG, std::numeric_limits<std::int32_t>::max() != *int32_val_ptr);

    return S_OK;
}
HRESULT VTL1_Declarations::Start_TestPassingPrimitivesAsOutPointers_To_HostApp_Callback_Test()
{
    bool* bool_val = nullptr;
    DecimalEnum* enum_val = nullptr;
    std::uint64_t* uint64_val = nullptr;

    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    THROW_IF_FAILED(VTL0_Callbacks::TestPassingPrimitivesAsOutPointers_To_HostApp_callback(
        &bool_val,
        &enum_val,
        &uint64_val,
        c_non_const_arbitrary_size_1,
        c_non_const_arbitrary_size_2));

    // Make sure the vtl1 allocated memory is freed when function goes out of scope
    wil::unique_process_heap_ptr<bool> bool_val_ptr {bool_val};
    wil::unique_process_heap_ptr<DecimalEnum> enum_val_ptr {enum_val};
    wil::unique_process_heap_ptr<std::uint64_t> uint64_val_ptr {uint64_val};

    // The out parameters should have been filled in by the abi in vtl1 based on the result from
    // the vtl0 version of the function
    THROW_IF_FAILED(VerifyContainsSameValuesArray(bool_val, c_arbitrary_size_1, true));
    THROW_IF_FAILED(VerifyContainsSameValuesArray(enum_val, c_arbitrary_size_2, DecimalEnum::Deci_val3));
    THROW_IF_FAILED(VerifyNumericArray(uint64_val, c_arbitrary_size_1));

    return S_OK;
}

HRESULT VTL1_Declarations::Start_ComplexPassingofTypes_To_HostApp_Callback_Test()
{
    auto expected_struct_values = CreateStructWithNoPointers();
    StructWithNoPointers struct_no_pointers_1 = expected_struct_values;
    StructWithNoPointers struct_no_pointers_2 {};
    StructWithNoPointers* struct_no_pointers_3;
    StructWithNoPointers struct_no_pointers_4 {};
    std::uint64_t* uint64_val = nullptr;
    size_t size_for_uint64_val = sizeof(std::uint64_t);

    // Note: Hresult is returned by vtl0, and copied to vtl1 then returned to this function.
    auto result = VTL0_Callbacks::ComplexPassingofTypes_To_HostApp_callback(
        struct_no_pointers_1,
        struct_no_pointers_2,
        &struct_no_pointers_3,
        struct_no_pointers_4,
        &uint64_val,
        size_for_uint64_val);

    // Make sure the vtl1 allocated memory is freed when function goes out of scope
    wil::unique_process_heap_ptr<StructWithNoPointers> struct_no_pointers_3_ptr {struct_no_pointers_3};
    wil::unique_process_heap_ptr<std::uint64_t> uint64_val_ptr {uint64_val};

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
