// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifdef __ENCLAVE_PROJECT__
#include <VbsEnclave\Enclave\Implementations.h>
#else
#include <VbsEnclave\HostApp\Stubs.h>
#include <windows.h> 
#endif

#include <wil\result_macros.h>
#include <wil\resource.h>
#include <vector>
#undef max
#include <numeric>
#include <limits>
#include <algorithm>

constexpr std::uint32_t c_data_size = 5;
constexpr std::uint32_t c_arbitrary_size_1 = 5;
constexpr size_t c_arbitrary_size_2 = 2;

template <typename T>
inline std::vector<T> CreateVector(size_t count)
{
    std::vector<T> vector(count);
    
    if constexpr (std::is_arithmetic_v<T>)
    {
        std::iota(vector.begin(), vector.end(), 0);
    }
    else if constexpr (std::is_same_v<T, DecimalEnum>)
    {
        std::fill_n(vector.begin(), vector.size(), DecimalEnum::Deci_val3);
    }
    else if constexpr (std::is_same_v<T, HexEnum>)
    {
        std::fill_n(vector.begin(), vector.size(), HexEnum::Hex_val3);
    }

    return vector;
}

inline std::unique_ptr<bool[]> CreateBoolReturnPtr( size_t size)
{
    auto bool_array = std::make_unique<bool[]>(size);
    std::fill(bool_array.get(), bool_array.get() + size, true);
    size_t arr_size_in_bytes = sizeof(bool) * size;
    return bool_array;
}

constexpr std::array<std::int8_t, c_arbitrary_size_1> c_int8_array = {5,5,5,5,5};
constexpr std::array<std::int16_t, c_arbitrary_size_2> c_int16_array = {6,6};
constexpr std::array<std::int32_t, c_arbitrary_size_1> c_int32_array = {7,7,7,7,7};
constexpr std::array<std::uint8_t, c_arbitrary_size_1> c_uint8_array = {5,5,5,5,5};
constexpr std::array<std::uint16_t, c_arbitrary_size_2> c_uint16_array = {6,6};
constexpr std::array<std::uint32_t, c_arbitrary_size_1> c_uint32_array = {7,7,7,7,7};

// This is just for testing. The expectation is that both pointers should point to valid memory
// and pointer to the same amount of data.
template <typename T>
HRESULT CompareArrays(const T* arr1, const T* arr2, size_t size)
{
    for (std::size_t i = 0; i < size; ++i)
    {
       
        RETURN_HR_IF(E_INVALIDARG, arr1[i] != arr2[i]);
    }

    return S_OK;
}

inline StructWithNoPointers CreateStructWithNoPointers()
{
    return {
        true,                                      // bool_val
        std::numeric_limits<int8_t>::max(),        // int8_val
        std::numeric_limits<int16_t>::max(),       // int16_val
        std::numeric_limits<int32_t>::max(),       // int32_val
        std::numeric_limits<int64_t>::max(),       // int64_val
        std::numeric_limits<uint8_t>::max(),       // uint8_val
        std::numeric_limits<uint16_t>::max(),      // uint16_val
        std::numeric_limits<uint32_t>::max(),      // uint32_val
        std::numeric_limits<uint64_t>::max(),      // uint64_val
        Hex_val3,                                  // hex_val (0x03)
        Deci_val2,                                 // deci_val (1)
        { std::numeric_limits<int64_t>::max() },   // nested_struct_val.value_in_nested_struct

        S_OK                                       // result (HRESULT)
    };
}

inline bool CompareStructWithNoPointers(const StructWithNoPointers& a, const StructWithNoPointers& b)
{
    // Compare all fields of the struct

    if (a.bool_val != b.bool_val) 
    {
        return false;
    }
    if (a.int8_val != b.int8_val) 
    {
        return false;
    }
    if (a.int16_val != b.int16_val) 
    {
        return false;
    }
    if (a.int32_val != b.int32_val) 
    {
        return false;
    }
    if (a.int64_val != b.int64_val) 
    {
        return false;
    }
    if (a.uint8_val != b.uint8_val) 
    {
        return false;
    }
    if (a.uint16_val != b.uint16_val) 
    {
        return false;
    }
    if (a.uint32_val != b.uint32_val) 
    {
        return false;
    }
    if (a.uint64_val != b.uint64_val) 
    {
        return false;
    }
    if (a.hex_val != b.hex_val) 
    {
        return false;
    }
    if (a.deci_val != b.deci_val) 
    {
        return false;
    }
    if (a.nested_struct_val.value_in_nested_struct != b.nested_struct_val.value_in_nested_struct) 
    {
        return false;
    }
    if (a.result != b.result) 
    {
        return false;
    }

    return true;  // All fields are equal
}
