// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifdef __ENCLAVE_PROJECT__
#include <VbsEnclave\Enclave\Implementation\Types.h>
#else
#include <VbsEnclave\HostApp\Implementation\Types.h>
#endif

#include <wil\result_macros.h>
#include <wil\resource.h>
#include <vector>
#undef max
#include <numeric>
#include <limits>
#include <algorithm>
#include <functional>

using namespace VbsEnclave::Types;

constexpr size_t c_data_size = 5;
constexpr size_t c_arbitrary_size_1 = 5;
constexpr size_t c_arbitrary_size_2 = 2;
static size_t c_non_const_arbitrary_size_1 = 5;
static size_t c_non_const_arbitrary_size_2 = 2;
static std::uint32_t c_expected_int32_val = 90;

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

inline TestStruct1 CreateTestStruct1()
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
        {1, 2, 3, 4, 5},
        S_OK                                       // result (HRESULT)
    };
}

inline bool CompareTestStruct1(TestStruct1 a, TestStruct1 b)
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

    if (a.array1.size() == b.array1.size())
    {
        if (!std::equal(a.array1.begin(), a.array1.end(), b.array1.begin()))
        {
            return false;
        }
    }
    else
    {
        return false;
    }

    if (a.result != b.result)
    {
        return false;
    }

    return true;  // All fields are equal
}

inline bool CompareNestedStructWithArray(NestedStructWithArray& lhs, NestedStructWithArray& rhs)
{
    return lhs.array1 == rhs.array1;
}

inline bool CompareNestedStructWithVectors(NestedStructWithVectors& lhs, NestedStructWithVectors& rhs)
{
    if (lhs.value_in_nested_struct.size() != rhs.value_in_nested_struct.size())
        return false;

    for (size_t i = 0; i < lhs.value_in_nested_struct.size(); ++i)
    {
        if (!CompareNestedStructWithArray(lhs.value_in_nested_struct[i], rhs.value_in_nested_struct[i]))
            return false;
    }

    return true;
}

inline bool CompareTestStruct2(TestStruct2& lhs, TestStruct2& rhs)
{
    return CompareNestedStructWithArray(lhs.field1, rhs.field1) &&
        CompareNestedStructWithVectors(lhs.field2, rhs.field2);
}

inline NestedStructWithArray CreateNestedStructWithArray()
{
    NestedStructWithArray result;

    result.array1 = {1,2,3,4,5,6,7,8,9,10};

    return result;
}

inline TestStruct2 CreateTestStruct2()
{
    TestStruct2 result;

    result.field1.array1 = {1,2,3,4,5,6,7,8,9,10};
    result.field2.value_in_nested_struct.push_back(CreateNestedStructWithArray());

    return result;
}

inline TestStruct3 CreateTestStruct3()
{
    TestStruct3 result;

    result.field1 = CreateTestStruct1();
    result.field2 = CreateTestStruct2();
    TestStruct2 ts2 = CreateTestStruct2();
    result.field3.push_back(ts2);

    for (size_t i = 0; i < value2; ++i)
    {
        result.field4[i] = CreateTestStruct1();
    }

    result.field5.field1.array1 = {100, 200, 300, 400, 500};
    result.field5.field2.value_in_nested_struct.push_back(CreateNestedStructWithArray());

    return result;
}

inline bool compareNestedStructWithArray(NestedStructWithArray& lhs, NestedStructWithArray& rhs)
{
    if (lhs.array1.size() != rhs.array1.size())
    {
        return false;
    }

    return std::equal(lhs.array1.begin(), lhs.array1.end(), rhs.array1.end());
}

inline bool compareNestedStructWithVectors(NestedStructWithVectors& lhs, NestedStructWithVectors& rhs)
{
    if (lhs.value_in_nested_struct.size() != rhs.value_in_nested_struct.size())
    {
        return false;
    }

    return std::equal(lhs.value_in_nested_struct.begin(), lhs.value_in_nested_struct.end(), rhs.value_in_nested_struct.end(), compareNestedStructWithArray);
}

inline bool CompareTestStruct3(TestStruct3& lhs, TestStruct3& rhs)
{
    if (!CompareTestStruct1(lhs.field1, rhs.field1)) return false;
    if (!CompareTestStruct2(lhs.field2, rhs.field2)) return false;
    if (lhs.field3.size() != rhs.field3.size()) return false;

    for (size_t i = 0; i < lhs.field3.size(); ++i)
    {
        if (!CompareTestStruct2(lhs.field3[i], rhs.field3[i]))
        {
            return false;
        }
    }

    for (size_t i = 0; i < value2; ++i)
    {
        if (!CompareTestStruct1(lhs.field4[i], rhs.field4[i]))
        {
            return false;
        }
    }

    return CompareTestStruct2(lhs.field5, rhs.field5);
}

inline NestedStructWithPointers CreateNestedStructWithPointers()
{
    std::unique_ptr<std::int32_t> int32_ptr = std::make_unique<std::int32_t>(100);
    std::unique_ptr<DecimalEnum> enum_val_ptr = std::make_unique<DecimalEnum>(DecimalEnum::Deci_val3);
    std::unique_ptr<TestStruct1> test_struct_val_ptr = std::make_unique<TestStruct1>(CreateTestStruct1());
    return NestedStructWithPointers(std::move(int32_ptr), std::move(enum_val_ptr), std::move(test_struct_val_ptr));
}

template <typename T>
inline bool ComparePtrToPod(T* lhs_ptr, T* rhs_ptr)
{
    static_assert(std::is_standard_layout<T>::value && std::is_trivial<T>::value);

    if ((lhs_ptr && !rhs_ptr) || (!lhs_ptr && rhs_ptr))
    {
        return false;
    }

    if (lhs_ptr && rhs_ptr && (*lhs_ptr != *rhs_ptr))
    {
        return false;
    }

    return true;
}

template <typename T, typename FuncT>
inline bool ComparePtrToStruct(T* lhs_ptr, T* rhs_ptr, FuncT comparison_function)
{
    if ((lhs_ptr && !rhs_ptr) || (!lhs_ptr && rhs_ptr))
    {
        return false;
    }

    if (lhs_ptr && rhs_ptr)
    {
        return comparison_function(*lhs_ptr, *rhs_ptr);
    }

    return true;
}

inline bool CompareNestedStructWithPointers(const NestedStructWithPointers& lhs, const NestedStructWithPointers& rhs)
{
    // Compare all fields of the struct

    if (!ComparePtrToPod(lhs.int32_ptr.get(), rhs.int32_ptr.get()))
    {
        return false;
    }

    if (!ComparePtrToPod(lhs.deci_ptr.get(), rhs.deci_ptr.get()))
    {
        return false;
    }

    if (!ComparePtrToStruct(lhs.struct_ptr.get(), rhs.struct_ptr.get(), CompareTestStruct1))
    {
        return false;
    }

    return true;
}

inline StructWithPointers CreateStructWithPointers()
{
    return
    {
        std::make_unique<NestedStructWithPointers>(CreateNestedStructWithPointers())
    };
}

inline std::vector<StructWithPointers> c_struct_with_ptrs_vec_empty(c_arbitrary_size_2);

inline std::array<StructWithPointers, c_arbitrary_size_2> c_struct_with_ptrs_arr_initialize {
    CreateStructWithPointers(),
    CreateStructWithPointers()
};

inline bool CompareStructWithPointers(const StructWithPointers& lhs, const StructWithPointers& rhs)
{
    return ComparePtrToStruct(lhs.nested_struct_ptr.get(), rhs.nested_struct_ptr.get(), CompareNestedStructWithPointers);
}
