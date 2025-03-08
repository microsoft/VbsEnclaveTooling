// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once
#include <windows.h> 
#include <enclaveapi.h>
#include <wil\result_macros.h>
#include <wil\resource.h>
#include <WexTestClass.h>


template <typename T>
inline void VerifyNumericArray(T* data, size_t size)
{
    VERIFY_IS_NOT_NULL(data);
    for (T i = 0; i < size; ++i)
    {
        VERIFY_ARE_EQUAL(data[i], i);
    }
}
template <typename T>
inline void VerifyContainsSameValuesArray(T* data, size_t size, T value)
{
    VERIFY_IS_NOT_NULL(data);
    for (size_t i = 0; i < size; ++i)
    {
        VERIFY_ARE_EQUAL(data[i], value);
    }
}

template <typename T>
inline void VerifyContainsSameValuesArray(const T* data, size_t size, T value)
{
    VERIFY_IS_NOT_NULL(data);
    for (size_t i = 0; i < size; ++i)
    {
        VERIFY_ARE_EQUAL(data[i], value);
    }
}

