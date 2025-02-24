// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <span>
#include <string>
#include <string_view>

#include <wil/resource.h>

namespace veil::any
{
    template <typename T>
    constexpr T math_max(const T& a, const T& b)
    {
        if (a > b)
        {
            return a;
        }
        return b;
    }

    template <typename BufferT>
    inline void add_buffer_bytes(BufferT& storage, std::span<uint8_t const> data)
    {
        storage.insert(storage.end(), data.begin(), data.end());
    }

    struct buffer_reader
    {
        std::span<UCHAR const> data;

        size_t remaining() const
        {
            return data.size();
        }

        std::span<UCHAR const> read(size_t size)
        {
            THROW_HR_IF(E_INVALIDARG, size > data.size());
            auto result = data.first(size);
            data = data.subspan(size);
            return result;
        }

        std::span<UCHAR const> read_remaining()
        {
            return std::exchange(data, {});
        }

        template <typename T>
        T const* read()
        {
            return reinterpret_cast<T const*>(read(sizeof(T)).data());
        }
    };
}
