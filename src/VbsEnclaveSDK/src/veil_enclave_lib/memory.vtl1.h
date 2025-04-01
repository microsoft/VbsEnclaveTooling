// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <array>
#include <string>

#include "wil/stl.h"

#include "..\veil_any_inc\veil_arguments.any.h"

#include "vtl0_functions.vtl1.h"

namespace veil::vtl1::memory
{
    // todo: stand-in type until tooling+marshalling code is online
    template <typename T>
    struct unique_vtl0_ptr
    {
        unique_vtl0_ptr() noexcept = default;

        unique_vtl0_ptr(T* memory) noexcept
            : m_memory(memory)
        {}

        ~unique_vtl0_ptr() noexcept
        {
            if (m_memory)
            {
                veil::vtl1::vtl0_functions::free(m_memory);
            }
        }

        // Delete copy
        unique_vtl0_ptr(const unique_vtl0_ptr&) = delete;
        unique_vtl0_ptr& operator=(const unique_vtl0_ptr&) = delete;

        // Allow move
        unique_vtl0_ptr(unique_vtl0_ptr&& other) = default;
        unique_vtl0_ptr& operator=(unique_vtl0_ptr&& other) = default;

        [[nodiscard]] constexpr T* operator->() const noexcept
        {
            return m_memory;
        }

        [[nodiscard]] constexpr T* get() const noexcept
        {
            return m_memory;
        }

        unique_vtl0_ptr<T> reset(unique_vtl0_ptr<T>&& other)
        {
            return std::exchange(m_memory, std::move(other));
        }

        T* release()
        {
            return std::exchange(m_memory, nullptr);
        }

    private:
        T* m_memory{};
    };

    // todo: stand-in type until tooling+marshalling code is online
    template <typename T>
    struct unique_vtl0_array_ptr
    {
        unique_vtl0_array_ptr() noexcept = default;

        unique_vtl0_array_ptr(T* memory, size_t size) noexcept
            : m_memory(memory), m_size(size)
        {
        }

        // Delete copy
        unique_vtl0_array_ptr(const unique_vtl0_array_ptr&) = delete;
        unique_vtl0_array_ptr& operator=(const unique_vtl0_array_ptr&) = delete;

        // Allow move
        unique_vtl0_array_ptr(unique_vtl0_array_ptr&& other) = default;
        unique_vtl0_array_ptr& operator=(unique_vtl0_array_ptr&& other) = default;

        [[nodiscard]] constexpr T* operator->() const noexcept
        {
            return m_memory;
        }

        [[nodiscard]] constexpr T* get() const noexcept
        {
            return m_memory;
        }

        unique_vtl0_array_ptr<T> reset(unique_vtl0_array_ptr<T>&& other)
        {
            return std::exchange(*this, std::move(other));
        }

        T* release()
        {
            return std::exchange(m_memory, nullptr);
        }

        [[nodiscard]] constexpr size_t size() const noexcept
        {
            return m_size;
        }

        // Implicit conversion operator to std::span
        operator std::span<uint8_t const>() const
        {
            return {get(), size()};
        }

        operator std::span<uint8_t>()
        {
            return {get(), size()};
        }

    private:
        T* m_memory{};
        size_t m_size{};
    };

    template <typename T>
    inline unique_vtl0_ptr<T> allocate_vtl0()
    {
        auto allocation = veil::vtl1::vtl0_functions::malloc(sizeof(T));
        THROW_IF_NULL_ALLOC(allocation.m_dangerous);
        return {reinterpret_cast<T*>(allocation.m_dangerous)};
    }

    template <typename T>
    inline unique_vtl0_array_ptr<T> allocate_vtl0_array(size_t count)
    {
        auto allocation = veil::vtl1::vtl0_functions::malloc(sizeof(T) * count);
        THROW_IF_NULL_ALLOC(allocation.m_dangerous);
        return { reinterpret_cast<T*>(allocation.m_dangerous), count };
    }

    [[nodiscard]] inline unique_vtl0_array_ptr<uint8_t> copy_to_vtl0_array(std::span<uint8_t const> src)
    {
        auto buffer = veil::vtl1::memory::allocate_vtl0_array<uint8_t>(src.size());
        memcpy(buffer.get(), src.data(), buffer.size());
        return buffer;
    }

    [[nodiscard]] inline veil::any::args::data_blob as_data_blob(std::span<uint8_t const> src)
    {
        veil::any::args::data_blob dst;
        dst.data = const_cast<uint8_t*>(src.data());
        dst.size = src.size();
        return dst;
    }

    [[nodiscard]] inline unique_vtl0_array_ptr<uint8_t> copy_to_vtl0_data_blob(veil::any::args::data_blob* dst, std::span<uint8_t const> src)
    {
        auto buffer = veil::vtl1::memory::allocate_vtl0_array<uint8_t>(src.size());
        memcpy(buffer.get(), src.data(), buffer.size());
        dst->data = buffer.get();
        dst->size = buffer.size();
        return buffer;
    }
}
