// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <array>
#include <string>

#include "wil/stl.h"

#include "vtl0_functions.vtl1.h"

namespace veil::vtl1::memory
{
    // todo: stand-in type until tooling+marshalling code is online
    template <typename T>
    struct unique_vtl0_ptr
    {
        unique_vtl0_ptr(T* memory) noexcept
            : m_memory(memory)
        {}

        ~unique_vtl0_ptr() noexcept
        {
            veil::vtl1::vtl0_functions::free(m_memory);
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

    private:
        T* m_memory;
    };

    template <typename T>
    inline unique_vtl0_ptr<T> allocate_vtl0()
    {
        auto allocation = veil::vtl1::vtl0_functions::malloc(sizeof(T));
        THROW_IF_NULL_ALLOC(allocation.m_dangerous);
        return {reinterpret_cast<T*>(allocation.m_dangerous)};
    }
}
