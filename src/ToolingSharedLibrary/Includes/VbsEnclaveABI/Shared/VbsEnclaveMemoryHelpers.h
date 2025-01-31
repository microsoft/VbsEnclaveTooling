// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <wil\result_macros.h>

namespace VbsEnclaveABI
{
    template <typename T>
    struct vtl0_ptr
    {
        // Memory should always be VTL0 memory. Class does not
        // own the memory the ptr points to.
        explicit vtl0_ptr(T* memory) noexcept
            : m_memory(memory)
        {
        }

 
        // Provide access to the underlying pointer for specific operations
        // Dangerous, so use sparingly.
        constexpr T* operator->() const noexcept
        {
            return m_memory;
        }

        // Provide access to the underlying pointer for specific operations
        // Dangerous, so use sparingly.
        T* get() const noexcept
        {
            return m_memory;
        }

        private:
            T* m_memory;
    };

    // Class used when VTL0 memory is allocated with HeapAlloc. This smart pointer will
    // free the memory using HeapFree
    template <typename T>
    struct vtl0_memory_ptr
    {
        vtl0_memory_ptr() = default;

        // Memory should always be VTL0 memory created with HeapAlloc
        // This class owns the memory it points to.
        explicit vtl0_memory_ptr(T* memory) noexcept
            : m_memory(memory)
        {
        }

        ~vtl0_memory_ptr() noexcept
        {
            free_memory(m_memory);
        }

        // Disallow copy for now
        vtl0_memory_ptr(const vtl0_memory_ptr&) = delete;
        vtl0_memory_ptr& operator=(const vtl0_memory_ptr&) = delete;

        // Allow moves
        vtl0_memory_ptr& operator=(vtl0_memory_ptr&& other)
        {
            if (this != &other)
            {
                m_memory(other.release());
            }

            return *this;
        }

        vtl0_memory_ptr(const vtl0_memory_ptr&& other) :
            m_memory(other.release())
        {
        }

        void reset()
        {
            T* memory = m_memory;
            m_memory = nullptr;

            if (m_memory)
            {
                release();
            }
        }

        T** put()
        {
            reset();
            return &m_memory;
        }

        vtl0_memory_ptr& operator=(T* other)
        {
            auto ptr = m_memory;
            m_memory = other;
           
            if (ptr)
            {
                ptr->release();
            }
            return *this;
        }

        constexpr T* operator->() const noexcept
        {
            return m_memory;
        }

        T* get() const noexcept
        {
            return m_memory;
        }

        T& operator*() const
        {
            return *m_memory;
        }

        T** operator&()
        {
            return put();
        }

        T* release() noexcept
        {
            T* memory = m_memory;
            m_memory = nullptr;

            return memory;
        }

        private:
            static void free_memory(T* memory)
            {
                if (memory)
                {
                    SecureZeroMemory(memory, sizeof(T));
                    ::HeapFree(::GetProcessHeap(), 0, memory);
                    memory = nullptr;
                }
            }

            T* m_memory{};
    };
}
