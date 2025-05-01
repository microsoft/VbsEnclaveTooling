// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// __ENCLAVE_PROJECT__ must be defined inside the enclave project only. If it is defined
// inside the host, the host won't build as winenclaveapi
// is not compatible in an non enclave environment.
// winenclaveapi.h is included in MemoryAllocation.h and MemoryChecks.h
#ifdef __ENCLAVE_PROJECT__

#pragma once 
#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>
#include <VbsEnclaveABI\Enclave\MemoryAllocation.h>

using namespace VbsEnclaveABI::Enclave::EnclaveMemoryAllocation;

namespace VbsEnclaveABI::Enclave::Pointers
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

    template <typename T>
    struct EnclaveHeapFreeVtl0Deleter
    {
        void operator()(T* memory) noexcept
        {
            if (memory)
            {
                LOG_IF_FAILED(DeallocateVtl0Memory(memory));
            }
        }
    };

    // Class used when VTL0 memory is allocated with HeapAlloc. This smart pointer will
    // free the memory using HeapFree
    template <typename T, typename DeleterT = EnclaveHeapFreeVtl0Deleter<T>>
    struct vtl0_memory_ptr
    {
        vtl0_memory_ptr() = default;

        explicit vtl0_memory_ptr(T* memory) noexcept
            : m_memory(memory), m_memory_size(sizeof(T))
        {
        }

        explicit vtl0_memory_ptr(T* memory, size_t memory_size) noexcept
            : m_memory(memory), m_memory_size(memory_size)
        {
        }

        ~vtl0_memory_ptr()
        {
            if (m_memory)
            {
                m_deleter(m_memory); 
            }
        }

        // Disallow copy for now
        vtl0_memory_ptr(const vtl0_memory_ptr&) = delete;
        vtl0_memory_ptr& operator=(const vtl0_memory_ptr&) = delete;

        // Allow moves
        vtl0_memory_ptr& operator=(vtl0_memory_ptr&& other)
        {
            if (this != &other)
            {
                auto size = other.m_memory_size;
                m_memory(other.release());
                m_memory_size = size;
            }

            return *this;
        }

        vtl0_memory_ptr(const vtl0_memory_ptr&& other)
        {
            auto size = other.m_memory_size;
            m_memory(other.release());
            m_memory_size = size;
        }

        void reset()
        {
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
            if (m_memory != other) // Prevent self-assignment
            {
                // Delete any previously allocated memory
                if (m_memory)
                {
                    m_deleter(m_memory);
                }

                // Assign the new raw pointer
                m_memory = other;
                m_memory_size = sizeof(T);
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
            m_memory_size = 0;

            return memory;
        }

        private:
            T* m_memory{};
            size_t m_memory_size{};
            DeleterT m_deleter{};
    };
}
#endif // end __ENCLAVE_PROJECT__
