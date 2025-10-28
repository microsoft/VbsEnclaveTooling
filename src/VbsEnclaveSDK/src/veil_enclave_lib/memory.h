// Copyright (c) Microsoft Corporation. All rights reserved.

#pragma once

#include <winenclave.h>
#include "wil_raw.h"

// Use HeapAlloc/HeapFree instead of malloc/free for VTL1 compatibility
void* VengcAlloc(size_t cb)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
}

void VengcFree(void* ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}

template <typename T>
T* VengcAlloc(size_t count)
{
    return static_cast<T*>(VengcAlloc(count * sizeof(T)));
}


//
// Blob
//
using unique_blob = wil_raw::unique_any<BYTE*, decltype(&::VengcFree), ::VengcFree>;

unique_blob make_unique_blob(size_t size)
{
    return unique_blob {VengcAlloc<BYTE>(size)};
}


//
// Blob with size
//
class unique_sized_blob
{
    public:
        // Constructors
    unique_sized_blob() {}
    unique_sized_blob(BYTE* ptr, UINT32 size) : m_blob(ptr), m_size(size) {}

    // Non-copyable
    unique_sized_blob(const unique_sized_blob&) = delete;
    unique_sized_blob& operator=(const unique_sized_blob&) = delete;

    // Movable
    unique_sized_blob(unique_sized_blob&& other) noexcept
        : m_blob(wil_raw::move(other.m_blob)), m_size(other.m_size)
    {
        other.reset();
    }

    unique_sized_blob& operator=(unique_sized_blob&& other) noexcept
    {
        if (this != &other)
        {
            reset();
            m_blob = wil_raw::move(other.m_blob);
            m_size = other.m_size;
            other.reset();
        }
        return *this;
    }

    // Destructor
    ~unique_sized_blob()
    {
        reset();
    }

    // Observers
    BYTE* get() const { return m_blob.get(); }
    UINT32 size() const { return m_size; }
    operator bool() const { return static_cast<bool>(m_blob); }

    // Modifiers
    void reset(BYTE* ptr = nullptr, UINT32 size = 0)
    {
        m_size = size;
        m_blob.reset(ptr);
    }

    BYTE* release()
    {
        m_size = 0;
        return m_blob.release();
    }

    private:
    unique_blob m_blob {};
    UINT32 m_size {};
};

inline unique_sized_blob make_unique_sized_blob(UINT32 size)
{
    auto blob = make_unique_blob(size);
    if (!blob)
    {
        return unique_sized_blob {};
    }
    return unique_sized_blob(blob.release(), size);
}


//
// Secure blob with size
//
class unique_secure_blob
{
    public:
        // Constructors
    unique_secure_blob() {}
    unique_secure_blob(BYTE* ptr, UINT32 size) : m_blob(unique_sized_blob {ptr, size}) {}
    unique_secure_blob(unique_sized_blob&& other) noexcept
        : m_blob(wil_raw::move(other))
    {
    }

    // Non-copyable
    unique_secure_blob(const unique_secure_blob&) = delete;
    unique_secure_blob& operator=(const unique_secure_blob&) = delete;

    // Movable
    unique_secure_blob(unique_secure_blob&& other) noexcept
        : m_blob(wil_raw::move(other.m_blob))
    {
        other.m_blob.reset();
    }

    unique_secure_blob& operator=(unique_secure_blob&& other) noexcept
    {
        if (this != &other)
        {
            reset();
            m_blob = wil_raw::move(other.m_blob);
        }
        return *this;
    }

    // Destructor
    ~unique_secure_blob()
    {
        reset();
    }

    // Observers
    BYTE* get() const { return m_blob.get(); }
    UINT32 size() const { return m_blob.size(); }
    operator bool() const { return static_cast<bool>(m_blob); }

    // Modifiers
    void reset(BYTE* ptr, UINT32 size)
    {
        if (m_blob)
        {
            // Zero the memory before freeing
            RtlSecureZeroMemory(m_blob.get(), m_blob.size());
        }
        m_blob.reset(ptr, size);
    }

    void reset()
    {
        reset(nullptr, 0);
    }

    BYTE* release()
    {
        return m_blob.release();
    }

    private:
    unique_sized_blob m_blob;
};

inline unique_secure_blob make_unique_secure_blob(UINT32 size)
{
    return unique_secure_blob(make_unique_sized_blob(size));
}


//
// Table of handles
//
namespace ObjectTable
{
    // Object table locking using SRW (Slim Reader-Writer) locks
inline PSRWLOCK AcquireTableLock(_In_ PSRWLOCK tableLock) noexcept
{
    AcquireSRWLockExclusive(tableLock);
    return tableLock;
}

using unique_table_lock = wil_raw::unique_any<PSRWLOCK, decltype(&ReleaseSRWLockExclusive), ReleaseSRWLockExclusive>;

// Object table
constexpr UINT32 MAX_ENTRIES = 64;

using Handle = uintptr_t;

template <typename T>
struct Entry
{
    wil_raw::unique_ptr<T> object;
    bool inUse = false;
};

template <typename T>
struct Table
{
    // Simple object table implementation
    Entry<T> s_table[MAX_ENTRIES];

    // SRW lock for thread safety - much more efficient than spinlock
    SRWLOCK s_tableLock = SRWLOCK_INIT;

    T* ResolveObject(_In_ Handle handle) noexcept
    {
        // Convert handle to index (handles are 1-based, array is 0-based)
        if (handle == 0 || handle > MAX_ENTRIES)
        {
            return nullptr;
        }

        UINT32 index = static_cast<UINT32>(handle - 1);

        auto lock = unique_table_lock {AcquireTableLock(&s_tableLock)};

        if (s_table[index].inUse)
        {
            return s_table[index].object.get();
        }

        return nullptr;
    }

    HRESULT InsertObject(wil_raw::unique_ptr<T>&& object, Handle* handle) noexcept
    {
        if (!object || !handle)
        {
            return E_INVALIDARG;
        }

        auto lock = unique_table_lock {AcquireTableLock(&s_tableLock)};

        // Find an empty slot
        for (int i = 0; i < MAX_ENTRIES; ++i)
        {
            if (!s_table[i].inUse)
            {
                s_table[i].object = wil_raw::move(object);
                s_table[i].inUse = true;

                // Convert index to handle (1-based)
                *handle = Handle {static_cast<uintptr_t>(i + 1)};
                return S_OK;
            }
        }

        return E_OUTOFMEMORY; // Table is full
    }

    HRESULT RemoveObject(_In_ Handle handle, _Out_ wil_raw::unique_ptr<T>* object) noexcept
    {
        // Convert handle to index
        if (handle == 0 || handle > MAX_ENTRIES)
        {
            return E_INVALIDARG;
        }

        UINT32 index = static_cast<UINT32>(handle - 1);

        auto lock = unique_table_lock {AcquireTableLock(&s_tableLock)};

        if (!s_table[index].inUse)
        {
            return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        }

        *object = wil_raw::move(s_table[index].object);
        s_table[index].inUse = false;
        return S_OK;
    }
};
}
