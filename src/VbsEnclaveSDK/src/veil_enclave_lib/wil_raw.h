// Copyright (c) Microsoft Corporation. All rights reserved.

#pragma once

namespace wil_raw
{

template <
    typename pointer_storage_t,
    typename close_fn_t,
    close_fn_t close_fn>
class unique_any
{
    public:
        // Constructors
    unique_any() : m_handle(0) {}
    explicit unique_any(pointer_storage_t handle) : m_handle(handle) {}

    // Non-copyable
    unique_any(const unique_any&) = delete;
    unique_any& operator=(const unique_any&) = delete;

    // Movable
    unique_any(unique_any&& other)
        : m_handle(other.m_handle)
    {
        other.m_handle = 0;
    }

    unique_any& operator=(unique_any&& other)
    {
        if (m_handle != other.m_handle)
        {
            reset();
            m_handle = other.m_handle;
            other.m_handle = 0;
        }
        return *this;
    }

    // Destructor
    ~unique_any()
    {
        reset();
    }

    // Observers
    pointer_storage_t get() const { return m_handle; }
    operator bool() const { return m_handle != 0; }

    // Modifiers
    void reset(pointer_storage_t newHandle = 0)
    {
        if (m_handle)
        {
            close_fn(m_handle);
        }
        m_handle = newHandle;
    }

    pointer_storage_t release()
    {
        pointer_storage_t temp = m_handle;
        m_handle = 0;
        return temp;
    }

    template <typename T>
    T release_as()
    {
        return static_cast<T>(release());
    }

    pointer_storage_t* addressof()
    {
        return &m_handle;
    }

    pointer_storage_t* put() noexcept
    {
        reset();
        return addressof();
    }

    pointer_storage_t* operator&() noexcept
    {
        return put();
    }

    private:
    pointer_storage_t m_handle {};
};

// Simple unique_ptr implementation without std or exceptions
template <typename T>
class unique_ptr
{
    public:
        // Type definitions
    using element_type = T;
    using pointer = T*;

    // Constructors
    unique_ptr() : m_ptr(nullptr) {}
    explicit unique_ptr(pointer ptr) : m_ptr(ptr) {}

    // Non-copyable
    unique_ptr(const unique_ptr&) = delete;
    unique_ptr& operator=(const unique_ptr&) = delete;

    // Movable
    unique_ptr(unique_ptr&& other) noexcept
        : m_ptr(other.m_ptr)
    {
        other.m_ptr = nullptr;
    }

    unique_ptr& operator=(unique_ptr&& other) noexcept
    {
        if (this != &other)
        {
            reset();
            m_ptr = other.m_ptr;
            other.m_ptr = nullptr;
        }
        return *this;
    }

    // Destructor
    ~unique_ptr()
    {
        reset();
    }

    // Observers
    pointer get() const noexcept { return m_ptr; }

    T& operator*() const noexcept { return *m_ptr; }
    pointer operator->() const noexcept { return m_ptr; }

    explicit operator bool() const noexcept { return m_ptr != nullptr; }

    // Modifiers
    void reset(pointer ptr = nullptr) noexcept
    {
        if (m_ptr)
        {
            VengcFree(m_ptr);
        }
        m_ptr = ptr;
    }

    pointer release() noexcept
    {
        pointer temp = m_ptr;
        m_ptr = nullptr;
        return temp;
    }

    private:
    pointer m_ptr;
};

// Factory function to create unique_ptr (like std::make_unique)
template <typename T, typename... Args>
unique_ptr<T> make_unique(Args&&... args)
{
    return unique_ptr<T>(new T(static_cast<Args&&>(args)...));
}

// Simple move implementation that mimics std::move
// Converts lvalue reference to rvalue reference to enable move semantics
template <typename T>
constexpr T&& move(T& t) noexcept
{
    return static_cast<T&&>(t);
}

// Overload for rvalue references (already movable)
template <typename T>
constexpr T&& move(T&& t) noexcept
{
    return static_cast<T&&>(t);
}

// Simple forward implementation that mimics std::forward
// Perfect forwarding utility for templates
template <typename T>
constexpr T&& forward(T& t) noexcept
{
    return static_cast<T&&>(t);
}

template <typename T>
constexpr T&& forward(T&& t) noexcept
{
    return static_cast<T&&>(t);
}


}
