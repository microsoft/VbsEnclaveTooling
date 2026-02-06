// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <type_traits>

namespace veil::any::veil_types
{
    // Minimal C++17 span for compatibility
    template<typename T>
    class span
    {
        T* m_data;
        size_t m_size;

    public:
        constexpr span() noexcept : m_data(nullptr), m_size(0) {}
        
        constexpr span(T* ptr, size_t count) noexcept : m_data(ptr), m_size(count) {}

        template <typename Container, typename T>
        using enable_if_span_compatible =
            std::enable_if_t<
                !std::is_same_v<std::decay_t<Container>, span>&&
                std::is_convertible_v<decltype(std::declval<Container&>().data()), T*>>;

        template <typename Container, typename = enable_if_span_compatible<Container, T>>
        constexpr span(Container& c) noexcept : m_data(c.data()), m_size(c.size()) {}

        template <typename Container, typename = enable_if_span_compatible<const Container, T>>
        constexpr span(const Container& c) noexcept : m_data(c.data()), m_size(c.size()) {}

        constexpr T* data() const noexcept { return m_data; }
        constexpr size_t size() const noexcept { return m_size; }
        constexpr bool empty() const noexcept { return m_size == 0; }

        constexpr T* begin() const noexcept { return m_data; }
        constexpr T* end() const noexcept { return m_data + m_size; }

        constexpr T& operator[](size_t idx) const noexcept { return m_data[idx]; }
    };
}
