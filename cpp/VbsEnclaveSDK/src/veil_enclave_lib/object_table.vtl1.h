// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <unordered_map>
#include <memory>

#include "future.vtl1.h"

//
// Provides types to store objects that need to be shared with VTL0 code via handles or ids.
//

namespace veil::vtl1
{
    // Fwd decl
    template <typename T>
    struct keepalive_mechanism;

    //
    // An object proxy that keeps the original object alive, via a keepalive_mechanism.
    // When the proxy is destroyed, it signals via a promise that the object has been destroyed.
    //
    template <typename T>
    struct keepalive_object_proxy
    {
        friend struct keepalive_mechanism<T>;

        keepalive_object_proxy(T& object)
            : m_object(object)
        {
        }

        ~keepalive_object_proxy()
        {
            m_promise.set_value();
        }

        // Delete copy
        keepalive_object_proxy(const keepalive_object_proxy&) = delete;
        keepalive_object_proxy& operator=(const keepalive_object_proxy&) = delete;

        // Delete move
        keepalive_object_proxy(keepalive_object_proxy&& other) = delete;
        keepalive_object_proxy& operator=(keepalive_object_proxy&& other) = delete;

        // Get reference to real object (which guaranteed it will outlive this object proxy)
        [[nodiscard]] constexpr T& object() const noexcept
        {
            return m_object;
        }

    private:
        veil::vtl1::future<void> get_destruction_future()
        {
            return m_promise.get_future();
        }

        T& m_object {};
        veil::vtl1::promise<void> m_promise;
    };

    //
    // Mechanism for keeping an object alive until all references to the keepalive_object_proxy are released.
    // 
    // Hold this mechanism in a class member to keep the object alive at destruction time.
    // Acquire and hand out weak references to the keepalive_object_proxy for consumers to resolve to a
    // strong reference of the original object.
    //
    // Key enabling behavior:
    //   - Enables consumer to create an object on the stack (instead of making a std::shared_ptr) and
    //     allow "child" or dependent objects to keep the object alive.
    //
    // Key runtime behavior:
    //   - Destructor will block until all (strong) references to the keepalive_object_proxy are released.
    //
    // In practice: This means letting a taskpool (i.e. the implementing object) fall out of scope will
    // block until the taskpool's queue is cleared (all tasks are done or de-scheduled).
    //
    template <typename T>
    struct keepalive_mechanism
    {
        keepalive_mechanism(T& object)
            : m_keepaliveHold(std::make_shared<keepalive_object_proxy<T>>(object)),
            m_futureObjectProxyDestruction(std::move(m_keepaliveHold->get_destruction_future()))
        {
        }

        ~keepalive_mechanism()
        {
            if (m_keepaliveHold)
            {
                release_keepalive_and_block();
            }
        }

        // Delete copy
        keepalive_mechanism(const keepalive_mechanism&) = delete;
        keepalive_mechanism& operator=(const keepalive_mechanism&) = delete;

        // Allow move
        keepalive_mechanism(keepalive_mechanism&& other) noexcept = default;
        keepalive_mechanism& operator=(keepalive_mechanism&& other) noexcept = default;

        std::weak_ptr<keepalive_object_proxy<T>> get_weak()
        {
            return std::weak_ptr(m_keepaliveHold);
        }

        // Release our strong reference to the keepaplive_object_proxy, then
        // wait for all other strong references to be released.
        //
        // Call this in your object's dtor.
        void release_keepalive_and_block()
        {
            THROW_HR_IF(E_ILLEGAL_METHOD_CALL, !m_keepaliveHold);
        
            // Delete our strong reference to the keepalive_object_proxy
            m_keepaliveHold.reset();

            // Wait for all other strong references to the object proxy to be released
            m_futureObjectProxyDestruction.get();
        }

    private:
        std::shared_ptr<keepalive_object_proxy<T>> m_keepaliveHold;
        veil::vtl1::future<void> m_futureObjectProxyDestruction;
    };

    //
    // Table for storing unique objects.
    // 
    // The unique entry ids are for safe for sharing as a 'handle' to the object with VTL0 code.
    //
    template <typename T>
    class unique_object_table
    {
    public:
        using id = size_t;

        unique_object_table() = default;

        // Delete copy
        unique_object_table(const unique_object_table&) = delete;
        unique_object_table& operator=(const unique_object_table&) = delete;

        // Allow move
        unique_object_table(unique_object_table&& other) noexcept = default;
        unique_object_table& operator=(unique_object_table&& other) noexcept = default;

        id peek_next_id()
        {
            auto lock = m_lock.lock_exclusive();
            return m_id;
        }

        id store(T&& object)
        {
            auto lock = m_lock.lock_exclusive();
            id id = m_id++;
            m_objects.emplace(id, std::move(object));
            return id;
        }

        std::optional<T> try_take(id handle)
        {
            auto lock = m_lock.lock_exclusive();
            auto it = m_objects.find(handle);
            if (it != m_objects.end())
            {
                auto node = m_objects.extract(it);
                return std::optional<T>{std::move(node.mapped())};
            }
            return std::nullopt;
        }

        void clear()
        {
            auto lock = m_lock.lock_exclusive();
            m_objects.clear();
        }

        T&& take(id handle)
        {
            if (auto&& object = try_take(handle))
            {
                return std::move(object);
            }
            THROW_WIN32_MSG(ERROR_INVALID_INDEX, "Object handle doesn't exist: %d", static_cast<int>(handle));
        }

    private:
        id m_id = 1;
        std::unordered_map<id, T> m_objects;
        wil::srwlock m_lock;
    };


    //
    // Table for storing weak pointers to objects.
    // 
    // The unique entry ids are for safe for sharing as a 'handle' to the object with VTL0 code.
    //
    template <typename T>
    class weak_object_table
    {
    public:
        using id = size_t;

        weak_object_table() = default;

        // Delete copy
        weak_object_table(const weak_object_table&) = delete;
        weak_object_table& operator=(const weak_object_table&) = delete;

        // Allow move
        weak_object_table(weak_object_table&& other) noexcept = default;
        weak_object_table& operator=(weak_object_table&& other) noexcept = default;

        id store(std::weak_ptr<T> object)
        {
            auto lock = m_lock.lock_exclusive();
            id id = m_id++;
            m_objects.emplace(id, std::move(object));
            return id;
        }

        void erase(id handle)
        {
            auto lock = m_lock.lock_exclusive();
            m_objects.erase(handle);
        }

        std::weak_ptr<T> get(id handle)
        {
            auto lock = m_lock.lock_shared();
            auto it = m_objects.find(handle);
            if (it == m_objects.end())
            {
                return {};
            }
            return it->second;
        }

        std::shared_ptr<T> resolve_strong_reference(id handle)
        {
            auto lock = m_lock.lock_shared();
            auto it = m_objects.find(handle);
            if (it == m_objects.end())
            {
                return nullptr;
            }
            if (auto strong = it->second.lock())
            {
                return strong;
            }
            return nullptr;
        }

    private:
        id m_id = 1;
        std::unordered_map<id, std::weak_ptr<T>> m_objects;
        wil::srwlock m_lock;
    };


}
