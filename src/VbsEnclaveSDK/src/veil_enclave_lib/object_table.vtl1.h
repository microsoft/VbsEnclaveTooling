#pragma once

#include <unordered_map>
#include <memory>

namespace veil::vtl1
{
    template <typename T>
    struct keepalive_mechanism;

    template <typename T>
    struct keepalive_hold
    {
        keepalive_hold(keepalive_mechanism<T>* mechanism)
            : m_mechanism(mechanism)
        {
        }

        ~keepalive_hold()
        {
            m_mechanism->notify_keepalive_hold_done();
        }

        // Delete copy
        keepalive_hold(const keepalive_hold&) = delete;
        keepalive_hold& operator=(const keepalive_hold&) = delete;

        // Delete move
        keepalive_hold(keepalive_hold&& other) = delete;
        keepalive_hold& operator=(keepalive_hold&& other) = delete;

        T* object()
        {
            return m_mechanism->object();
        }
    private:
        keepalive_mechanism<T>* m_mechanism{};
    };

    template <typename T>
    struct keepalive_mechanism
    {
        keepalive_mechanism(T* object)
            : m_object(object),
            m_keepaliveHold(std::make_shared<keepalive_hold<T>>(this))
        {
        }

        ~keepalive_mechanism()
        {
            release_hold_and_block();
        }

        // Delete copy
        keepalive_mechanism(const keepalive_mechanism&) = delete;
        keepalive_mechanism& operator=(const keepalive_mechanism&) = delete;

        // Allow move
        keepalive_mechanism(keepalive_mechanism&& other) noexcept = default;
        keepalive_mechanism& operator=(keepalive_mechanism&& other) noexcept = default;

        std::weak_ptr<keepalive_hold<T>> get_weak()
        {
            return std::weak_ptr(m_keepaliveHold);
        }

        T* object()
        {
            return m_object;
        }

        void notify_keepalive_hold_done()
        {
            {
                auto lock = m_lock.lock_exclusive();
                m_done = true;
            }
            m_cv.notify_all();
        }

        // release keepalive_hold and wait until no more strong references
        void release_hold_and_block()
        {
            if (m_keepaliveHold)
            {
                auto weakPtr = get_weak();
                m_keepaliveHold.reset();
                while (true)
                {
                    auto lock = m_lock.lock_exclusive();
                    if (m_done)
                    {
                        break;
                    }
                    m_cv.wait(lock);
                }
            }
        }

        private:
        T* m_object {};
        std::shared_ptr<keepalive_hold<T>> m_keepaliveHold;
        wil::srwlock m_lock;
        wil::condition_variable m_cv;
        bool m_done {};
    };

    //
    // Unique objects table that gives handles suitable for sharing with VTL0
    //
    template <typename T>
    class unique_object_table
    {
    public:
        using handle = size_t;

        handle store(T&& object)
        {
            auto lock = m_lock.lock_exclusive();
            handle handle = m_nextHandle++;
            m_objects.emplace(handle, std::move(object));
            return handle;
        }

        std::optional<T> try_take(handle handle)
        {
            auto lock = m_lock.lock_shared();
            auto it = m_objects.find(handle);
            if (it != m_objects.end())
            {
                auto node = m_objects.extract(it);
                return std::optional<T>{std::move(node.mapped())};
            }
            return std::nullopt;
        }

        T&& take(handle handle)
        {
            if (auto&& object = try_take(handle))
            {
                return std::move(object);
            }
            THROW_WIN32_MSG(ERROR_INVALID_INDEX, "Object handle doesn't exist: %d", (int)handle);
        }

    private:
        handle m_nextHandle = 1;
        std::unordered_map<handle, T> m_objects;
        wil::srwlock m_lock;
    };


    //
    // Weak object table that gives handles suitable for sharing with VTL0
    //
    template <typename T>
    class weak_object_table
    {
    public:
        using handle = size_t;

        handle store(std::weak_ptr<T> object)
        {
            handle handle = m_nextHandle++;
            m_objects.emplace(handle, std::move(object));
            return handle;
        }

        void erase(handle handle)
        {
            m_objects.erase(handle);
        }

        std::weak_ptr<T> get(handle handle)
        {
            auto it = m_objects.find(handle);
            if (it == m_objects.end())
            {
                return {};
            }
            return it->second;
        }

        std::shared_ptr<T> resolve_strong_reference(handle handle)
        {
            // todo: make threadsafe
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
        handle m_nextHandle = 1;
        std::unordered_map<handle, std::weak_ptr<T>> m_objects;
        wil::srwlock m_lock;
    };


}
