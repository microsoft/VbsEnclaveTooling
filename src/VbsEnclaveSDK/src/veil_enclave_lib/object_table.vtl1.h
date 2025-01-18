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
        keepalive_mechanism<T>* m_keepaliveObject{};
        wil::srwlock m_lock;

        keepalive_hold(keepalive_mechanism<T>* keeapliveObject)
            : m_keepaliveObject(keeapliveObject)
        {
        }

        ~keepalive_hold()
        {
            m_keepaliveObject->notify_keepalive_hold_done();
        }

        // Delete copy
        keepalive_hold(const keepalive_hold&) = delete;
        keepalive_hold& operator=(const keepalive_hold&) = delete;

        // Delete move
        keepalive_hold(keepalive_hold&& other) = delete;
        keepalive_hold& operator=(keepalive_hold&& other) = delete;

        T* object()
        {
            return m_keepaliveObject->object();
        }
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
            reset_keepalive_and_block();
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
        void reset_keepalive_and_block()
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

        handle store_object(T&& object)
        {
            handle handle = nextHandle++;
            //objects.emplace(handle, std::make_unique<T>(object));
            objects.emplace(handle, std::move(object));
            return handle;
        }

        std::optional<T> try_take_object(handle handle)
        {
            auto it = objects.find(handle);
            if (it != objects.end())
            {
                auto node = objects.extract(it);
                return std::optional<T>{std::move(node.mapped())};
            }
            return std::nullopt;
        }

        T take_object(handle handle)
        {
            if (auto object = try_take_object(handle))
            {
                return object;
            }
            THROW_WIN32_MSG(ERROR_INVALID_INDEX, "Object handle doesn't exist: %d", (int)handle);
        }

    private:
        handle nextHandle = 1;
        std::unordered_map<handle, T> objects;
        //std::unordered_map<handle, std::shared_ptr<T>> objects;
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
            handle handle = nextHandle++;
            //objects.emplace(handle, std::make_unique<T>(object));
            objects.emplace(handle, std::move(object));
            return handle;
        }

        void erase(handle handle)
        {
            objects.erase(handle);
        }

        std::weak_ptr<T> get(handle handle)
        {
            auto it = objects.find(handle);
            if (it == objects.end())
            {
                return {};
            }
            //auto strong = it->second->lock();
            //return strong;
            return it->second;
            //auto node = objects.extract(it);
            //return std::optional<T>{std::move(node.mapped())};
        }

        std::shared_ptr<T> resolve_strong_reference(handle handle)
        {
            // todo: make threadsafe
            auto it = objects.find(handle);
            if (it == objects.end())
            {
                return nullptr;
            }
            if (auto strong = it->second.lock())
            {
                return strong;
            }
            return nullptr;
            //auto node = objects.extract(it);
            //return std::optional<T>{std::move(node.mapped())};
        }

    private:
        handle nextHandle = 1;
        std::unordered_map<handle, std::weak_ptr<T>> objects;
        //std::unordered_map<handle, std::shared_ptr<T>> objects;
    };


}
