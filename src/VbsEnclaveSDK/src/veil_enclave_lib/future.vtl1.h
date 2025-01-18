#pragma once

#include <memory>
#include <optional>

#include "utils.vtl1.h"

extern std::exception_ptr globalExceptionPtr;

namespace veil::vtl1
{
    namespace details
    {
        //
        // shared state value for promise <-> future
        //
        template <typename T>
        struct shared_state_value
        {
            std::optional<T> m_value;
            void set_value(const T& value)
            {
                m_value = std::move(value);
            }

            T&& take_value()
            {
                return std::move(*m_value);
            }
        };

        template <>
        struct shared_state_value<void>
        {
            void set_value()
            {
            }

            void take_value()
            {
            }
        };

        //
        // shared state for promise <-> future
        //
        template <typename T>
        struct shared_state
        {
            void wait_for_ready()
            {
                auto lock = m_lock.lock_exclusive();
                while (!m_ready)
                {
                    m_cv.wait(lock);
                }
            }

            T get_value()
            {
                wait_for_ready();
                return m_valueholder.take_value();
            }

            // Unified set_value for void and non-void types
            void set_value(auto&&... args)
            {
                auto lock = m_lock.lock_exclusive();
                m_valueholder.set_value(std::forward<decltype(args)>(args)...);
                m_ready = true;
                m_cv.notify_all();
            }

            std::exception_ptr get_exception()
            {
                wait_for_ready();
                return std::move(m_exception);
            }

            void set_exception(std::exception_ptr&& e)
            {
                auto lock = m_lock.lock_exclusive();
                m_exception = std::move(e);
                m_ready = true;
                m_cv.notify_all();
            }

        private:
            shared_state_value<T> m_valueholder;
            std::exception_ptr m_exception{};
            bool m_ready{};
            wil::srwlock m_lock;
            wil::condition_variable m_cv;
        };
    }

    template <typename T>
    class future {
    public:
        future(std::shared_ptr<details::shared_state<T>> sharedState)
            : m_sharedState(std::move(sharedState))
        {
        }

        ~future()
        {
            if (m_sharedState)
            {
                get();
            }
        }

        // Delete copy
        future(const future&) = delete;
        future& operator=(const future&) = delete;

        // Allow move
        future(future&& other) = default;
        future& operator=(future&& other) = default;

        T get()
        {
            m_sharedState->wait_for_ready();

            if (auto e = m_sharedState->get_exception())
            {
                m_sharedState.reset();
                std::rethrow_exception(e);
            }

            if constexpr (std::is_void_v<T>)
            {
                m_sharedState->get_value();
                m_sharedState.reset();
                return;
            }
            else
            {
                auto&& value = std::move(m_sharedState->get_value());
                m_sharedState.reset();
                return value;
            }
        }

        // Consider removing detach since it's non-standard
        void detach()
        {
            m_sharedState.reset();
        }

    private:
        std::shared_ptr<details::shared_state<T>> m_sharedState;
    };

    template <typename T>
    class promise {
    public:
        promise()
            : m_sharedState(std::make_shared<details::shared_state<T>>())
        {
        }

        // Delete copy
        promise(const promise&) = delete;
        promise& operator=(const promise&) = delete;

        // Allow move
        promise(promise&&) = default;
        promise& operator=(promise&&) = default;

        future<T> get_future()
        {
            return { m_sharedState };
        }

        // Unified set_value for void and non-void types
        void set_value(auto&&... args)
        {
            m_sharedState->set_value(std::forward<decltype(args)>(args)...);
        }

        void set_exception(std::exception_ptr e)
        {
            m_sharedState->set_exception(std::move(e));
        }

    private:
        std::shared_ptr<details::shared_state<T>> m_sharedState;
    };
}
