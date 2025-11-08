// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <future>
#include <memory>
#include <optional>

#include "utils.vtl1.h"

/*
[Usage]

    veil::vtl1::promise<int> p;
    auto fut = p.get_future();
    run_on_another_thread([p = std::move(p)]() {
        p.set_value(42);
    );
    int result = fut.get(); // Blocks until the result 42 is ready.


[Implementation]

    The promise constructs a shared_state (which has a shared_state_value to hold
    a future value), and can return a future. The future waits for the shared_state
    to be ready and then retrieves the value.

*/

namespace veil::vtl1
{
    //
    // Shared state object holds a value set by a promise and retrieved by a future
    //
    namespace details
    {
        //
        // A shared_state_value represents a container that holds a value 
        // communicated between a promise and a future. Specialized for both 
        // general types and `void`.
        //
        //  Note: Not thread-safe. Only for use by shared_state, which locks.
        //
        template <typename T>
        struct shared_state_value
        {
            shared_state_value() = default;

            // Delete copy
            shared_state_value(const shared_state_value&) = delete;
            shared_state_value& operator=(const shared_state_value&) = delete;

            // Delete move
            shared_state_value(shared_state_value&& other) = delete;
            shared_state_value& operator=(shared_state_value&& other) = delete;
            
            void set_value(const T& value) noexcept
            {
                m_value = std::move(value);
            }

            T&& take_value() noexcept
            {
                return std::move(*m_value);
            }

        private:
            std::optional<T> m_value;
        };

        template <>
        struct shared_state_value<void>
        {
            shared_state_value() = default;

            // Delete copy
            shared_state_value(const shared_state_value&) = delete;
            shared_state_value& operator=(const shared_state_value&) = delete;

            // Delete move
            shared_state_value(shared_state_value&& other) = delete;
            shared_state_value& operator=(shared_state_value&& other) = delete;

            void set_value() noexcept
            {
            }

            void take_value() noexcept
            {
            }
        };

        //
        // The shared_state bridges communication between a promise and a future.
        // It manages the state of the operation, including value, exception, 
        // and readiness notifications.
        //
        template <typename T>
        struct shared_state
        {
            shared_state() = default;

            // Delete copy
            shared_state(const shared_state&) = delete;
            shared_state& operator=(const shared_state&) = delete;

            // Delete move
            shared_state(shared_state&& other) = delete;
            shared_state& operator=(shared_state&& other) = delete;

            void wait_for_ready()
            {
                auto lock = m_lock.lock_exclusive();
                while (!m_ready)
                {
                    m_cv.wait(lock);
                }
            }

            constexpr T get_value()
            {
                wait_for_ready();
                return m_valueholder.take_value();
            }

            // Unified set_value for void and non-void types
            void set_value(auto&&... args)
            {
                auto lock = m_lock.lock_exclusive();
                if (m_ready)
                {
                    throw std::future_error(std::future_errc::promise_already_satisfied);
                }
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
                if (m_ready)
                {
                    throw std::future_error(std::future_errc::promise_already_satisfied);
                }
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

    //
    // Future mimics std::future (implemented here because of missing c++ runtime support)
    //
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

        constexpr T get()
        {
            auto state = std::exchange(m_sharedState, nullptr);
            if (!state)
            {
                throw std::future_error(std::future_errc::no_state);
            }
            state->wait_for_ready();

            if (auto e = state->get_exception())
            {
                state.reset();
                std::rethrow_exception(e);
            }

            if constexpr (std::is_void_v<T>)
            {
                state->get_value();
                return;
            }
            else
            {
                return std::move(state->get_value());
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

    //
    // Promise mimics std::promise (implemented here because of missing c++ runtime support)
    //
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
            if (m_alreadyRetrievedFuture)
            {
                throw std::future_error(std::future_errc::future_already_retrieved);
            }
            m_alreadyRetrievedFuture = true;
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
        bool m_alreadyRetrievedFuture{};
    };
}
