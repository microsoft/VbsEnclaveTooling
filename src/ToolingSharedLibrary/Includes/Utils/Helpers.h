// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include <pch.h>
#include <span>
#include <ranges>

namespace Helpers
{
    // Simple OrderedMap class to maintain insertion order and fast lookup
    template<typename Key, typename Value>
    class OrderedMap 
    {
        public:
            Value& at(const Key& key) { return m_map.at(key); }
            const Value& at(const Key& key) const { return m_map.at(key); }
            auto find(const Key& key) { return m_map.find(key); }
            auto find(const Key& key) const { return m_map.find(key); }
            std::span<const Key> keys() const { return m_keys; }
            size_t size() const { return m_map.size(); }

            // Technically if this was a true orderedmap doing begin() should return [key in order, value in order]
            // not the unordered_map version. However we don't need this for our use cases. We just need this classes 
            // keys() and values() methods to return their data in insertion order.
            auto begin() const { return m_map.begin(); }
            auto end() const { return m_map.end(); }
            auto begin() { return m_map.begin(); }
            auto end() { return m_map.end(); }

            const Value& operator[](const Key& key) const { return m_map.at(key); }
            bool contains(const Key& key) const { return m_map.contains(key); }
            bool empty() const { return m_map.empty(); }
            void clear()
            {
                m_map.clear();
                m_keys.clear();
            }

            Value& operator[](const Key& key)
            {
                if (!contains(key))
                {
                    m_keys.push_back(key);
                }

                return m_map[key];
            }


            void insert(const Key key, const Value& value)
            {
                if (!contains(key))
                {
                    m_keys.push_back(key);
                }

                m_map[key] = value;
            }

            void insert_front(const Key key, const Value& value)
            {
                if (!contains(key))
                {
                    m_keys.insert(m_keys.begin(), key);
                }

                m_map[key] = value;
            }

            // Merge another OrderedMap into this one, preserving order and uniqueness
            void merge(const OrderedMap& other)
            {
                for (const auto& key : other.m_keys)
                {
                    if (!contains(key))
                    {
                        insert(key, other.m_map.at(key));
                    }
                }
            }

            // Merge another OrderedMap into this one with a custom conflict resolver
            template<typename ConflictResolver>
            void merge(const OrderedMap& other, ConflictResolver resolver)
            {
                for (const auto& key : other.m_keys)
                {
                    if (contains(key))
                    {
                        resolver(key);
                    }
                    else
                    {
                        insert(key, other.m_map.at(key));
                    }
                }
            }

            auto values() const
            {
                return m_keys | std::views::transform([this] (const std::string& key) -> const Value&
                {
                    return m_map.at(key);
                });
            }

            auto values()
            {
                return m_keys | std::views::transform([this] (const std::string& key) -> Value&
                {
                    return m_map.at(key);
                });
            }

        private:
            std::unordered_map<Key, Value> m_map;
            std::vector<Key> m_keys; // Keys are kept in insertion order.
    };
}
