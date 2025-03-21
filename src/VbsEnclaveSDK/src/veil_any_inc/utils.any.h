// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <span>
#include <string>
#include <string_view>
#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>

#include <wil/resource.h>

namespace veil::any
{
    template <typename T>
    constexpr T math_max(const T& a, const T& b)
    {
        if (a > b)
        {
            return a;
        }
        return b;
    }

    template <typename BufferT>
    inline void add_buffer_bytes(BufferT& storage, std::span<uint8_t const> data)
    {
        storage.insert(storage.end(), data.begin(), data.end());
    }

    struct buffer_reader
    {
        std::span<UCHAR const> data;

        size_t remaining() const
        {
            return data.size();
        }

        std::span<UCHAR const> read(size_t size)
        {
            THROW_HR_IF(E_INVALIDARG, size > data.size());
            auto result = data.first(size);
            data = data.subspan(size);
            return result;
        }

        std::span<UCHAR const> read_remaining()
        {
            return std::exchange(data, {});
        }

        template <typename T>
        T const* read()
        {
            return reinterpret_cast<T const*>(read(sizeof(T)).data());
        }
    };

    namespace telemetry
    {
        struct activity
        {
            private: 
            std::wstring logString;
            std::wstring logFilePath;

            std::wstring CreateTimestamp()
            {
                // Get the current time
                std::time_t now = std::time(nullptr);

                // Convert to local time
                std::tm localTime;
                localtime_s(&localTime, &now);

                // Format the time as a wide string
                std::wostringstream timestamp;
                timestamp << std::put_time(&localTime, L"%Y-%m-%d %H:%M:%S");

                return timestamp.str(); // Return the formatted timestamp as std::wstring
            }

            std::wstring ReplaceForbiddenFilenameChars(const std::wstring& input)
            {
                std::wstring modified = input;
                for (wchar_t& ch : modified)
                {
                    if (ch == L' ')
                    {
                        ch = L'_';
                    }
                    if (ch == L':')
                    {
                        ch = L'.';
                    }
                }

                return modified;
            }


            public:
            void SetLogFilePath()
            {
                logFilePath = L"c:\\VeilLogs\\" + ReplaceForbiddenFilenameChars(CreateTimestamp()) + L".txt";
            }

            void AddLog(const std::wstring& log) // Called from Enclave
            {
                logString.append(log + L"\n"); // Add a new line after each log
            }

            void AddTimestampedLog(const std::wstring& log) // Called from Host
            {
                logString.append(CreateTimestamp() + L": " + log + L"\n"); // Add a new line after each log
            }

            void SaveLog()
            {
                std::filesystem::path filePath(logFilePath);
                std::filesystem::path dirPath = filePath.parent_path();

                // Create the directory if it doesn't exist
                if (!dirPath.empty() && !std::filesystem::exists(dirPath))
                {
                    std::filesystem::create_directories(dirPath);
                }

                std::wofstream wofs(filePath, std::ios::out);

                wofs << logString;
                wofs.close();
            }

            std::wstring GetLog()
            {
                return logString;
            }

            std::vector<uint8_t> WstringToBytes()
            {
                std::vector<uint8_t> bytes;
                bytes.reserve(logString.size() * sizeof(wchar_t));
                for (wchar_t wc : logString)
                {
                    uint8_t* bytePtr = reinterpret_cast<uint8_t*>(&wc);
                    for (size_t i = 0; i < sizeof(wchar_t); ++i)
                    {
                        bytes.push_back(bytePtr[i]);
                    }
                }
                return bytes;
            }

            std::wstring BytesToWString(const std::vector<uint8_t>& bytes)
            {
                std::wstring wstr(bytes.size() / sizeof(wchar_t), L'\0');
                std::memcpy(&wstr[0], bytes.data(), bytes.size());
                return wstr;
            }
        };
    }
}
