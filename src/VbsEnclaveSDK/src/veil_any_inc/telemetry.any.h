// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <span>
#include <string>
#include <string_view>
#include <iostream>
#include <fstream>
#include <filesystem>

#include <wil/resource.h>

namespace veil::any
{
    namespace telemetry
    {
        enum class eventLevel : uint32_t
        {
            EVENT_LEVEL_CRITICAL = 1,
            EVENT_LEVEL_ERROR,
            EVENT_LEVEL_WARNING,
            EVENT_LEVEL_INFO,
            EVENT_LEVEL_VERBOSE
        };

        class activity
        {
            private:
            std::wstring provider;
            std::wstring guid;
            std::wstring logString;
            std::wstring logFilePath;
            eventLevel activityLevel;

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

            void SetLogFilePath()
            {
                logFilePath = L"c:\\VeilLogs\\" + ReplaceForbiddenFilenameChars(CreateTimestamp()) + L".txt";
            }

            void SaveLog()
            {
                // TODO: Multiple threads can potentially save log at the same time. Make sure to lock
                std::filesystem::path filePath(logFilePath);
                std::filesystem::path dirPath = filePath.parent_path();

                // Create the directory if it doesn't exist
                if (!dirPath.empty() && !std::filesystem::exists(dirPath))
                {
                    std::filesystem::create_directories(dirPath);
                }

                std::wofstream wofs(filePath, std::ios::app);

                wofs << logString;
                logString = L"";
                wofs.close();
            }

            public:
            activity(const eventLevel level) : activityLevel(level) // This is used from the enclave to create and append to logString, no writes can be performed from enclave
            {}

            activity(const std::wstring& providerName,
                const std::wstring& guidStr,
                const eventLevel level) : provider(providerName), guid(guidStr), activityLevel(level)
            {
                SetLogFilePath();
            }

            void AddLog(const std::wstring& log, const eventLevel level) // Called from Enclave
            {
                if (level <= activityLevel)
                {
                    logString.append(log + L"\n"); // Add a new line after each log
                }
            }

            static std::wstring CreateTimestamp()
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

            void AddTimestampedLog(const std::wstring& log, const eventLevel level) // Called from Host
            {
                if (level <= activityLevel)
                {
                    logString.append(CreateTimestamp() + L": " + guid + L": " + provider + L": " + log + L"\n"); // Add a new line after each log
                }

                SaveLog();
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

            void AddLogFromEnclave(uint8_t* data, size_t size)
            {
                auto logSpan = std::span<uint8_t>(reinterpret_cast<uint8_t*>(data), size);
                std::vector<uint8_t> logBytes(logSpan.begin(), logSpan.end());
                auto logStr = BytesToWString(logBytes);
                AddTimestampedLog(logStr, activityLevel);
            }

            // Getters
            std::wstring GetLog()
            {
                return logString;
            }

            eventLevel GetActivityLevel()
            {
                return activityLevel;
            }

            std::wstring GetLogFilePath()
            {
                return logFilePath;
            }
        };
    }
}

