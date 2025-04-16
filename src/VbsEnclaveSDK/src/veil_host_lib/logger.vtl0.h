// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <filesystem>
#include <fstream>
#include <string>
#include <mutex>

#include <wil/resource.h>

#include "logger.any.h"

namespace veil::vtl0::implementation::callbacks
{
    void* add_log(void* args) noexcept;
}

namespace veil::vtl0
{
    namespace logger
    {
        extern std::mutex logMutex;

        class logger
        {
            private:
            std::wstring provider;
            std::wstring guid;
            std::wstring logFilePath;
            veil::any::logger::eventLevel logLevel;

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

            void SaveLog(const std::wstring& log)
            {
                SaveLog(log, logFilePath);
            }

            static void SaveLog(const std::wstring& log, const std::wstring& logPath)
            {
                std::filesystem::path filePath(logPath);
                std::filesystem::path dirPath = filePath.parent_path();

                std::scoped_lock lock(logMutex);

                // Create the directory if it doesn't exist
                if (!dirPath.empty() && !std::filesystem::exists(dirPath))
                {
                    std::filesystem::create_directories(dirPath);
                }

                std::wofstream wofs(filePath, std::ios::app);

                wofs << log;
                wofs.close();
            }

            public:
            logger(const std::wstring& providerName,
                const std::wstring& guidStr,
                const veil::any::logger::eventLevel level) : provider(providerName), guid(guidStr), logLevel(level)
            {
                SetLogFilePath();
            }

            void AddTimestampedLog(const std::wstring& log, const veil::any::logger::eventLevel level) // Called from Host
            {
                if (level <= logLevel)
                {
                    std::wstring timestampedLog = CreateTimestamp() + L": " + guid + L": " + provider + L": " + log + L"\n"; // Add a new line after each log 
                    SaveLog(timestampedLog);
                }
            }

            static void AddTimestampedLog(const std::wstring& log, const std::wstring& logFilePath) // Callback from Enclave via Host
            {
                std::wstring timestampedLog = CreateTimestamp() + L": " + log + L"\n"; // Add a new line after each log 
                SaveLog(timestampedLog, logFilePath);
            }

            // Getters
            veil::any::logger::eventLevel GetLogLevel()
            {
                return logLevel;
            }

            std::wstring GetLogFilePath()
            {
                return logFilePath;
            }
        };
    }
}
#pragma once
