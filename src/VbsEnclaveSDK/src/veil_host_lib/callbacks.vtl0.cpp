// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <iostream>
#include <map>
#include <mutex>

#include "veil.any.h"

#include "callbacks.vtl0.h"
#include "taskpool.vtl0.h"
#include "utils.vtl0.h"

namespace veil::vtl0::implementation::callbacks
{
    void* malloc(void* args) noexcept;
    void* free(void* args) noexcept;
    void* printf(void* args) noexcept;
    void* wprintf(void* args) noexcept;

    veil::implementation::callback_t callback_addresses[veil::implementation::callback_id_count] = {
        &malloc,
        &free,
        &printf,
        &wprintf,
        &taskpool_make,
        &taskpool_delete,
        &taskpool_schedule_task
    };
}

namespace veil::vtl0::implementation::callbacks
{
    void* malloc(void* args) noexcept
    {
        auto size = reinterpret_cast<size_t>(args);
        auto buffer = ::malloc(size);
        return buffer;
    }
    
    void* free(void* buffer) noexcept
    {
        ::free(buffer);
        return NULL;
    }

    VEIL_ABI_FUNCTION(printf, args,
    {
        auto lock = std::scoped_lock<std::mutex>(veil::vtl0::implementation::g_printMutex);
        auto buffer = reinterpret_cast<char*>(args);

        std::cout << "FROM VTL1: " << buffer << std::endl;
        return S_OK;
    })

    VEIL_ABI_FUNCTION(wprintf, args,
    {
        auto lock = std::scoped_lock<std::mutex>(veil::vtl0::implementation::g_printMutex);
        auto buffer = reinterpret_cast<wchar_t*>(args);

        std::wcout << L"FROM VTL1: " << buffer << std::endl;
        return S_OK;
    })
}
