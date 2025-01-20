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
    void* malloc(void* args);
    void* printf(void* args);
    void* wprintf(void* args);

    veil::implementation::callback_t callback_addresses[veil::implementation::callback_id_count] = {
        &malloc,
        &printf,
        &wprintf,
        &taskpool_make,
        &taskpool_delete,
        &taskpool_schedule_task
    };
}

namespace veil::vtl0::implementation::callbacks
{
    void* malloc(void* args)
    {
        // todo: alignment, etc
        auto size = reinterpret_cast<size_t>(args);
        auto buffer = ::malloc(size);
        return buffer;
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
