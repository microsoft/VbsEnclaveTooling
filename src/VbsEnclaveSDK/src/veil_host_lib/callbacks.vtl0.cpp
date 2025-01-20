#include "pch.h"

#include <iostream>
#include <map>
#include <mutex>
#include <syncstream>

#include "veil.any.h"

#include "callbacks.vtl0.h"
#include "threadpool.vtl0.h"
#include "utils.vtl0.h"

namespace veil::vtl0::implementation::callbacks
{
    void* malloc(void* args);
    void* printf(void* args);
    void* wprintf(void* args);
    void* get_per_thread_buffer(void* args);

    veil::implementation::callback_t callback_addresses[veil::implementation::callback_id_count] = {
        &malloc,
        &printf,
        &wprintf,
        &get_per_thread_buffer,
        &threadpool_make,
        &threadpool_delete,
        &threadpool_schedule_task
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
        //auto io = reinterpret_cast<recall::args::PrintfBuffer*>(args);
        auto buffer = reinterpret_cast<char*>(args);

        std::osyncstream synced_out(std::cout);
        synced_out << "FROM VTL1: " << buffer << std::endl;
        return S_OK;
    })

    VEIL_ABI_FUNCTION(wprintf, args,
    {
        auto lock = std::scoped_lock<std::mutex>(veil::vtl0::implementation::g_printMutex);
        //auto io = reinterpret_cast<recall::args::PrintfBuffer*>(args);
        auto buffer = reinterpret_cast<wchar_t*>(args);

        std::wosyncstream synced_out(std::wcout);
        synced_out << L"FROM VTL1: " << buffer << std::endl;
        return S_OK;
    })

    VEIL_ABI_FUNCTION(get_per_thread_buffer, args,
    {
        //auto threadIndex = reinterpret_cast<uint32_t>(args);
        //static std::map<uint32_t, void*>
        return S_OK;
    })
}
