#pragma once

#include <string>

#include "registered_callbacks.vtl1.h"

/*
namespace veil::outcalls
{
    inline void* malloc(size_t size)
    {
        // Try get buffer from call context

        // Perform host allocation by making an ocall.
        //return oe_host_malloc(size);

        void* output;
        //auto fp_malloc = (LPENCLAVE_ROUTINE)implementation::get_callback(L"malloc");
        auto fp_malloc = (LPENCLAVE_ROUTINE)veil::vtl1::implementation::get_callback(veil::callback_id::malloc);
        THROW_IF_WIN32_BOOL_FALSE(CallEnclave((LPENCLAVE_ROUTINE)fp_malloc, reinterpret_cast<void*>(size), TRUE, reinterpret_cast<void**>(&output)));
        return output;
    }



    template <typename... Args>
    inline std::wstring format_string(PCWSTR format, Args&&... args)
    {
        std::array<wchar_t, MAX_PATH> outString;
        THROW_IF_FAILED(StringCchPrintfW(outString.data(), MAX_PATH, format, std::forward<Args>(args)...));
        return std::wstring(outString.data());
    }

    template <typename... Ts>
    inline void PrintfInHost(Ts&&... args)
    {
        auto str = veil::outcalls::format_string(std::forward<Ts>(args)...);

        void* output;

        size_t len = str.size();
        //size_t len = wcslen(str);
        size_t cbBuffer = (len + 1) * sizeof(wchar_t);

        auto fp_malloc = (LPENCLAVE_ROUTINE)veil::vtl1::implementation::get_callback(veil::callback_id::malloc);
        THROW_IF_WIN32_BOOL_FALSE(CallEnclave((LPENCLAVE_ROUTINE)fp_malloc, reinterpret_cast<void*>(cbBuffer), TRUE, reinterpret_cast<void**>(&output)));

        void* allocation = veil::outcalls::malloc(cbBuffer);
        THROW_IF_NULL_ALLOC(allocation);

        auto buffer = reinterpret_cast<wchar_t*>(allocation);

        memcpy(buffer, str.c_str(), cbBuffer);
        buffer[len] = NULL;

        auto funcPrintf = veil::vtl1::implementation::get_callback(veil::callback_id::printf);
        THROW_IF_WIN32_BOOL_FALSE(CallEnclave((LPENCLAVE_ROUTINE)funcPrintf, reinterpret_cast<void*>(buffer), TRUE, reinterpret_cast<void**>(&output)));
    }
}

inline HRESULT CheckForVTL0Buffer22(_In_ const void* const, _In_ const size_t)
{
    // todo: implemented by tooling repo
    return S_OK;
}

inline HRESULT CheckForVTL1Buffer22(_In_ const void* const, _In_ const size_t)
{
    // todo: implemented by tooling repo
    return S_OK;
}
*/
