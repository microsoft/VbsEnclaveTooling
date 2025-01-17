#pragma once

#include <map>
#include <optional>
#include <vector>

#include "veil.any.h"

namespace veil::vtl1::implementation::export_helpers
{
    extern wil::srwlock g_enclaveErrorsMutex;

    // TID, Errors
    extern std::map<DWORD, std::vector<enclave_error>> g_enclaveErrors;

    namespace
    {
        inline errno_t __cdecl wcsncpy_s_max(
                _Out_writes_z_(sizeInWords) wchar_t* dst,
                _In_                         rsize_t        sizeInWords,
                _In_reads_or_z_(srcSizeInWords)   wchar_t const* src,
                _In_                         rsize_t        srcSizeInWords
        )
        {
            size_t amount = sizeInWords < srcSizeInWords ? sizeInWords : srcSizeInWords;
            auto ret = wcsncpy_s(dst, sizeInWords, src, amount);
            dst[sizeInWords - 1] = '\0';
            return ret;
        }
    }

    inline void copy_enclave_error(enclave_error& dst, const enclave_error& src)
    {
        dst.hr = src.hr;
        dst.threadId = src.threadId;
        // Copy error message
        wcsncpy_s_max(dst.wmessage, _countof(dst.wmessage), src.wmessage, wcslen(src.wmessage));
    }

    inline std::optional<enclave_error> pop_back_thread_enclave_error(DWORD tid)
    {
        auto lock = g_enclaveErrorsMutex.lock_exclusive();
        if (g_enclaveErrors[tid].empty())
        {
            return std::nullopt;
        }
        auto last = std::move(g_enclaveErrors[tid].back());
        g_enclaveErrors[tid].pop_back();
        return last;
    }

    struct enclave_error_populator
    {
        enclave_error& m_errorReference;

        enclave_error_populator(enclave_error& errorReference) : m_errorReference(errorReference)
        {
            wil::SetResultLoggingCallback([](wil::FailureInfo const& failure) WI_NOEXCEPT
            {
                enclave_error e;
                e.hr = failure.hr;
                e.threadId = failure.threadId;
                wil::GetFailureLogString(&e.wmessage[0], _countof(e.wmessage), failure);

                auto lock = g_enclaveErrorsMutex.lock_exclusive();
                g_enclaveErrors[e.threadId].emplace_back(std::move(e));
            });
        }

        ~enclave_error_populator()
        {
            auto lock = g_enclaveErrorsMutex.lock_exclusive();

            auto& threadErrors = g_enclaveErrors[GetCurrentThreadId()];
            if (threadErrors.empty())
            {
                return;
            }

            auto& lastError = threadErrors.back();
            copy_enclave_error(m_errorReference, lastError);
            //g_enclaveErrors[GetCurrentThreadId()].clear();
        }
    };


}
