// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <memory>
#include <span>
#include <string>
#include <windows.h>
#include <shared_enclave.h>

// Helpers for writing code that handles the Sqlite ABI boundary.
#define CATCH_RETURN_SQLITE_RESULT() \
    catch (...) \
    { \
        return SqliteResultFromFailureHRESULT(LOG_HR(wil::ResultFromCaughtException())); \
    }

constexpr HRESULT HRESULT_FROM_SQLITE_RESULT(int code)
{
    return code ? MAKE_HRESULT(SEVERITY_ERROR, FACILITY_SQLITE, code) : S_OK;
}

inline __declspec(noinline) int SqliteResultFromFailureHRESULT(HRESULT hr)
{
    // Assume generic error unless we find something better.
    int code = HRESULT_CODE(SQLITE_E_ERROR);
    if (HRESULT_FACILITY(hr) == FACILITY_SQLITE)
    {
        code = (int)HRESULT_CODE(hr);
        if (code == 0) // SQLITE_OK mistakenly reported as an exception
        {
            code = HRESULT_CODE(SQLITE_E_ERROR); // Generic error
        }
    }
    else if (hr == E_OUTOFMEMORY)
    {
        code = HRESULT_CODE(SQLITE_E_NOMEM);
    }
    else if (hr == E_ACCESSDENIED)
    {
        code = HRESULT_CODE(SQLITE_E_PERM);
    }
    return code;
}

inline int SqliteResultFromHRESULT(HRESULT hr)
{
    return SUCCEEDED(hr) ? 0 : SqliteResultFromFailureHRESULT(hr);
}

