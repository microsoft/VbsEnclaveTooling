// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"
#include "EnclaveHost.h"
#include "EnclaveFeatureHost.h"
#include <vector>

Enclave::Enclave(IEnclaveHost& enclaveHost)
    : m_enclaveHost{&enclaveHost}
{
}

Enclave::Enclave(IEnclaveHost& enclaveHost, void* enclave)
    : m_enclaveHost{&enclaveHost}
    , m_enclave{enclave}
{
}

Enclave::Enclave(Enclave&& other)
    : m_enclaveHost{other.m_enclaveHost}
    , m_enclave{std::exchange(other.m_enclave, {})}
{
}

Enclave& Enclave::operator=(Enclave&& other)
{
    TerminateAndDelete();

    m_enclaveHost = other.m_enclaveHost;
    m_enclave = std::exchange(other.m_enclave, {});

    return *this;
}

Enclave::~Enclave()
{
    TerminateAndDelete();
}

PENCLAVE_ROUTINE Enclave::GetEnclaveRoutine(LPCSTR functionName)
{
    PENCLAVE_ROUTINE function{};
    HRESULT hr = m_enclaveHost->GetEnclaveFunction(functionName, m_enclave, &function);
    THROW_IF_FAILED(hr);

    return function;
}

PENCLAVE_ROUTINE Enclave::TryGetEnclaveRoutine(LPCSTR functionName) noexcept
{
    PENCLAVE_ROUTINE function{};
    if (FAILED_LOG(m_enclaveHost->GetEnclaveFunction(functionName, m_enclave, &function)))
    {
        function = nullptr;
    }

    return function;
}

void Enclave::Call(PENCLAVE_ROUTINE method, PVOID params)
{
    THROW_IF_FAILED(CallNoThrow(method, params));
}

HRESULT Enclave::CallNoThrow(PENCLAVE_ROUTINE method, PVOID params) noexcept
{
    PVOID output = nullptr;
    RETURN_IF_FAILED(CallWithResult(method, params, &output));
    RETURN_HR((HRESULT)((UINT_PTR)(output) & 0x00000000FFFFFFFFull));
}

HRESULT Enclave::CallWithResult(PENCLAVE_ROUTINE method, PVOID params, PVOID* result) noexcept
{
    // Ensure enclaves are properly intialized before use
    // The enclave hasn't been unlocked yet. Return E_ACCESSDENIED.
    if (!m_enclave || !m_enclaveHost || !method)
    {
        return E_ACCESSDENIED;
    }

    RETURN_IF_WIN32_BOOL_FALSE(m_enclaveHost->CallEnclave(method, params, TRUE, result));
    return S_OK;
}

IEnclaveHost& Enclave::GetHost()
{
    return *m_enclaveHost;
}

void* Enclave::GetEnclave()
{
    return m_enclave;
}

void Enclave::TerminateAndDelete()
{
    if (m_enclave)
    {
        // fWait = TRUE means that we wait for all threads in the enclave to terminate.
        // This is necessary because you cannot delete an enclave if it still has
        // running threads.
        LOG_IF_WIN32_BOOL_FALSE(m_enclaveHost->TerminateEnclave(m_enclave, TRUE));

        // Delete the enclave.
        LOG_IF_WIN32_BOOL_FALSE(m_enclaveHost->DeleteEnclave(m_enclave));

        m_enclave = {};
    }
}

void Enclave::LoadNamedEnclave(const wchar_t* enclaveDll, const ENCLAVE_INIT_INFO_VBS& initializationInfo, std::span<const uint8_t> ownerId)
{
    if (m_enclave)
    {
        return;
    }

    if (!m_enclaveHost->IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS))
    {
        THROW_HR_MSG(E_ACCESSDENIED, "VBS enclave type not supported");
    }

    ENCLAVE_CREATE_INFO_VBS createInfo;
    createInfo.Flags = ENCLAVE_VBS_FLAG_DEBUG;
    std::memcpy(
        createInfo.OwnerID, ownerId.data(),
            ownerId.size() > IMAGE_ENCLAVE_LONG_ID_LENGTH ? IMAGE_ENCLAVE_LONG_ID_LENGTH : ownerId.size());

    m_enclave = m_enclaveHost->CreateEnclave(
        GetCurrentProcess(),
        nullptr,    // Preferred base address
        0x10000000, // Size
        0,          // Initial commit
        ENCLAVE_TYPE_VBS,
        &createInfo,
        sizeof(ENCLAVE_CREATE_INFO_VBS),
        nullptr); // EnclaveError
    THROW_LAST_ERROR_IF_NULL(m_enclave);

    auto cleanup = wil::scope_exit([&] {
        TerminateAndDelete();
    });

    // Load enclave module with SEM_FAILCRITICALERRORS enabled to suppress
    // the error message dialog.
    {
        DWORD previousMode = GetThreadErrorMode();
        SetThreadErrorMode(previousMode | SEM_FAILCRITICALERRORS, nullptr);
        auto restoreErrorMode = wil::scope_exit([&] {
            SetThreadErrorMode(previousMode, nullptr);
        });
        THROW_IF_WIN32_BOOL_FALSE(m_enclaveHost->LoadEnclaveImageW(m_enclave, enclaveDll));
    }

    THROW_IF_WIN32_BOOL_FALSE(m_enclaveHost->InitializeEnclave(GetCurrentProcess(), m_enclave, &initializationInfo, initializationInfo.Length, nullptr));

    cleanup.release();
}

void Enclave::GetEnclaveRoutines(std::span<PCSTR const> functionNames, std::span<PENCLAVE_ROUTINE*> functions)
{
    FAIL_FAST_IF(functionNames.size() != functions.size());

    for (size_t i = 0; i < functionNames.size(); i++)
    {
        *(functions[i]) = this->GetEnclaveRoutine(functionNames[i]);
    }
}

bool Enclave::Initialized()
{
    return m_enclave != nullptr;
}
