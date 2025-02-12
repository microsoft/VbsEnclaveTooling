// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <enclaveapi.h>
#include <span>
#include <gsl/gsl>
#include <vector>

struct IEnclaveHost
{
    virtual BOOL IsEnclaveTypeSupported(DWORD flEnclaveType) = 0;

    _Ret_maybenull_
    _Post_writable_byte_size_(dwSize)
    virtual LPVOID CreateEnclave(
        _In_ HANDLE hProcess,
        _In_opt_ LPVOID lpAddress,
        _In_ SIZE_T dwSize,
        _In_ SIZE_T dwInitialCommitment,
        _In_ DWORD flEnclaveType,
        _In_reads_bytes_(dwInfoLength) LPCVOID lpEnclaveInformation,
        _In_ DWORD dwInfoLength,
        _Out_opt_ LPDWORD lpEnclaveError) = 0;

    _Success_(return != FALSE)
    virtual BOOL LoadEnclaveData(
        _In_ HANDLE hProcess,
        _In_ LPVOID lpAddress,
        _In_reads_bytes_(nSize) LPCVOID lpBuffer,
        _In_ SIZE_T nSize,
        _In_ DWORD flProtect,
        _In_reads_bytes_(dwInfoLength) LPCVOID lpPageInformation,
        _In_ DWORD dwInfoLength,
        _Out_ PSIZE_T lpNumberOfBytesWritten,
        _Out_opt_ LPDWORD lpEnclaveError) = 0;

    _Success_(return != FALSE)
    virtual BOOL InitializeEnclave(
        _In_ HANDLE hProcess,
        _In_ LPVOID lpAddress,
        _In_reads_bytes_(dwInfoLength) LPCVOID lpEnclaveInformation,
        _In_ DWORD dwInfoLength,
        _Out_opt_ LPDWORD lpEnclaveError) = 0;

    _Success_(return != FALSE)
    virtual BOOL LoadEnclaveImageA(_In_ LPVOID lpEnclaveAddress, _In_ LPCSTR lpImageName) = 0;

    _Success_(return != FALSE)
    virtual BOOL LoadEnclaveImageW(_In_ LPVOID lpEnclaveAddress, _In_ LPCWSTR lpImageName) = 0;

    _Success_(return != FALSE)
    virtual BOOL CallEnclave(_In_ LPENCLAVE_ROUTINE lpRoutine, _In_ LPVOID lpParameter, _In_ BOOL fWaitForThread, _Out_ LPVOID* lpReturnValue) = 0;

    _Success_(return != FALSE)
    virtual BOOL TerminateEnclave(_In_ LPVOID lpAddress, _In_ BOOL fWait) = 0;

    _Success_(return != FALSE)
    virtual BOOL DeleteEnclave(_In_ LPVOID lpAddress) = 0;

    _Success_(return != FALSE)
    virtual HRESULT GetEnclaveFunction(_In_ LPCSTR functionName, _In_ LPVOID lpEnclaveAddress, _Out_ PENCLAVE_ROUTINE* enclaveFunction) = 0;

    virtual std::vector<uint8_t> GetOwnerID() = 0;

protected:
    ~IEnclaveHost() = default;
};

class Enclave
{
    gsl::not_null<IEnclaveHost*> m_enclaveHost;
    void* m_enclave{};

public:
    explicit Enclave(IEnclaveHost& enclaveHost);

    Enclave(IEnclaveHost& enclaveHost, void* enclave);

    Enclave(const Enclave&) = delete;

    Enclave& operator=(const Enclave&) = delete;

    Enclave(Enclave&& other);

    Enclave& operator=(Enclave&& other);

    ~Enclave();

    PENCLAVE_ROUTINE GetEnclaveRoutine(LPCSTR functionName);

    PENCLAVE_ROUTINE TryGetEnclaveRoutine(LPCSTR functionName) noexcept;

    void GetEnclaveRoutines(std::span<PCSTR const> functionNames, std::span<PENCLAVE_ROUTINE*> functions);

    void Call(PENCLAVE_ROUTINE method, PVOID params);

    bool Initialized();

    template <typename T>
    void Call(PENCLAVE_ROUTINE method, T* params)
    {
        static_assert(std::is_standard_layout_v<T>, "Parameter to Call must be memcpy'able");
        Call(method, static_cast<void*>(params));
    }

    HRESULT CallNoThrow(PENCLAVE_ROUTINE method, PVOID params) noexcept;

    template <typename T>
    HRESULT CallNoThrow(PENCLAVE_ROUTINE method, T* params) noexcept
    {
        static_assert(std::is_standard_layout_v<T>, "Parameter to CallNoThrow must be memcpy'able");
        return CallNoThrow(method, static_cast<void*>(params));
    }

    HRESULT CallWithResult(PENCLAVE_ROUTINE method, PVOID params, PVOID* result) noexcept;

    template <typename T>
    HRESULT CallWithResult(PENCLAVE_ROUTINE method, T* params, PVOID* result) noexcept
    {
        static_assert(std::is_standard_layout_v<T>, "Parameter to CallWithResult must be memcpy'able");
        return CallWithResult(method, static_cast<void*>(params), result);
    }

    IEnclaveHost& GetHost();

    void* GetEnclave();

    void TerminateAndDelete();

    void LoadNamedEnclave(const wchar_t* enclaveDll, const ENCLAVE_INIT_INFO_VBS& initializationInfo, std::span<const uint8_t> ownerId);
};

