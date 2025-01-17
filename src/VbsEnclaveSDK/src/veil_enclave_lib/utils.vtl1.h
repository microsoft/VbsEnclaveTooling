// © Microsoft Corporation. All rights reserved.

#pragma once

#include <limits>
#include <span>
#include <vector>

struct AiEnclaveInputBlob
{
    PVOID Data;
    SIZE_T Size;
};

struct AiEnclaveOutputBlob
{
    PVOID Data;
    SIZE_T Capacity;
    SIZE_T Size;
};

// Notes: Only callable inside an enclave.
// Return Value: Returns S_OK iff the source buffer is entirely outside
// the VTL1 address space and the destination buffer is entirely inside
// the VTL1 address space.
//
// The _NoLogging suffix guarantees that it does not perform WIL logging.
// This makes it easier to validate by inspection that the logging code doesn't
// accidentally trigger recursive logging.
HRESULT CopyFromVTL0ToVTL1_NoLogging(
    _Out_writes_bytes_(length) void* const destination, _In_reads_bytes_(length) const void* const source, _In_ const size_t length);

inline HRESULT CopyFromVTL0ToVTL1(
    _Out_writes_bytes_(length) void* const destination, _In_reads_bytes_(length) const void* const source, _In_ const size_t length)
{
    // Dirty little secret: The "Logging OK" version doesn't log either.
    return CopyFromVTL0ToVTL1_NoLogging(destination, source, length);
}

// Notes: Only callable inside an enclave.
// Return Value: Returns S_OK iff the source buffer is entirely inside
// the VTL1 address space and the destination buffer is entirely outside
// the VTL1 address space.
HRESULT CopyFromVTL1ToVTL0(_Out_writes_bytes_(length) void* const destination, _In_reads_bytes_(length) const void* const source, _In_ const size_t length);

// Notes: Only callable inside an enclave.
// Return Value: a vector-alike of bytes from the VTL0 address space.
// Fails if the incoming buffer is not entirely outside the VTL1 address space.
// You can also use CopyFromVTL0ToVTL1<wil::secure_vector<uint8_t>> to get a vector that self-zeroes on destruction.
template <typename TVector = std::vector<uint8_t>>
TVector CopyFromVTL0ToVTL1(_In_reads_bytes_(length) const void* const source, _In_ const size_t length)
{
    // For now, we limit to byte-sized types to avoid confusion over what "length" means (elements? bytes?)
    using value_type = typename TVector::value_type;
    static_assert(std::is_standard_layout_v<value_type> && sizeof(value_type) == 1,
            "Must be vector of memcpy'able byte-sized type (like uint8_t or char)");
    TVector destination(length);
    THROW_IF_FAILED(CopyFromVTL0ToVTL1(destination.data(), source, length));
    return destination;
}

// Given an enclave blob header pointing to VTL0 data, copy the data into a VTL1
// vector instead.
template <typename TVector = std::vector<uint8_t>>
TVector CopyVtl0InputBlob(const AiEnclaveInputBlob& blob)
{
    THROW_HR_IF(E_INVALIDARG, blob.Size > 0 && blob.Data == NULL);
    return blob.Size ? CopyFromVTL0ToVTL1(blob.Data, blob.Size) : TVector{};
}

// Given a data blob in VTL1, copy it into an existing VTL0 output blob.
void CopyToVtl0OutputBlob(std::span<uint8_t const> data, AiEnclaveOutputBlob* vtl0Blob);

// Notes: Only callable inside an enclave.
// Return Value: Returns S_OK iff the function pointer is entirely outside the
// VTL1 address space.
//HRESULT CheckForVTL0Function(_In_ void* (*fn)(void*));

template<typename T>
HRESULT CheckForVTL0Span(std::span<T> span)
{
    constexpr auto maximumCount = (std::numeric_limits<typename std::span<T>::size_type>::max)() / sizeof(T);
    RETURN_HR_IF(E_INVALIDARG, span.size() > maximumCount);
    RETURN_IF_FAILED(CheckForVTL0Buffer(span.data(), span.size_bytes()));
    return S_OK;
}

template <typename T, typename Count>
HRESULT CheckForVTL0Span(T* pointer, Count elementCount)
{
    return CheckForVTL0Span(std::span(pointer, elementCount));
}

template <typename T>
HRESULT CopyFromVTL1ToVTL0(_Out_writes_bytes_(sizeof(T)) T* vtl0Destination, _In_reads_bytes_(sizeof(T)) const T* vtl1Source)
{
    return CopyFromVTL1ToVTL0(vtl0Destination, vtl1Source, sizeof(T));
}

template <typename T>
HRESULT CopyFromVTL1ToVTL0_NoLogging(_Out_writes_bytes_(sizeof(T)) T* vtl0Destination, _In_reads_bytes_(sizeof(T)) const T* vtl1Source)
{
    return CopyFromVTL1ToVTL0_NoLogging(vtl0Destination, vtl1Source, sizeof(T));
}

template <typename T>
HRESULT CopyFromVTL0ToVTL1(_Out_writes_bytes_(sizeof(T)) T* vtl1Destination, _In_reads_bytes_(sizeof(T)) const T* vtl0Source)
{
    return CopyFromVTL0ToVTL1(vtl1Destination, vtl0Source, sizeof(T));
}

template <typename T>
HRESULT CopyFromVTL0ToVTL1_NoLogging(_Out_writes_bytes_(sizeof(T)) T* vtl1Destination, _In_reads_bytes_(sizeof(T)) const T* vtl0Source)
{
    return CopyFromVTL0ToVTL1_NoLogging(vtl1Destination, vtl0Source, sizeof(T));
}

template <typename T>
T CopyFromVTL0ToVTL1(_In_reads_bytes_(sizeof(T)) const void* source)
{
    T destination;
    THROW_IF_FAILED(CopyFromVTL0ToVTL1(&destination, source, sizeof(T)));
    return destination;
}

namespace details
{
template<typename T>
concept trivial_span_or_vector = requires(T t) {
    { t.data() } -> std::same_as<typename T::value_type*>;
    { t.size() } -> std::integral;
} && std::is_trivially_destructible_v<typename T::value_type>;
}

// Automatically zeros a type on destruction. You can use it with
template <typename T>
[[nodiscard]] auto zero_on_exit(T& t)
{
    if constexpr (std::is_trivially_destructible_v<T>)
    {
        return wil::scope_exit([&t]() {
            SecureZeroMemory(std::addressof(t), sizeof(t));
        });
    }
    else if constexpr (std::is_array_v<T> && std::is_trivially_destructible_v<std::remove_extent_t<T>>)
    {
        return wil::scope_exit([&t]() {
            SecureZeroMemory(std::begin(t), std::size(t) * sizeof(std::remove_extent_t<T>));
        });
    }
    else if constexpr (details::trivial_span_or_vector<T>)
    {
        return wil::scope_exit([&t]() {
            SecureZeroMemory(t.data(), t.size() * sizeof(typename T::value_type));
        });
    }
    else
    {
        static_assert(std::is_trivially_destructible_v<T>, "zero_on_exit works with POD, not " __FUNCSIG__);
    }
}

// Verifies that the output blob is correctly formed. Note that this must be called only on
// AiEnclaveOutputBlob structures that are in VTLT1, pointing to VTL0 data.
void CheckOutputBlob(const AiEnclaveOutputBlob& outputBlob);

#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002L)
#endif

// RtlNtStatusToDosError converts STATUS_AUTH_TAG_MISMATCH to the very misleading
// HRESULT_FROM_WIN32(ERROR_CRC). Special-case that error and preserve it as itself.
inline HRESULT HResultFromBCryptStatus(NTSTATUS status)
{
    RETURN_HR_IF_EXPECTED((HRESULT)STATUS_AUTH_TAG_MISMATCH, status == STATUS_AUTH_TAG_MISMATCH);
    RETURN_IF_NTSTATUS_FAILED_EXPECTED(status);
    return S_OK;
}

namespace veil::vtl1
{
    constexpr bool buffers_are_equal(std::span<const uint8_t> a, std::span<const uint8_t> b)
    {
        if (a.size() != b.size())
        {
            return false;
        }
        return memcmp(a.data(), b.data(), a.size()) == 0;
    }
}

namespace veil::vtl1
{
    namespace utils
    {
        static constexpr size_t c_symmetricSecretSize = 32;
        using symmetric_secret = std::array<BYTE, c_symmetricSecretSize>;

        HRESULT GenerateSymmetricSecret(_Out_ symmetric_secret& symmetricSecretData);
        HRESULT GenerateSymmetricKey(_In_ symmetric_secret& symmetricSecretData, _Out_ wil::unique_bcrypt_key& symmetricKey);
        HRESULT GetAttestationReport(const std::vector<uint8_t>& enclaveReportData, _Inout_ std::vector<BYTE>& report);
        HRESULT GetAttestationForSessionChallenge(const symmetric_secret& symmetricSecret, const std::vector<BYTE>& sessionChallenge, _Inout_ std::vector<BYTE>& report);



    } // namespace enclave_utils

    inline void sleep(DWORD milliseconds)
    {
        CONDITION_VARIABLE cv;
        SRWLOCK lock;
        InitializeConditionVariable(&cv);
        InitializeSRWLock(&lock);

        AcquireSRWLockExclusive(&lock);
        SleepConditionVariableSRW(&cv, &lock, milliseconds, 0);
        ReleaseSRWLockExclusive(&lock);
    }
}
