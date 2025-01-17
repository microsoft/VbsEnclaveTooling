// © Microsoft Corporation. All rights reserved.

#include "pch.h"

#include <array>

#include <bcrypt.h>

#include "mutualauth.vtl1.h"
#include "utils.vtl1.h"

#include "EnclaveServices.h"
//#include "shared_enclave.h"
//#include "enclavethreading.h"

inline HRESULT CheckForVTL0Buffer(_In_ const void* const, _In_ const size_t)
{
    // todo: implemented by tooling repo
    return S_OK;
}

inline HRESULT CheckForVTL1Buffer(_In_ const void* const, _In_ const size_t)
{
    // todo: implemented by tooling repo
    return S_OK;
}

#include <wil/enclave/push_disable_wil_logging.h>
HRESULT CopyFromVTL0ToVTL1_NoLogging(
    _Out_writes_bytes_(length) void* const vtl1Destination, _In_reads_bytes_(length) const void* const vtl0Source, _In_ const size_t length)
{
#pragma warning(push)
#pragma warning(disable : 6001) // Suppress warning about uninitialized memory, as CheckForVTL0Buffer/1 don't dereference the first parameter
    RETURN_IF_FAILED_EXPECTED(CheckForVTL0Buffer(vtl0Source, length));
    RETURN_IF_FAILED_EXPECTED(CheckForVTL1Buffer(vtl1Destination, length));
#pragma warning(pop)
    memcpy_s(vtl1Destination, length, vtl0Source, length);
    return S_OK;
}
#include <wil/enclave/pop_enable_wil_logging.h>

HRESULT CopyFromVTL1ToVTL0(
    _Out_writes_bytes_(length) void* const vtl0Destination, _In_reads_bytes_(length) const void* const vtl1Source, _In_ const size_t length)
{

#pragma warning(push)
#pragma warning(disable : 6001) // Suppress warning about uninitialized memory, as CheckForVTL0Buffer/1 don't dereference the first parameter.
    RETURN_IF_FAILED(CheckForVTL1Buffer(vtl1Source, length));
    RETURN_IF_FAILED(CheckForVTL0Buffer(vtl0Destination, length));
#pragma warning(pop)
    memcpy_s(vtl0Destination, length, vtl1Source, length);
    return S_OK;
}

void CopyToVtl0OutputBlob(std::span<uint8_t const> data, AiEnclaveOutputBlob* vtl0Blob)
{
    // Recheck the blob content...
    auto vtl1Blob = CopyFromVTL0ToVTL1<AiEnclaveOutputBlob>(vtl0Blob);

    if (vtl1Blob.Capacity < data.size())
    {
        vtl0Blob->Size = data.size();
        THROW_HR(HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER));
    }
    else if (data.empty())
    {
        vtl0Blob->Size = data.size();
    }
    else
    {
        THROW_IF_FAILED(CopyFromVTL1ToVTL0(vtl1Blob.Data, data.data(), data.size()));
        vtl0Blob->Size = data.size();
    }
}

// Verifies that the output blob is correctly formed. Note that this must be called only on
// AiEnclaveOutputBlob structures that are in VTLT1, pointing to VTL0 data.
void CheckOutputBlob(const AiEnclaveOutputBlob& outputBlob)
{
    // Output blobs can be "all zeros" (meaning all fields empty), or they can have a data _and_
    // a nonzero capacity buffer.  If the data pointer is present with a capacity field,
    // data+capacity must be a valid VTL0 buffer.
    if (outputBlob.Data)
    {
        THROW_HR_IF(E_INVALIDARG, outputBlob.Capacity == 0);
        THROW_HR_IF(E_INVALIDARG, outputBlob.Size != 0);
        THROW_IF_FAILED(CheckForVTL0Buffer(outputBlob.Data, outputBlob.Capacity));
    }
    else
    {
        THROW_HR_IF(E_INVALIDARG, outputBlob.Capacity != 0);
        THROW_HR_IF(E_INVALIDARG, outputBlob.Size != 0);
    }
}

#include <wil/enclave/push_disable_wil_logging.h>
#pragma region WIL logging not allowed (used by logging code)

// Enclave image creation policies
#ifndef ENCLAVE_MAX_THREADS
#define ENCLAVE_MAX_THREADS 16
#endif

uint32_t g_threadEnclaveCalloutCounts[ENCLAVE_MAX_THREADS];

/*
extern uint32_t& GetThreadEnclaveCalloutCount_NoLogging()
{
    auto index = GetCurrentEnclaveThreadIndex();
    FAIL_FAST_IMMEDIATE_IF(index < 0 || index >= ENCLAVE_MAX_THREADS);
    return g_threadEnclaveCalloutCounts[index];
}
*/
#pragma endregion
#include <wil/enclave/pop_enable_wil_logging.h> // WIL logging permitted again



namespace veil::vtl1::utils
{

    HRESULT GenerateSymmetricSecret(_Out_ symmetric_secret& symmetricSecretData)
    {
        RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptGenRandom(
            nullptr, symmetricSecretData.data(), static_cast<ULONG>(symmetricSecretData.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG)));
        return S_OK;
    }

    HRESULT GenerateSymmetricKey(_In_ symmetric_secret& symmetricSecretData, _Out_ wil::unique_bcrypt_key& symmetricKey)
    {
        wil::unique_bcrypt_key symKey{};
        RETURN_IF_NTSTATUS_FAILED(BCryptGenerateSymmetricKey(
            BCRYPT_AES_GCM_ALG_HANDLE,
            &symKey,
            nullptr,
            0,
            symmetricSecretData.data(),
            static_cast<ULONG>(symmetricSecretData.size()),
            0));

        symmetricKey = std::move(symKey);
        return S_OK;
    }

    HRESULT GetAttestationReport(const std::vector<uint8_t>& enclaveReportData, _Inout_ std::vector<BYTE>& report)
    {
        IEnclaveServices& enclaveServices = GetEnclaveServices();

        UINT32 reportSize{};
        RETURN_IF_FAILED(enclaveServices.GetAttestationReport(enclaveReportData.data(), nullptr, 0, &reportSize));

        std::vector<BYTE> attestationReport(reportSize);
        RETURN_IF_FAILED(enclaveServices.GetAttestationReport(
            enclaveReportData.data(), attestationReport.data(), static_cast<UINT32>(attestationReport.size()), &reportSize));

        report = std::move(attestationReport);
        return S_OK;
    }

    HRESULT GetAttestationForSessionChallenge(const symmetric_secret& symmetricSecret, const std::vector<BYTE>& sessionChallenge, _Inout_ std::vector<BYTE>& report)
    {
        IEnclaveServices& enclaveServices = GetEnclaveServices();

        auto localSessionChallenge = Vtl1MutualAuth::SessionChallenge::FromVector(sessionChallenge);

        Vtl1MutualAuth::AttestationData attestationData{};
        static_assert(localSessionChallenge.challenge.size() == attestationData.challenge.size());
        memcpy(attestationData.challenge.data(), localSessionChallenge.challenge.data(), attestationData.challenge.size());

        /*
        RETURN_IF_FAILED(BCryptGenRandom(
            nullptr, attestationData.symmetricSecret.data(), static_cast<ULONG>(attestationData.symmetricSecret.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG));

        wil::unique_bcrypt_key symKey{};
        RETURN_IF_NTSTATUS_FAILED(BCryptGenerateSymmetricKey(
            BCRYPT_AES_GCM_ALG_HANDLE,
            &symKey,
            nullptr,
            0,
            attestationData.symmetricSecret.data(),
            static_cast<ULONG>(attestationData.symmetricSecret.size()),
            0));

        m_symmetricKey = std::move(symKey);
        */
        memcpy(attestationData.symmetricSecret.data(), symmetricSecret.data(), symmetricSecret.size());


        auto attestationBuffer = attestationData.ToVector();
        std::array<BYTE, ENCLAVE_REPORT_DATA_LENGTH> enclaveData{};
        RETURN_HR_IF(NTE_BAD_DATA, attestationBuffer.size() > enclaveData.size());
        memcpy(enclaveData.data(), attestationBuffer.data(), attestationBuffer.size());

        UINT32 reportSize{};
        RETURN_IF_FAILED(enclaveServices.GetAttestationReport(enclaveData.data(), nullptr, 0, &reportSize));

        std::vector<BYTE> attestationReport(reportSize);
        RETURN_IF_FAILED(enclaveServices.GetAttestationReport(
            enclaveData.data(), attestationReport.data(), static_cast<UINT32>(attestationReport.size()), &reportSize));

        TRUSTLET_BINDING_DATA trustletData{};
#define TRUSTLETIDENTITY_NGC 6
        trustletData.TrustletIdentity = TRUSTLETIDENTITY_NGC;
        trustletData.TrustletSessionId = localSessionChallenge.sessionId;
        trustletData.TrustletSvn = 0;
        trustletData.Reserved1 = 0;
        trustletData.Reserved2 = 0;

        UINT32 encryptedSize{};
        RETURN_IF_FAILED(enclaveServices.EncryptDataForTrustlet(
            attestationReport.data(), static_cast<UINT32>(attestationReport.size()), &trustletData, nullptr, 0, &encryptedSize));

        std::vector<BYTE> encryptedReport(encryptedSize);
        RETURN_IF_FAILED(enclaveServices.EncryptDataForTrustlet(
            attestationReport.data(),
            static_cast<UINT32>(attestationReport.size()),
            &trustletData,
            encryptedReport.data(),
            static_cast<UINT32>(encryptedReport.size()),
            &encryptedSize));

        report = std::move(encryptedReport);
        return S_OK;
    }
}

