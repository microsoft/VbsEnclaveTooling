// Copyright (c) Microsoft Corporation. All rights reserved.

#pragma once

namespace Vtl1MutualAuthNoStd
{
// Header constants used throughout the namespace - defined once to eliminate duplication
static constexpr BYTE CHALLENGE_HEADER[10] = {'c','h','a','l','l','e','n','g','e','\0'};
static constexpr BYTE ATTESTATION_HEADER[8] = {'a','t','t','e','s','t','\0','\0'};
static constexpr SIZE_T c_challengeSize = 24;

struct SessionChallenge
{
    static constexpr SIZE_T c_sessionChallengeVectorSize = sizeof(CHALLENGE_HEADER) + c_challengeSize + sizeof(PS_TRUSTLET_TKSESSION_ID);
    BYTE challenge[c_challengeSize];
    PS_TRUSTLET_TKSESSION_ID sessionId;

    HRESULT ToVector(_Out_writes_bytes_(c_sessionChallengeVectorSize) BYTE* buffer) const
    {
        if (buffer == NULL)
        {
            return E_INVALIDARG;
        }

        SIZE_T index = 0;

        memcpy(buffer + index, CHALLENGE_HEADER, sizeof(CHALLENGE_HEADER));
        index += sizeof(CHALLENGE_HEADER);

        memcpy(buffer + index, challenge, c_challengeSize);
        index += c_challengeSize;

        memcpy(buffer + index, &sessionId, sizeof(sessionId));
        index += sizeof(sessionId);

        return S_OK;
    }

    static HRESULT FromVector(const BYTE* buffer, UINT32 bufferSize, _Out_ SessionChallenge* result)
    {
        if (buffer == NULL || result == NULL)
        {
            return E_INVALIDARG;
        }

        SIZE_T expectedSize = sizeof(CHALLENGE_HEADER) + c_challengeSize + sizeof(result->sessionId);
        if (bufferSize < expectedSize)
        {
            return NTE_BAD_DATA;
        }

        SIZE_T index = 0;

        // Check if buffer starts with the expected challenge header
        if (0 != memcmp(CHALLENGE_HEADER, buffer, sizeof(CHALLENGE_HEADER)))
        {
            return NTE_BAD_TYPE;
        }
        index += sizeof(CHALLENGE_HEADER);

        // Copy challenge data
        memcpy(result->challenge, buffer + index, c_challengeSize);
        index += c_challengeSize;

        // Copy session ID
        memcpy(&result->sessionId, buffer + index, sizeof(result->sessionId));
        index += sizeof(result->sessionId);

        return S_OK;
    }
};

struct AttestationData
{
    static constexpr SIZE_T c_symmetricSecretSize = 32;
    static constexpr SIZE_T c_attestationDataVectorSize = sizeof(ATTESTATION_HEADER) + c_challengeSize + c_symmetricSecretSize;
    BYTE challenge[c_challengeSize];
    BYTE symmetricSecret[c_symmetricSecretSize];

    HRESULT ToVector(_Out_writes_bytes_(c_attestationDataVectorSize) BYTE* buffer) const
    {
        if (buffer == NULL)
        {
            return E_INVALIDARG;
        }

        SIZE_T index = 0;

        memcpy(buffer + index, ATTESTATION_HEADER, sizeof(ATTESTATION_HEADER));
        index += sizeof(ATTESTATION_HEADER);

        memcpy(buffer + index, challenge, c_challengeSize);
        index += c_challengeSize;

        memcpy(buffer + index, symmetricSecret, c_symmetricSecretSize);
        index += c_symmetricSecretSize;

        return S_OK;
    }

    static HRESULT FromVector(const BYTE* buffer, UINT32 bufferSize, _Out_ AttestationData* result)
    {
        if (buffer == NULL || result == NULL)
        {
            return E_INVALIDARG;
        }

        SIZE_T expectedSize = sizeof(ATTESTATION_HEADER) + c_challengeSize + c_symmetricSecretSize;
        if (bufferSize < expectedSize)
        {
            return NTE_BAD_DATA;
        }

        SIZE_T index = 0;

        // Check if buffer starts with the expected attestation header
        if (0 != memcmp(ATTESTATION_HEADER, buffer, sizeof(ATTESTATION_HEADER)))
        {
            return NTE_BAD_TYPE;
        }
        index += sizeof(ATTESTATION_HEADER);

        // Copy challenge data
        memcpy(result->challenge, buffer + index, c_challengeSize);
        index += c_challengeSize;

        // Copy symmetric secret
        memcpy(result->symmetricSecret, buffer + index, c_symmetricSecretSize);
        index += c_symmetricSecretSize;

        return S_OK;
    }
};
}
