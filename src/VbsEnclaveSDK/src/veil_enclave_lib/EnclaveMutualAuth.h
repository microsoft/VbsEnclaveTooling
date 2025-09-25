// Copyright (c) Microsoft Corporation. All rights reserved.

#pragma once

#include "Vtl1MutualAuth.h"

namespace EnclaveUtils
{

class EnclaveMutualAuthOld : public Vtl1MutualAuth::MutualAuthOld
{
    public:
    EnclaveMutualAuthOld() : Vtl1MutualAuth::MutualAuthOld(true) {}   // Enclave is always initiator for MutualAuth
    ~EnclaveMutualAuthOld() {}

    HRESULT GetAttestationForSessionChallenge(const std::vector<BYTE>& sessionChallenge, _Inout_ std::vector<BYTE>& report);
};

class EnclaveMutualAuth : public Vtl1MutualAuth::MutualAuth
{
    public:
    EnclaveMutualAuth() : Vtl1MutualAuth::MutualAuth(true) {}   // Enclave is always initiator for MutualAuth
    ~EnclaveMutualAuth() {}

    HRESULT GetAttestationForSessionChallenge(const std::vector<BYTE>& sessionChallenge, _Inout_ std::vector<BYTE>& report);
};

}   // namespace EnclaveUtils
