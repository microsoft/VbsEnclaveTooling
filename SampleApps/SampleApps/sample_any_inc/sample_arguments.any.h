// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "veil_arguments.any.h"
#include "utils.any.h"
#include "telemetry.any.h"

namespace sample
{
    namespace args
    {
        // Taskpool
        struct RunTaskpoolExample
        {
            uint32_t threadCount;
        };

        // Hello-secured encryption keys
        struct RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey
        {
            std::wstring helloKeyName;
            veil::any::telemetry::eventLevel activityLevel;

            //out
            veil::any::args::data_blob securedEncryptionKeyBytes;
            veil::any::args::data_blob enclaveLog;
        };

        struct RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey
        {
            veil::any::args::data_blob securedEncryptionKeyBytes;
            std::wstring dataToEncrypt;
            bool isToBeEncrypted = false; // Controls if the Load flow is used for encryption or decryption
            veil::any::telemetry::eventLevel activityLevel;

            // out
            veil::any::args::data_blob resealedEncryptionKeyBytes;
            veil::any::args::data_blob encryptedInputBytes;
            veil::any::args::data_blob tag;
            veil::any::args::data_blob decryptedInputBytes;
            veil::any::args::data_blob enclaveLog;
        };
    }
}
