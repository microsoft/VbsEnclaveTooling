// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "veil_arguments.any.h"

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
            std::wstring helloKeyName; // Note: not worrying about passing complex types until codegen tooling work is done.

            //out
            veil::any::args::data_blob securedEncryptionKeyBytes;
        };

        struct RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey
        {
            veil::any::args::data_blob securedEncryptionKeyBytes;

            // out
            bool needsReseal = true;
            veil::any::args::data_blob resealedEncryptionKeyBytes;
        };
    }
}
