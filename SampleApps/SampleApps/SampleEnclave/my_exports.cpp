// Copyright (c) Microsoft Corporation.
//

#include "pch.h"

#include <array>
#include <stdexcept>

#include <veil.any.h>

#include <enclave_interface.vtl1.h>
#include <export_helpers.vtl1.h>
#include <hello.vtl1.h>
#include <taskpool.vtl1.h>
#include <vtl0_functions.vtl1.h>

#include "sample_arguments.any.h"

//
// Hello-secured encryption key
//
void RunHelloSecuredEncryptionKeyExample_CreateEncryptionKeyImpl(_In_ sample::args::RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey* data)
{
    using namespace veil::vtl1::vtl0_functions;
    
    const bool requireEnclaveOwnerIdMatchesHelloContainerSecureId = false;

    debug_print("");
    debug_print(L"[Create flow]");
    debug_print("");
    
    // Create a hello key for the root of our Hello-secured encryption key
    debug_print(L"1. Creating a 'Hello' key: %ws", data->helloKeyName.c_str());
    auto [helloKey, createdKey] = veil::vtl1::hello::create_or_open_hello_key(data->helloKeyName, L"Let's secure the encryption key with this Hello key!");
    debug_print("");

    // Generate our encryption key
    debug_print(L"2. Generating our encryption key");
    auto encryptionKeyBytes = veil::vtl1::crypto::generate_symmetric_key_bytes();
    debug_print(L" ...CHECKPOINT: encryption key byte count: %d", encryptionKeyBytes.size());
    debug_print("");

    // Arbitrary metadata to encode in the final secured serialized key material blob saved on disk
    std::wstring customData = L"usage=for_decryption";

    // Secure our encryption key with Hello
    debug_print(L"3. Securing our encryption key with Hello");
    auto serializedHelloSecuredKey = veil::vtl1::hello::conceal_encryption_key_with_hello(
        helloKey.get(),
        data->helloKeyName,
        STANDARD_HELLO_KEY_CACHE_CONFIG,
        encryptionKeyBytes,
        veil::vtl1::as_data_span(customData),
        requireEnclaveOwnerIdMatchesHelloContainerSecureId);
    debug_print(L" ...CHECKPOINT: secured encryption key material byte count: %d", serializedHelloSecuredKey.size());
    debug_print("");
    
    // Seal it so only our enclave may open it
    debug_print(L"4. Sealing the serialized key material for our enclave only");
    auto sealedKeyMaterial = veil::vtl1::crypto::seal_data(serializedHelloSecuredKey, ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE, ENCLAVE_RUNTIME_POLICY_ALLOW_FULL_DEBUG);
    debug_print(L" ...CHECKPOINT: sealed key material byte count: %d", sealedKeyMaterial.size());
    debug_print("");

    // Erase our plain-text encryption key, (not necessary, but being explicit that we do not need this data anymore)
    encryptionKeyBytes.fill(0);

    // Return the secured encryption key to vtl0 host caller...
    auto buffer_vtl0 = veil::vtl1::memory::copy_to_vtl0_data_blob(&data->securedEncryptionKeyBytes, sealedKeyMaterial);
    buffer_vtl0.release();
}

ENCLAVE_FUNCTION RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey(_In_ PVOID pv) noexcept try
{
    auto data = reinterpret_cast<sample::args::RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey*>(pv);
    RunHelloSecuredEncryptionKeyExample_CreateEncryptionKeyImpl(data);
    return nullptr;
}
catch (...)
{
    using namespace veil::vtl1::vtl0_functions;
    auto error = veil::vtl1::implementation::export_helpers::get_back_thread_enclave_error(GetCurrentThreadId());
    debug_print(error->wmessage);

    LOG_CAUGHT_EXCEPTION();
    RETURN_HR_AS_PVOID(wil::ResultFromCaughtException());
}

bool RunHelloSecuredEncryptionKeyExample_LoadEncryptionKeyImpl(_In_ sample::args::RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey* data)
{
    using namespace veil::vtl1::vtl0_functions;
    const bool requireEnclaveOwnerIdMatchesHelloContainerSecureId = false;
    
    debug_print("");
    debug_print(L"[Load flow]");
    debug_print("");

    debug_print(L"1. Unsealing our encryption key (only our enclave can succeed this operation)");
    auto [unsealedBytes, unsealingFlags] = veil::vtl1::crypto::unseal_data(data->securedEncryptionKeyBytes);
    debug_print(L" ...CHECKPOINT: unsealed byte count: = %d", unsealedBytes.size());
    debug_print("");
    
    // Arbitrary metadata that must match what's encoded in the serialized key blob
    std::wstring expectedCustomData = L"usage=for_decryption";

    // Decrypt the encryption key
    debug_print(L"2. Unsecuring our encryption key with Hello");
    auto encryptionKey = veil::vtl1::hello::reveal_encryption_key_with_hello(unsealedBytes, veil::vtl1::as_data_span(expectedCustomData), requireEnclaveOwnerIdMatchesHelloContainerSecureId);
    debug_print(L" ...CHECKPOINT: encryption key handle: = %d", encryptionKey.get());
    debug_print("");

    if (data->isToBeEncrypted)
    {
        //
        // Now let's encrypt the input data with our encryption key
        //

        // Encrypting the user input data
        auto const SOME_PLAIN_TEXT = data->dataToEncrypt.c_str();

        // Let's encrypt the input text
        debug_print(L"3. Encrypting input text.");
        auto [encryptedText, tag] = veil::vtl1::crypto::encrypt(encryptionKey.get(), veil::vtl1::as_data_span(SOME_PLAIN_TEXT), veil::vtl1::crypto::zero_nonce);
        debug_print(L" ...CHECKPOINT: encrypted text's byte count: = %d", encryptedText.size());
        debug_print("");

        // Return the encrypted input to vtl0 host caller...
        auto buffer_vtl0 = veil::vtl1::memory::copy_to_vtl0_data_blob(&data->encryptedInputBytes, encryptedText);
        buffer_vtl0.release();

        auto buffer1_vtl0 = veil::vtl1::memory::copy_to_vtl0_data_blob(&data->tag, tag);
        buffer1_vtl0.release();

        return true;
    }
    else
    {
        // Let's decrypt the stored encrypted input
        debug_print(L"4. Decrypting text...");
        auto decryptedText = veil::vtl1::crypto::decrypt(encryptionKey.get(), data->encryptedInputBytes, veil::vtl1::crypto::zero_nonce, data->tag);
        std::wstring decryptedString = veil::vtl1::to_wstring(decryptedText);
        debug_print(L" ...CHECKPOINT: decrypted text: = %ws", decryptedString.c_str());
        debug_print("");

        // Return the decrypted input to vtl0 host caller...
        auto buffer_vtl0 = veil::vtl1::memory::copy_to_vtl0_data_blob(&data->decryptedInputBytes, decryptedText);
        buffer_vtl0.release();

        return true;
    }
}

ENCLAVE_FUNCTION RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey(_In_ PVOID pv) noexcept try
{
    auto data = reinterpret_cast<sample::args::RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey*>(pv);
    if (!RunHelloSecuredEncryptionKeyExample_LoadEncryptionKeyImpl(data)) 
    { }
    return nullptr;
}
catch (...)
{
    using namespace veil::vtl1::vtl0_functions;
    auto error = veil::vtl1::implementation::export_helpers::get_back_thread_enclave_error(GetCurrentThreadId());
    debug_print(error->wmessage);

    LOG_CAUGHT_EXCEPTION();
    RETURN_HR_AS_PVOID(wil::ResultFromCaughtException());
}
