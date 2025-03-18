Developer flow: Create a host app, encrypt and decrypt data in enclave
======================================================================

Steps
------------
1. In your host app set up enclave as shown below

    // Create app+user enclave identity
    auto ownerId = veil::vtl0::appmodel::owner_id();

    // Load enclave
    auto flags = ENCLAVE_VBS_FLAG_DEBUG;

    auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
    veil::vtl0::enclave::load_image(enclave.get(), L"SampleEnclave.dll");
    veil::vtl0::enclave::initialize(enclave.get(), 1);

    // Register framework callbacks
    veil::vtl0::enclave_api::register_callbacks(enclave.get());

	- Encrypt flow:
		- Call into Enclave to create an encryption key. Encrytion key will be Windows Hello encrypted and sealed by the enclave, can only be unsealed by the same enclave and decrypted by Windows Hello.
		  veil::vtl0::enclave::call_enclave(enclave, "RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey", data);
		- Write the Hello encrypted, enclave sealed encryption key bytes received from the Enclave to a file on disk.
		- Pass the encryption key bytes and the input to be encrypted into the Enclave for encryption
		  veil::vtl0::enclave::call_enclave(enclave, "RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey", loadData);
		- Write the encrypted data back to a file on disk.  
		  
	- Decrpyt flow:
		- Load the encryption key bytes and encryted data bytes from disk.
		- Pass the encrypted key and the data to be decrypted in the Enclave.
		  veil::vtl0::enclave::call_enclave(enclave, "RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey", data);
		- Decrypted data is passed back to the host app.
		  
1. Create enclave dll- SampleEnclave.dll
	
Refer to VBS Enclave development guide: https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide
Make sure you have made the following changes to the compiler and linker configurations of your Enclave dll (VS dll). 
https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide#:~:text=Before%20we%20can%20build%20the%20test%20enclave%20DLL%2C%20some%20changes%20to%20the%20compiler%20and%20linker%20configurations%20are%20required%3A
	
	- Implement RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey
		- Create a hello key for the root of our Hello-secured encryption key
		- Generate an encryption key
		- Secure our encryption key with Hello
		- Seal encryption key so only our enclave may open it
		- Return the secured encryption key to vtl0 host caller
	- Implement RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey
		- Unseal the encrypted encryption key bytes received from the host
		- Decrypt the encryption key using Windows Hello
		- Use the encryption key to encrypt/decrypt input data.

1. Debugging in a VM using Visual Studio
	- Create a VM, turn on Windows Security -> Device Security -> Core Isolation -> Memory integrity. Restart the VM.
	- Set up Accounts -> Sign-in options -> Windows Hello PIN. Make sure you are in a Basic session, otherwise Windows Hello settings are not available.
	- Install Visual Studio Remote Debugger in your VM. https://learn.microsoft.com/en-us/visualstudio/debugger/remote-debugging?view=vs-2022
	- Set up Visual Studio remote debugger for the Host app. https://learn.microsoft.com/en-us/visualstudio/debugger/remote-debugging?view=vs-2022
	- Make sure you have the enclave dll available in the working directory of the VM. 
	- You should be able to set breakpoints in host and debug. You can use debug_print commands in the Enclave code to help debug
	- You could also use Windbg to debug code inside the enclave.