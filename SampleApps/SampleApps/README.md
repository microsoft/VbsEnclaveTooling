Running the sample host app
======================================================================

Steps
------------

1. Running in a VM using Visual Studio
	- Create a VM, turn on Windows Security -> Device Security -> Core Isolation -> Memory integrity. Restart the VM. 
You would be running your app here.
	- Please make sure you have Microsoft.Windows.SDK.cpp version 10.0.26100.2454 installed on your host machine where 
you would be building code. You may have to downgrade your SDK version if needed.
	- Install Visual Studio Remote Debugger in your VM. 
https://learn.microsoft.com/en-us/visualstudio/debugger/remote-debugging?view=vs-2022
	- Set up Visual Studio remote debugger for the Host app. 
https://learn.microsoft.com/en-us/visualstudio/debugger/remote-debugging?view=vs-2022
	- Make sure you have the enclave dll available in the working directory of the VM. You can specify the absolute dll 
path in Visual Studio -> SampleHostApp -> Properties -> Debugging -> Remote Windows Debugger -> Additional files to 
let VS do place it on the VM.
	- F5 on Visual studio will launch the app on your VM.
	- You should be able to set breakpoints in host and debug. You can use debug_print commands in the Enclave code to 
help debug.
	- You could also launch the host app and use Windbg -> Attach to process to debug code inside the enclave.


1. Known issues:
	- No certificates were found that met all the given criteria.
		- Make sure to go through Step 3 in 
https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide and run the following 
commands.
		- PS C:\WINDOWS\system32> New-SelfSignedCertificate -CertStoreLocation Cert:\\CurrentUser\\My -DnsName 
"TheDefaultTestEnclaveCertName" -KeyUsage DigitalSignature -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA 
-HashAlgorithm SHA256 -TextExtension 
"2.5.29.37={text}1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.76.57.1.15,1.3.6.1.4.1.311.97.814040577.346743380.4783503.105
532347"	
		- You would see the following:
		   PSParentPath: Microsoft.PowerShell.Security\Certificate::CurrentUser\My

			Thumbprint                                Subject
			----------                                -------
			4BCEEFFE327F46DFB2401F3460123BB016B50C22  CN=TheDefaultTestEnclaveCertName



Developer flow: Create a host app, encrypt and decrypt data in enclave
======================================================================

Steps
------------
1. In your host app set up enclave as shown below
```
    // Create app+user enclave identity
    auto ownerId = veil::vtl0::appmodel::owner_id();

    // Load enclave
    auto flags = ENCLAVE_VBS_FLAG_DEBUG;

    auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
    veil::vtl0::enclave::load_image(enclave.get(), L"SampleEnclave.dll");
    veil::vtl0::enclave::initialize(enclave.get(), 1);

    // Register framework callbacks
    veil::vtl0::enclave_api::register_callbacks(enclave.get());
```		  
1. Create enclave dll- SampleEnclave.dll

	Refer to VBS Enclave development guide: 
https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide
	Make sure you have made the following [changes to the compiler and linker configurations of your Enclave dll] (https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide#:~:text=Before%20we%20can%20build%20the%20test%20enclave%20DLL%2C%20some%20changes%20to%20the%20compiler%20and%20linker%20configurations%20are%20required%3A) (VS 
dll). 

1. Telemetry support

	- We support telemetry strings from the Enclave that are 2048 chars or shorter. Refer to telemetry usage in the 
sample app.
	- Telemetry files are stored in c:\VeilLogs.	