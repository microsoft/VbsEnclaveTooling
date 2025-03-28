### Running the Taef tests for the TestEnclave dll.

The Enclave Taef tests require the machine that will contain the enclave to
enable test-signing and require the enclave to be signed with a certificate that
is available on the machine. As part of the `TestEnclave` project, the 
[EnclaveBuild.targets](.\TestEnclave\EnclaveBuild.targets) file should sign the `TestEnclave.dll`
using the certificate you provide. Most developers'  primary dev machines won't be set up to
use test signing which is needed to load the enclave dll in debug mode.
So your best bet is to remotely run the taef tests on a VM that has test signing enabled.
We recommend using TShell to connect to the remote machine and run the following from
the `EnclaveTests` folder on your primary dev machine (Not the remote machine):

`.\run-enclave-tests.ps1 -run tshell`

This script should copy the necessary Taef binaries to the remote machine and run
the tests. `Note:` you may need to set the execution policy to "Bypass" on your machine
if it doesn't allow unsigned scripts. You can do this for the current process by
running the following in a PowerShell window on your primary dev machine.

`Set-ExecutionPolicy Bypass -Scope Process -Force`

`Note:` Taef tests can't run inside an enclave. So we use VTL0 (`TestHostApp`)
as a proxy to test enclave functionality through function calls into the `TestEnclave` enclave 
during the test. The tests involve calling into functions within the `TestEnclave.dll`, and these
functions return some result back to VTL0. This can either be as a function return value or
an InOut or Out parameter. Based on the result VTL0 expects it either passes or fails the test.

Your developer inner loop can be something like this:

-   Change code in Visual Studio and/or update [CodeGenTestFunctions.edl](.\CodeGenTestFunctions.edl)
-   Build the `TestHostApp` project since it will build the `TestEnclave` project as
    well. If you changed the .edl file you might need to update code in the
    [Vtl1ExportsImplementations](.\TestEnclave\Vtl1ExportsImplementations.cpp),
    [Vtl0CallbackImplementations](.\TestHostApp\Vtl0CallbackImplementations.cpp) and 
    [TestEnclaveTaefTests](.\TestHostApp\TestEnclaveTaefTests.cpp) files with new code based on what was
    generated.
- Connect to the remote machine using TShell:<br>
   `tshell.cmd` or `tshell.ps1` or `tshell` if its available in you `%Path%` environment variable.<br>
   Then: <br> 
   `open-device -target <targets IP address> `
- In a connected tshell window,
   `.\run-enclave-tests.ps1 -run tshell`

The script also has a `-run no` switch, so you can copy the Taef binarys to the remote machine without
running the tests. This way you can use `WinDbg` to debug them
(or run them manually.) To do that instead:

-   Change code in Visual Studio, build
-   Run the script with the `-run no` option
-   Connect your primary dev machines `WinDbg` instance to your guest VM
    -   `File` > `Start Debugging` > `Connect to...`
    -   Refresh machines to find your VM
    -   Select `Launch Executable`
    -   Set Executable to `c:\taef_data\te.exe`
    -   Set Arguments to `/inproc TestHostApp.dll /name:*YourTestName*`
    -   Set Start Directory to `c:\data\test\bin`. This is the directory the `TestEnclave.dll` is copied to
-   Click the `Debug` button

You can set breakpoints in the enclave DLL with `bm
TestEnclave!TestFunctionName` or similar. Note: the `TestEnclave` name is not the name
of the Taef test. It is the name of an actual function within the enclave you want to
debug. Be sure to insert the functions namespace in from of the function name as well.
E.g `bm TestEnclave!VbsEnclave::VTL1_Declarations::ReturnInt8ValPtr_From_Enclave`
Because the `TestEnclave` are
configured with debugging enabled, the debugger will pick up the symbol load and
help you break in when it's hit. Then you can F10/F11 in the normal way!

There are other `-run` options as well, such as `-run runon` which uses TAEF's
`/runon:ip.ad.dr.ess` option. Note that this requires a matched pair of TAEF on
the host & guest, and direct connectivity between them.
