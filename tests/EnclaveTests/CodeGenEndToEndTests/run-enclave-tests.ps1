<#
.SYNOPSIS

Run the enclave tests and copying of binaries to the target machine

.DESCRIPTION

This script will copy the TestEnclave.dll binary to a connected device, and run
tests using TAEF. Each step is optional along the way. Defaults to using TAEF's /runon option to directly
invoke TAEF's remote service, but supports "copy and invoke in TShell" as well.

.PARAMETER target

Target machine name or IP address. Defaults to TShell's currently connected device.

.PARAMETER taef

Specifies the path to TAEF's te.exe for runon or local execution. Defaults to "c:\tests\te.exe".

.PARAMETER run

Selects whether the test uses TAEF's "runon", option or uses TShell's "cmdd te.exe", or skips running 
the tests entirely.

.PARAMETER copy

Enables copying of the TAEF binaries and enclave bits via putd in TShell. Enabled by default when connected
to a device with TShell.

#>
param(
    [Parameter()]
    [ValidateSet('x64', 'arm64')]
    [string]$Architecture = "x64",
    [Parameter()]
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = "Debug",
    [string]$outdir = "$PSScriptRoot\_build\$Architecture\$Configuration",
    [string]$target = $DeviceAddress,

    # If we update Taef this path will need to be updated to the newer version
    [string]$taef = "$PSScriptRoot\packages\Microsoft.Taef.10.93.240607003\build\Binaries\$Architecture\TE.exe",
    [switch]$copy = ($null -ne $DeviceAddress),

    [Parameter()]
    [ValidateSet('runon', 'tshell', 'no')]
    [string]$run = "runon",

    [string]$taefArgs
)

function Show-HowToNuget
{
    Write-Host "Couldn't find TAEF at $taef. Check that the Nuget package is installed in the root packages folder"
}

if ((($run -eq "runon") -or ($run -eq "tshell")) -and -not $target) {
    Write-Error "You need to specify a target machine to run on, like '-target 127.0.0.1', or connect"
    Write-Error "to a device with TShell via 'connectd' or similar, which picks up the target argument"
    Write-Error "from the $$DeviceAddress environmental setting."
    return
}

$tests = @(
    "TestHostApp.dll"
)

# In copy mode for TShell, put the built binaries into the test path. Also put the CRT base DLL,
# or tests will fail with a "dll not found" on ucrtbased.dll
if ($copy)
{
    putd $outdir\TestEnclave.dll c:\data\test\bin
    putd $outdir\TestHostApp.dll c:\data\test\bin
    $crtBaseDll = Get-ChildItem -r 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\ucrt\ucrtbased.dll' | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
    putd $crtBaseDLl c:\data\test\bin

    #Copy dll's needed to run taef to c:\taef_data on the target device. Make sure when Taef package is updated this version
    # number is also changes.
    $taef_binaries_location = "$PSScriptRoot\packages\Microsoft.Taef.10.93.240607003\build\Binaries\$Architecture\*"
    putd $taef_binaries_location c:\taef_data\
}

# The Taef service must be installed on the machine before attempting to use the /runon option
# or the command will fail
if ($run -eq "runon")
{
    $taefCmd = get-command $taef -ErrorAction SilentlyContinue
    if (-not $taefCmd)
    {
        Show-HowToNuget;
        return
    }

    # Per the example above, it is important that the versions of TAEF remotely and locally must match.
    # So, override the value above with whatever you have installed remotely.
    & $taefCmd ($tests | %{ join-path $outdir $_ }) /logOutput:low /runas:elevatedUser /runon:$target $taefArgs
}
# Tshell must already be installed on the remote machine and connected before using the -tshell switch
# or the command will fail.
elseif ($run -eq "tshell")
{
    cdd c:\data\test\bin

    # separate test dlls by spaces.
    cmdd c:\taef_data\te.exe /logOutput:low /runas:elevatedUser ($tests -join ' ') $taefArgs
}

