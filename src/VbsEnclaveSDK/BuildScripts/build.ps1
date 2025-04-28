[CmdletBinding()]
Param(
    [ValidateSet('all', 'x64', 'arm64','X64', 'ARM64')]
    [System.String]
    $Platforms = "x64",
    
    [ValidateSet('all', 'debug', 'release', 'Debug', 'Release')]
    [System.String]
    $Configurations = "debug",
    
    [System.Boolean]
    $IsLocalBuild = $true,

    [System.Boolean]
    $BuildCodeGenNugetDependency = $true,

    [switch]
    $Help
)

$StartTime = Get-Date

if ($Help)
{
    Write-Host @"
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.

Syntax:
      Build.ps1 [options]

Description:
      Builds the vbs enclave implementation library solution.

Options:

  -Platform <platform>
      Only build the selected platform(s)
      Example: -Platform x64
      Example: -Platform all

  -Configuration <configuration>
      Only build the selected configuration(s)
      Example: -Configuration Release
      Example: -Configuration all

  -IsLocalBuild
      Changes build behavior to build as if it was not in a pipeline.

  -BuildCodeGenNugetDependency
      Used to indicate whether or not the Vbs Enclave code generator nuget package should be built.

  -Help
      Display this usage message.
"@
  Exit
}
# Note: new additions to the commandline build should be added to the VisualStudioUiBuild.targets file as well
# so the building behavior in VS UI and commandline stay the same.
$ErrorActionPreference = "Stop"
$BuildRootDirectory = (Split-Path $MyInvocation.MyCommand.Path)
$BaseSolutionDirectory = Split-Path $BuildRootDirectory
$lowerCasePlatforms = $Platforms.ToLower()
$lowerCaseConfigurations = $Configurations.ToLower()

if ($lowerCasePlatforms -eq "all")
{
    $BuildPlatform = @("x64", "arm64")
}
else
{
    $BuildPlatform = @($lowerCasePlatforms)
}

if ($lowerCaseConfigurations -eq "all")
{
    $Build_Configuration = @("debug", "release")
}
else
{
    $Build_Configuration = @($lowerCaseConfigurations)
}

if ($BuildCodeGenNugetDependency)
{
    $codeGenBuildScriptPath = "$BaseSolutionDirectory\..\..\BuildScripts\build.ps1"
    & $codeGenBuildScriptPath -Platforms $Platforms -Configurations $Configurations -IsLocalBuild $IsLocalBuild -NugetPackagesToOutput "CodeGenOnly"
}

# Edit this to change the official version of the nuget package at build time.
# For local builds make sure "$IsLocalBuild" is true.
$BuildTargetVersion = [System.Version]::new(0, 0, 1)

if ($IsLocalBuild)
{
    # Use the triple zeros as the version number for local builds.
    $BuildTargetVersion = [System.Version]::new(0, 0, 0)
}

$msbuildPath = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -prerelease -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe

Try 
{
    $solutionName = "vbs_enclave_implementation_library"
    $nuspecFile = "$BaseSolutionDirectory\src\veil_nuget\Nuget\Microsoft.Windows.VbsEnclave.SDK.nuspec"
    $nugetPackProperties = "target_version=$BuildTargetVersion;"

    # Run nuget restore
    $nugetPath = & "$BaseSolutionDirectory\..\..\BuildScripts\NugetExeDownloader.ps1"
    Write-Host "Running nuget restore for $solutionName"
    & $nugetPath restore "$BaseSolutionDirectory\$solutionName.sln"

    # Build
    foreach ($platform in $BuildPlatform)
    {
      foreach ($configuration in $Build_Configuration)
      {
        Write-Host "Building $solutionName for EnvPlatform: $BuildPlatform Platform: $platform Configuration: $configuration"
        $msbuildArgs = 
        @(
            ("$BaseSolutionDirectory\$solutionName.sln"),
            ("/p:Platform=$platform"),
            ("/p:Configuration=$configuration"),
            ("/restore"),
            ("/binaryLogger:$BaseSolutionDirectory\_build\$platform\$configuration\$solutionName.$platform.$configuration.binlog")
        )

        & $msbuildPath $msbuildArgs
        if ($LASTEXITCODE -ne 0)
        {
            Write-Error "MSBuild failed with exit code $LASTEXITCODE"
            exit $LASTEXITCODE
        }

        # Now update the nuget pack properties
        $cppSupportLibPath = "$BaseSolutionDirectory\_build\$platform\$configuration\veil_enclave_cpp_support_lib.lib"
        $nugetPackProperties += "vbsenclave_sdk_cpp_support_$platform"+"_lib=$cppSupportLibPath;"
        $veilEnclaveLibPath = "$BaseSolutionDirectory\_build\$platform\$configuration\veil_enclave_lib.lib"
        $nugetPackProperties += "vbsenclave_sdk_enclave_$platform"+"_lib=$veilEnclaveLibPath;"
        $veilHostLibPath = "$BaseSolutionDirectory\_build\$platform\$configuration\veil_host_lib\veil_host_lib.lib"
        $nugetPackProperties += "vbsenclave_sdk_host_$platform"+"_lib=$veilHostLibPath;"
      }
    }

    # Pack nuget to account for both arm64 and x64 exes
    $packageNugetScriptPath  = "$BaseSolutionDirectory\..\..\BuildScripts\PackageNuget.ps1"

    & $packageNugetScriptPath -NugetSpecFilePath $nuspecFile -NugetPackProperties $nugetPackProperties -OutputDirectory "$BaseSolutionDirectory\_build"
} 
Catch
{
    $formatString = "`n{0}`n`n{1}`n`n"
    $fields = $_, $_.ScriptStackTrace
    Write-Host ($formatString -f $fields) -ForegroundColor RED
    throw
}

$TotalTime = (Get-Date)-$StartTime
$TotalMinutes = [math]::Floor($TotalTime.TotalMinutes)
$TotalSeconds = [math]::Ceiling($TotalTime.TotalSeconds) - ($totalMinutes * 60)

Write-Host "Successfully built the vbs enclave SDK." -ForegroundColor GREEN

Write-Host @"

Total Running Time to build vbs enclave SDK:
$TotalMinutes minutes and $TotalSeconds seconds
"@ -ForegroundColor CYAN
