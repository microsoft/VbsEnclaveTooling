Param(
    [ValidateSet('all', 'x64', 'arm64','X64', 'ARM64')]
    [System.String]
    $Platforms = "x64",
    
    [ValidateSet('all', 'debug', 'release', 'Debug', 'Release')]
    [System.String]
    $Configurations = "debug",
    
    [switch]
    $IsLocalBuild = $true,

    [switch]$Help = $false
)

$StartTime = Get-Date

if ($Help)
{
    Write-Host @"
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.

Syntax:
      Build.cmd [options]

Description:
      Builds vbs enclave tooling.

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
      Changes build behavior to build vbs enclave tooling and not through a pipeline.

  -Help
      Display this usage message.
"@
  Exit
}
# Note: new additions to the commandline build should be added to the VisualStudioUiBuild.targets file as well
# so the building behavior in VS UI and commandline stay the same.
$ErrorActionPreference = "Stop"
$BuildRootDirectory = (Split-Path $MyInvocation.MyCommand.Path)
$BaseRepositoryDirectory = Split-Path $BuildRootDirectory
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
    $solutionName = "VbsEnclaveTooling"
    $nuspecFile = "$BaseRepositoryDirectory\src\ToolingNuget\nuget\Microsoft.Windows.$solutionName.nuspec"
    $nugetPackProperties = "target_version=$BuildTargetVersion;"

    # Build
    foreach ($platform in $BuildPlatform)
    {
      foreach ($configuration in $Build_Configuration)
      {
        Write-Host "Building $solutionName for EnvPlatform: $BuildPlatform Platform: $platform Configuration: $configuration"
        $msbuildArgs = 
        @(
            ("$BaseRepositoryDirectory\$solutionName.sln"),
            ("/p:Platform=$platform"),
            ("/p:Configuration=$configuration"),
            ("/p:VbsEnclavePackageVersion=$BuildTargetVersion.ToString()"),
            ("/p:VbsEnclaveToolingIsPackaged=true"),
            ("/restore"),
            ("/binaryLogger:$BaseRepositoryDirectory\_build\$platform\$configuration\$solutionName.$platform.$configuration.binlog")
        )

        & $msbuildPath $msbuildArgs

        #Now create the nuget package 
        $vbsExePath = "$BaseRepositoryDirectory\_build\$platform\$configuration\$solutionName.exe"
        $nugetPackProperties += "vbsenclavetooling_$platform"+"_exe=$vbsExePath;"

        $cppSupportLibPath = "$BaseRepositoryDirectory\_build\$platform\$configuration\veil_enclave_cpp_support_lib.lib"
        $nugetPackProperties += "vbsenclavetooling_cpp_support_$platform"+"_lib=$cppSupportLibPath;"
        $veilEnclaveLibPath = "$BaseRepositoryDirectory\_build\$platform\$configuration\veil_enclave_lib.lib"
        $nugetPackProperties += "vbsenclavetooling_enclave_$platform"+"_lib=$veilEnclaveLibPath;"
        $veilHostLibPath = "$BaseRepositoryDirectory\_build\$platform\$configuration\veil_host_lib\veil_host_lib.lib"
        $nugetPackProperties += "vbsenclavetooling_host_$platform"+"_lib=$veilHostLibPath;"
        $veilAnyIncPath = "$BaseRepositoryDirectory\_build\$platform\$configuration\veil_any_inc"
        $nugetPackProperties += "vbsenclavetooling_any_$platform"+"_inc=$veilAnyIncPath;"
        $nugetPackProperties += "vcpkg_sources=$BaseRepositoryDirectory\src\ToolingSharedLibrary\vcpkg_installed\$platform-windows-static\$platform-windows-static;";
        $nugetPackProperties += "vcpkg_tools=$BaseRepositoryDirectory\src\ToolingSharedLibrary\vcpkg_installed\$platform-windows-static\$platform-windows\tools;";
      }
    }

    # Pack nuget to account for both arm64 and x64 exes
    $packageNugetScriptPath  = "$BuildRootDirectory\PackageNuget.ps1"

    & $packageNugetScriptPath -NugetSpecFilePath $nuspecFile -NugetPackProperties $nugetPackProperties -OutputDirectory "$BaseRepositoryDirectory\_build"
} 
Catch
{
    $formatString = "`n{0}`n`n{1}`n`n"
    $fields = $_, $_.ScriptStackTrace
    Write-Host ($formatString -f $fields) -ForegroundColor RED
}

$TotalTime = (Get-Date)-$StartTime
$TotalMinutes = [math]::Floor($TotalTime.TotalMinutes)
$TotalSeconds = [math]::Ceiling($TotalTime.TotalSeconds) - ($totalMinutes * 60)

Write-Host @"

Total Running Time:
$TotalMinutes minutes and $TotalSeconds seconds
"@ -ForegroundColor CYAN
