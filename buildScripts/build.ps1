[CmdletBinding()]
Param(
    [ValidateSet('all', 'x64', 'arm64','X64', 'ARM64')]
    [System.String]
    $Platforms = "x64",
    
    [ValidateSet('all', 'debug', 'release', 'Debug', 'Release')]
    [System.String]
    $Configurations = "debug",

    [ValidateSet('all', 'CodeGenOnly')]
    [System.String]
    $NugetPackagesToOutput = "all",
    
    [System.Boolean]
    $IsLocalBuild = $true,

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
      Builds the vbs enclave tooling and the vbs enclave implementation library solutions.

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
    $nuspecFile = "$BaseRepositoryDirectory\src\ToolingNuget\nuget\Microsoft.Windows.VbsEnclave.CodeGenerator.nuspec"
    $nugetPackProperties = "target_version=$BuildTargetVersion;"

    # Run nuget restore
    $nugetExeDownloaderPath = (Join-Path $BuildRootDirectory "NugetExeDownloader.ps1")
    $nugetPath = & $nugetExeDownloaderPath
    Write-Host "Running nuget restore for $solutionName"
    & $nugetPath restore "$BaseRepositoryDirectory\$solutionName.sln"

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
            ("/restore"),
            ("/binaryLogger:$BaseRepositoryDirectory\_build\$platform\$configuration\$solutionName.$platform.$configuration.binlog")
        )

        & $msbuildPath $msbuildArgs
        if ($LASTEXITCODE -ne 0)
        {
            Write-Error "MSBuild failed with exit code $LASTEXITCODE"
            exit $LASTEXITCODE
        }

        #Now create the nuget package 
        $vbsExePath = "$BaseRepositoryDirectory\_build\$platform\$configuration\edlcodegen.exe"
        $nugetPackProperties += "vbsenclave_codegen_$platform"+"_exe=$vbsExePath;"
        $nugetPackProperties += "vcpkg_sources=$BaseRepositoryDirectory\src\ToolingSharedLibrary\vcpkg_installed\$platform-windows-static\$platform-windows-static;";
        $nugetPackProperties += "vcpkg_tools=$BaseRepositoryDirectory\src\ToolingSharedLibrary\vcpkg_installed\$platform-windows-static\$platform-windows\tools;";
        $cppSupportLibPath = "$BaseRepositoryDirectory\_build\$platform\$configuration\veil_enclave_cpp_support_lib.lib"
        $nugetPackProperties += "vbsenclave_codegen_cpp_support_$platform"+"_lib=$cppSupportLibPath;"

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
    throw
}

# Now that we've finished building the codegen project and nuget package, build the sdk project and its nuget package.
if ($NugetPackagesToOutput -eq "all")
{
    $sdkBuildScriptPath = "$BaseRepositoryDirectory\src\VbsEnclaveSDK\BuildScripts\build.ps1"
    & $sdkBuildScriptPath -Platforms $Platforms -Configurations $Configurations -IsLocalBuild $IsLocalBuild -BuildCodeGenNugetDependency $false
}

$TotalTime = (Get-Date)-$StartTime
$TotalMinutes = [math]::Floor($TotalTime.TotalMinutes)
$TotalSeconds = [math]::Ceiling($TotalTime.TotalSeconds) - ($totalMinutes * 60)

Write-Host "Successfully built the vbs enclave CodeGenerator." -ForegroundColor GREEN

Write-Host @"

Total Running Time to build vbs enclave CodeGenerator:
$TotalMinutes minutes and $TotalSeconds seconds
"@ -ForegroundColor CYAN
