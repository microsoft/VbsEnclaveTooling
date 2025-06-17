[CmdletBinding()]
Param(
    [ValidateSet('all', 'x64', 'ARM64')]
    [System.String]
    $Platforms = "all",
    
    [ValidateSet('all', 'Debug', 'Release')]
    [System.String]
    $Configurations = "all",

    [ValidateSet('all', 'CodeGenOnly')]
    [System.String]
    $NugetPackagesToOutput = "all",
    
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
      Example: -Configuration release
      Example: -Configuration all

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
$BuildPlatform = @($Platforms)
$BuildConfiguration = @($Configurations)

if ($Platforms -eq "all")
{
    $BuildPlatform = @("x64", "ARM64")
}

if ($Configurations -eq "all")
{
    $BuildConfiguration = @("Release", "Debug")
}

# Use the triple zeros as the version number for local builds.
$BuildTargetVersion = [System.Version]::new(0, 0, 0)
$msbuildPath = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -prerelease -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe

Try 
{
    $solutionName = "VbsEnclaveTooling"

    # Run nuget restore
    $nugetExeDownloaderPath = (Join-Path $BuildRootDirectory "NugetExeDownloader.ps1")
    $nugetPath = & $nugetExeDownloaderPath
    Write-Host "Running nuget restore for $solutionName"
    & $nugetPath restore "$BaseRepositoryDirectory\$solutionName.sln"

    # Create nuget pack properties that will always exist
    $nuspecFile = "$BaseRepositoryDirectory\src\ToolingNuget\nuget\Microsoft.Windows.VbsEnclave.CodeGenerator.nuspec"
    $nugetPackProperties = "target_version=$BuildTargetVersion;"
    $nugetPackProperties += "vcpkg_sources=$BaseRepositoryDirectory\src\ToolingSharedLibrary\vcpkg_installed\x64-windows-static-cfg\x64-windows-static-cfg;";
    $nugetPackProperties += "vcpkg_tools=$BaseRepositoryDirectory\src\ToolingSharedLibrary\vcpkg_installed\x64-windows-static-cfg\x64-windows\tools;";
         
    $edlcodegen_exe_path = ""
    $cppSupportLibPath = ""

    # Build
    foreach ($platform in $BuildPlatform)
    {
        foreach ($configuration in $BuildConfiguration)
        {
            Write-Host "Building $solutionName for EnvPlatform: $BuildPlatform Platform: $platform Configuration: $configuration"
            $msbuildArgs = 
            @(
                ("$BaseRepositoryDirectory\$solutionName.sln"),
                ("/p:Platform=$Platform"),
                ("/p:Configuration=$Configuration"),
                ("/restore"),
                ("/binaryLogger:$BaseRepositoryDirectory\_build\$platform\$configuration\$solutionName.$platform.$configuration.binlog")
            )

            & $msbuildPath $msbuildArgs
            if ($LASTEXITCODE -ne 0)
            {
                Write-Error "MSBuild failed with exit code $LASTEXITCODE"
                exit $LASTEXITCODE
            }

            $cppSupportLibPath = "$BaseRepositoryDirectory\_build\$platform\$configuration\veil_enclave_cpp_support_${platform}_${configuration}_lib.lib"
            $cppSupportLibPdbPath = "$BaseRepositoryDirectory\_build\$platform\$configuration\veil_enclave_cpp_support_${platform}_${configuration}_lib.pdb"
            $nugetPackProperties += "vbsenclave_codegen_cpp_support_${platform}_${configuration}_lib=$cppSupportLibPath;"
            $nugetPackProperties += "vbsenclave_codegen_cpp_support_${platform}_${configuration}_pdb=$cppSupportLibPdbPath;"

            # only need the exe path once. If the user uses the -all flag for the configuration, we use the release version. Otherwise
            # we use the specified user provided configuration. e.g debug or release.
            if ($edlcodegen_exe_path -eq "")
            {
                $edlcodegen_exe_path = "vbsenclave_codegen_x64_exe=$BaseRepositoryDirectory\_build\x64\$configuration\edlcodegen.exe;"
                $nugetPackProperties += $edlcodegen_exe_path
            }
        }
    }
 
    # Pack nuget
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
    & $sdkBuildScriptPath -Platforms $Platforms -Configurations $Configurations -BuildCodeGenNugetDependency $false
}

$TotalTime = (Get-Date)-$StartTime
$TotalMinutes = [math]::Floor($TotalTime.TotalMinutes)
$TotalSeconds = [math]::Ceiling($TotalTime.TotalSeconds) - ($totalMinutes * 60)

Write-Host "Successfully built the vbs enclave CodeGenerator." -ForegroundColor GREEN

Write-Host @"

Total Running Time to build vbs enclave CodeGenerator:
$TotalMinutes minutes and $TotalSeconds seconds
"@ -ForegroundColor CYAN
