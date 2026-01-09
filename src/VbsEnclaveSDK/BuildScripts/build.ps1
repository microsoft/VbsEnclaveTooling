[CmdletBinding()]
Param(
    [ValidateSet('all', 'x64', 'ARM64')]
    [System.String]
    $Platforms = "all",
    
    [ValidateSet('all', 'Debug', 'Release')]
    [System.String]
    $Configurations = "all",

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
    $solutionName = "vbs_enclave_implementation_library"

    # Run nuget restore
    $nugetPath = & "$BaseSolutionDirectory\..\..\BuildScripts\NugetExeDownloader.ps1"
    Write-Host "Running nuget restore for $solutionName"
    & $nugetPath restore "$BaseSolutionDirectory\$solutionName.sln"

    # Create nuget pack properties that will always exist
    $nuspecFile = "$BaseSolutionDirectory\src\veil_nuget\Nuget\Microsoft.Windows.VbsEnclave.SDK.nuspec"
    $nugetPackProperties = "target_version=$BuildTargetVersion;"
     
    # Build
    foreach ($platform in $BuildPlatform)
    {
        foreach ($configuration in $BuildConfiguration)
        {
            Write-Host "Building $solutionName for EnvPlatform: $BuildPlatform Platform: $platform Configuration: $configuration"
            $msbuildArgs = 
            @(
                ("$BaseSolutionDirectory\$solutionName.sln"),
                ("/t:Rebuild"),
                ("/p:Platform=$Platform"),
                ("/p:Configuration=$Configuration"),
                ("/restore"),
                ("/binaryLogger:$BaseSolutionDirectory\_build\$platform\$configuration\$solutionName.$platform.$configuration.binlog")
            )

            & $msbuildPath $msbuildArgs
            if ($LASTEXITCODE -ne 0)
            {
                Write-Error "MSBuild failed with exit code $LASTEXITCODE"
                exit $LASTEXITCODE
            }

            $cppSupportLibPath = "$BaseSolutionDirectory\_build\$platform\$configuration\veil_enclave_cpp_support.lib"
            $nugetPackProperties += "vbsenclave_sdk_cpp_support_${platform}_${configuration}_lib=$cppSupportLibPath;"

            $veilEnclaveLibPath = "$BaseSolutionDirectory\_build\$platform\$configuration\veil_enclave.lib"
            $nugetPackProperties += "vbsenclave_sdk_enclave_${platform}_${configuration}_lib=$veilEnclaveLibPath;"

            if ($configuration -eq "Release")
            {
                $veilHostLibPath = "$BaseSolutionDirectory\_build\$platform\$configuration\veil_host"
                $nugetPackProperties += "vbsenclave_sdk_host_${platform}_${configuration}_lib=$veilHostLibPath.lib;"
                $nugetPackProperties += "vbsenclave_sdk_host_${platform}_${configuration}_dll=$veilHostLibPath.dll;"
            }
        }
    }

    # Pack nuget
    $packageNugetScriptPath  = "$BaseSolutionDirectory\..\..\BuildScripts\PackageNuget.ps1"

    & $packageNugetScriptPath -NugetSpecFilePath $nuspecFile -NugetPackProperties $nugetPackProperties -OutputDirectory "$BaseSolutionDirectory\_build"

    # Copy the built SDK nuget package to the repo's root build folder so it's easy for developers to find.
    Copy-Item -Path "$BaseSolutionDirectory\_build\Microsoft.Windows.VbsEnclave.SDK.$BuildTargetVersion.nupkg" -Destination "$BaseSolutionDirectory\..\..\_build" -Force
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
