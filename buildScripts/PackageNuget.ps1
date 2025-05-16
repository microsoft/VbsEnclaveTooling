Param(
    [Parameter(Mandatory=$true)]
    [System.String]
    $NugetPackProperties,

    [Parameter(Mandatory=$true)]
    [System.String]
    $NugetSpecFilePath,
    
    [Parameter(Mandatory=$true)]
    [System.String]
    $OutputDirectory,

    [switch]$Help = $false
)

$StartTime = Get-Date

if ($Help)
{
    Write-Host @"
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.

Syntax:
      PackageNuget.ps1 [options]

Description:
      create vbs enclave tooling's .nupkg file.

Options:

  -NugetPackProperties <prop1_key=prop1_value;prop2_key=prop2_value>
      Properties to pass to nuget.exe when packaging nuget package.

  -NugetSpecFilePath <absolute-path-to-file>
      absolute path to a .nuspec file.

  -OutputDirectory <absolute-path-to-directory>
      Directory to place .nupkg into.

  -Help
      Display this usage message.
"@
  Exit
}

$ErrorActionPreference = "Stop"
$BuildRootDirectory = (Split-Path $MyInvocation.MyCommand.Path)
try 
{
    Write-Host "Starting nuget pack with the following properties:"

    # $NugetPackProperties is a semi-colon delimited list.
    $properties = $NugetPackProperties -split ";"

    foreach ($item in $properties)
    {
        Write-Host "    $item"
    }

    $nugetExeDownloaderPath = (Join-Path $BuildRootDirectory "NugetExeDownloader.ps1")
    $nugetPath = & $nugetExeDownloaderPath
   
    # create nuget package.
    & $nugetPath pack $NugetSpecFilePath -Properties $NugetPackProperties -OutputDirectory $OutputDirectory
    if ($LASTEXITCODE -ne 0)
    {
        throw "Failed to package nuget file"
    }

    Write-Host "Successfully created .nupkg file using nuget spec file: '$NugetSpecFilePath'." -ForegroundColor GREEN
} 
catch
{
    Write-Host ("Failed to create .nupkg file using nuget spec file: '$NugetSpecFilePath'.") -ForegroundColor RED
    throw
}
