# Generates version.h file for edlcodgen.exe static files.
# This script is invoked by the build system and should not be run manually.
# To update the ABI version, update the CodeGenABIVersion property in helpers.targets
param (
    [string]$VersionString,
    [string]$OutputFile
)

# Ensure version string is provided
if (-not $VersionString)
{
    Write-Error "Version string not specified."
    exit 1
}

# Ensure output file path is provided
if (-not $OutputFile)
{
    Write-Error "Output file not specified."
    exit 1
}

$template = @"
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Auto-generated version file for edlcodgen.exe. Do not edit manually.
#pragma once

// Codegen ABI version; increment only for breaking changes.
#define VBS_ENCLAVE_CODEGEN_ABI_VERSION "{0}"
"@

$fileHeader = $template -f $VersionString

$fileHeader | Out-File -FilePath $OutputFile -Encoding UTF8

