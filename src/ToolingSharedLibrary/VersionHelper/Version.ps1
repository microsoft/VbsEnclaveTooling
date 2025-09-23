# Generates version.h file for edlcodgen.exe static files.
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

#define __VBS_ENCLAVE_CODEGEN_VERSION__ "{0}"
"@

$fileHeader = $template -f $VersionString

$fileHeader | Out-File -FilePath $OutputFile -Encoding UTF8

