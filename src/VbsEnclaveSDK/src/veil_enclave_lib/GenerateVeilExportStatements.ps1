# Generates pragma linker statements for Veil Enclave exports,
# using the 'Exports.cpp' file produced by edlcodegen.exe.
param (
    [string]$InputFile,
    [string]$OutputFile
)

# Ensure input file exists
if (-not (Test-Path $InputFile))
{
    Write-Error "Input file not found: $InputFile"
    exit 1
}

# Extract pragma lines and append them to the output file.
# example line: #pragma comment(linker, "/include:__AbiRegisterVtl0Callbacks_veil_abi__")
$pragmaLines = Select-String -Path $InputFile -Pattern '#pragma comment\(linker,' | ForEach-Object { $_.Line }

$fileHeader = @"
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Auto-generated export pragmas for the Veil Enclave static library.
// This file should be included in the developer's enclave project to ensure
// the Veil enclave export symbols are properly exposed by the enclave DLL.
// Do not modify this file manually.
#pragma once

"@

$fileHeader, $pragmaLines | Out-File -FilePath $OutputFile -Encoding UTF8
