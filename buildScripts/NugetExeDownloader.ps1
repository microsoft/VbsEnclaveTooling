$ErrorActionPreference = "Stop"

# Set VisualStudioVersion to 15.0 if not already set
if (-not $env:VisualStudioVersion) {
    $env:VisualStudioVersion = '15.0'
}

# Define the path to the nuget executable
$nugetPath = Join-Path $env:TEMP 'nuget.exe'

# Function to download nuget.exe
function Download-NuGet
{
    try {
        Write-Host "Attempting to download nuget.exe..."
        Invoke-WebRequest -Uri 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe' -OutFile $nugetPath
        Write-Host "Download successful."
    } catch {
        Write-Host "Failed to download nuget.exe. Error: $_"
        throw $_  # Re-throw the exception to be caught by the caller
    }
}

function Get-NugetExe
{
    [OutputType([System.String])]
    param
    (
        [System.String]
        $SomeParameter
    )

    # First attempt to download nuget.exe
    $attempt = 1
    $maxAttempts = 2
    $downloadSuccess = $false

    while ($attempt -le $maxAttempts -and -not $downloadSuccess)
    {
        try 
        {
            # Check if nuget.exe exists and if so, delete it on the second attempt
            if ($attempt -eq 2 -and (Test-Path $nugetPath))
            {
                Write-Host "Removing existing nuget.exe to try downloading again."
                Remove-Item -Path $nugetPath -Force
            }

            # Attempt to download nuget.exe
            if (-not (Test-Path $nugetPath))
            {
                Write-Host "Nuget.exe not found in the temp dir, downloading."
                Download-NuGet
            }
            else
            {
                # nuget.exe exists. Now test that its working by running at least once. if there are errors delete and re-download.
                # $null 2>&1 | Write-Host will not show its output but will show stderr. Note: if there is an error an exception will
                # be thrown, and we'll attempt to re-download it at least once.
                & $nugetPath > $null 2>&1 | Write-Host
            }

            # If we reach here, the download was successful
            $downloadSuccess = $true

        } 
        catch
        {
            Write-Host "Attempt $attempt failed. Error: $_"
            if ($attempt -eq $maxAttempts)
            {
                Write-Host "Second attempt also failed. Exiting."
                throw $_  # Re-throw the exception on the second failure
            }
        }

        # Increment attempt counter
        $attempt++
    }

    # Execute nuget.exe with any arguments passed to the script if the download was successful
    if ($downloadSuccess)
    {
        return $nugetPath
    } 
    else 
    {
        throw "Could not find nuget.exe"
    }
}

Get-NugetExe
