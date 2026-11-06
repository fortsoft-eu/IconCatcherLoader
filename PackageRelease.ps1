<#
This is open-source software licensed under the terms of the MIT License.

Copyright (c) 2026 Petr Červinka - FortSoft <cervinka@fortsoft.eu>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Last modified for version 2.1.0.0
#>

[CmdletBinding()]
param (
    [string]$SignerName =
        [Environment]::GetEnvironmentVariable("BUILD_SIGNER_NAME", "User"),
    [string]$CertificateThumbprint =
        [Environment]::GetEnvironmentVariable("BUILD_CERTIFICATE_THUMBPRINT", "User"),
    [string]$SignToolPath =
        [Environment]::GetEnvironmentVariable("BUILD_SIGNTOOL_PATH", "User"),
    [string]$TimestampServer =
        [Environment]::GetEnvironmentVariable("BUILD_TIMESTAMP_SERVER", "User")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSCommandPath
$solution = Get-ChildItem -LiteralPath $root -Filter "*.sln" -File | Select-Object -First 1
$assemblyInfo = Join-Path $root "IconCatcherLoader.Net48\Properties\AssemblyInfo.cs"
$license = Join-Path $root "license.txt"
$binaryName = "IconCatcherLoader.exe"
$projects = @(
    "IconCatcherLoader.Net20",
    "IconCatcherLoader.Net35Client",
    "IconCatcherLoader.Net40Client",
    "IconCatcherLoader.Net48"
)

# Returns the four-part file version of the Release executable used to name the solution package.
function Get-PackageVersion {
    param (
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing Release executable: $Path"
    }

    $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    if ([string]::IsNullOrEmpty($versionInfo.FileVersion)) {
        throw "The Release executable has no file version: $Path"
    }

    return "{0}.{1}.{2}.{3}" -f $versionInfo.FileMajorPart, $versionInfo.FileMinorPart,
        $versionInfo.FileBuildPart, $versionInfo.FilePrivatePart
}

# Returns the newest valid current-user code-signing certificate with a private key that matches the supplied
# name or thumbprint; returns null when no signer was requested or no matching certificate exists.
function Find-SignerCertificate {
    param (
        [string]$Name,
        [string]$Thumbprint
    )

    if (-not $Name -and -not $Thumbprint) {
        return $null
    }

    $now = Get-Date
    if ($Thumbprint) {
        $normalizedThumbprint = $Thumbprint.Replace(" ", "")
    } else {
        $normalizedThumbprint = $null
    }
    $certificates = @(Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
        Where-Object {
            $_.HasPrivateKey -and
            $_.NotBefore -le $now -and
            $_.NotAfter -gt $now -and
            (-not $normalizedThumbprint -or $_.Thumbprint -ieq $normalizedThumbprint) -and
            (-not $Name -or $_.GetNameInfo(
                [Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -ieq $Name)
        } |
        Sort-Object NotAfter -Descending)

    return $certificates | Select-Object -First 1
}

# Resolves the requested signing tool or searches PATH and installed Windows SDK versions; returns null if
# unavailable.
function Find-SignTool {
    param (
        [string]$RequestedPath
    )

    if ($RequestedPath) {
        if (Test-Path -LiteralPath $RequestedPath -PathType Leaf) {
            return [IO.Path]::GetFullPath($RequestedPath)
        }
        return $null
    }

    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) {
        return $command.Source
    }

    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (-not (Test-Path -LiteralPath $kitsRoot -PathType Container)) {
        return $null
    }

    $versionDirectories = Get-ChildItem -LiteralPath $kitsRoot -Directory |
        Where-Object {
            $_.Name -match "^\d+\.\d+\.\d+\.\d+`$"
        } |
        Sort-Object {
            [version]$_.Name
        } -Descending
    foreach ($directory in $versionDirectories) {
        foreach ($architecture in @("x64", "x86")) {
            $candidate = Join-Path $directory.FullName "$architecture\signtool.exe"
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                return $candidate
            }
        }
    }

    foreach ($architecture in @("x64", "x86")) {
        $candidate = Join-Path $kitsRoot "$architecture\signtool.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    return $null
}

# Verifies Authenticode trust using SignTool when available, otherwise using PowerShell's signature status.
function Test-BinarySignature {
    param (
        [Parameter(Mandatory)][string]$Path,
        [string]$ToolPath
    )

    if ($ToolPath) {
        & $ToolPath verify /pa /q $Path *> $null
        return $LASTEXITCODE -eq 0
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    return $null -ne $signature.SignerCertificate -and $signature.Status -eq "Valid"
}

# Reports whether the binary contains a signer certificate, independently of whether its signature is trusted.
function Test-BinaryHasSignature {
    param (
        [Parameter(Mandatory)][string]$Path
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    return $null -ne $signature.SignerCertificate
}

# Signs a staged copy with SHA-256, retries without timestamping if that request fails, and verifies the
# resulting signature. Throws on signing or verification failure so an invalid package cannot be reported
# as successfully signed.
function Sign-Binary {
    param (
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Certificate,
        [Parameter(Mandatory)][string]$ToolPath,
        [string]$RequestedSignerName,
        [string]$TimestampUrl
    )

    if ($RequestedSignerName) {
        $certificateSelector = @("/n", $RequestedSignerName)
    } else {
        $certificateSelector = @("/sha1", $Certificate.Thumbprint)
    }

    Write-Host "Signing $([IO.Path]::GetFileName($Path))"
    $signedWithTimestamp = $false
    if ($TimestampUrl) {
        & $ToolPath sign @certificateSelector /fd SHA256 /tr $TimestampUrl /td SHA256 /v $Path
        $signedWithTimestamp = $LASTEXITCODE -eq 0
        if (-not $signedWithTimestamp) {
            Write-Warning "Signing with a timestamp failed; retrying without a timestamp."
        }
    }

    if (-not $signedWithTimestamp) {
        & $ToolPath sign @certificateSelector /fd SHA256 /v $Path
        if ($LASTEXITCODE -ne 0) {
            throw "Signing failed for '$Path'."
        }
    }

    if (-not (Test-BinarySignature -Path $Path -ToolPath $ToolPath)) {
        throw "Authenticode verification failed after signing '$Path'."
    }
}

# Performs verbose SignTool verification of the staged binary, reporting success or throwing on failure.
function Confirm-BinarySignature {
    param (
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ToolPath
    )

    & $ToolPath verify /pa /v $Path
    if ($LASTEXITCODE -ne 0) {
        throw "Authenticode verification failed for '$Path'."
    }
    Write-Host "Signature verified successfully: $Path"
}

# Searches PATH and standard installation directories for 7-Zip; returns null to select ZIP creation through
# .NET.
function Find-SevenZip {
    $command = Get-Command 7z.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) {
        return $command.Source
    }

    foreach ($candidate in @(
        (Join-Path $env:ProgramFiles "7-Zip\7z.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "7-Zip\7z.exe")
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    return $null
}

if (-not $solution) {
    throw "No solution file was found in '$root'."
}

$solutionName = $solution.BaseName
$staleArchives = @(Join-Path $root ($solutionName + ".zip"))
$versionedArchivePattern = "^{0}-\d+\.\d+\.\d+\.\d+\.zip`$" -f [regex]::Escape($solutionName)
$versionedArchives = Get-ChildItem -LiteralPath $root -Filter "$solutionName-*.zip" -File
foreach ($versionedArchive in $versionedArchives) {
    if ($versionedArchive.Name -match $versionedArchivePattern) {
        $staleArchives += $versionedArchive.FullName
    }
}
foreach ($staleArchive in ($staleArchives | Select-Object -Unique)) {
    if (Test-Path -LiteralPath $staleArchive -PathType Leaf) {
        Remove-Item -LiteralPath $staleArchive -Force
        Write-Host "Removed previous package: $staleArchive"
    }
}

if (-not (Test-Path -LiteralPath $license -PathType Leaf)) {
    throw "Missing license: $license"
}

$versionMatch = [regex]::Match((Get-Content -LiteralPath $assemblyInfo -Raw),
    '^\[assembly:\s*AssemblyFileVersion\("(\d+\.\d+\.\d+\.\d+)"\)\]',
    [Text.RegularExpressions.RegexOptions]::Multiline)
if (-not $versionMatch.Success) {
    throw "A four-part AssemblyFileVersion was not found in '$assemblyInfo'."
}

$version = $versionMatch.Groups[1].Value
$archiveName = "{0}-{1}.zip" -f $solutionName, $version
$archive = Join-Path $root $archiveName

foreach ($project in $projects) {
    $file = Join-Path $root "$project\bin\Release\$binaryName"
    if ((Get-PackageVersion -Path $file) -ne $version) {
        throw "The Release executable for '$project' does not match version $version. Rebuild the solution."
    }
}

$certificate = Find-SignerCertificate -Name $SignerName -Thumbprint $CertificateThumbprint
$resolvedSignTool = Find-SignTool -RequestedPath $SignToolPath
if ($SignerName -or $CertificateThumbprint) {
    if (-not $certificate) {
        Write-Warning ("The requested valid code-signing certificate with a private key was not found. " +
            "Unsigned binaries will remain unsigned.")
    } elseif (-not $resolvedSignTool) {
        Write-Warning "signtool.exe was not found. Unsigned binaries will remain unsigned."
        $certificate = $null
    }
} else {
    Write-Host ("No signer was specified. Existing valid signatures will be preserved; " +
        "unsigned binaries will remain unsigned.")
}

$staging = Join-Path ([IO.Path]::GetTempPath()) `
    ($solutionName + "-package-" + [guid]::NewGuid().ToString("N"))
$packageDirectory = Join-Path $staging "files"
$packageArchive = Join-Path $staging $archiveName
$unsignedBinaries = [Collections.Generic.List[string]]::new()

try {
    New-Item -ItemType Directory -Path $packageDirectory -Force | Out-Null

    foreach ($project in $projects) {
        $file = Join-Path $root "$project\bin\Release\$binaryName"
        $destination = Join-Path $packageDirectory $project
        New-Item -ItemType Directory -Path $destination | Out-Null
        $stagedFile = Join-Path $destination $binaryName
        Copy-Item -LiteralPath $file -Destination $stagedFile
        $hasExistingSignature = Test-BinaryHasSignature -Path $stagedFile
        $hasValidSignature = Test-BinarySignature -Path $stagedFile -ToolPath $resolvedSignTool
        if ($hasExistingSignature) {
            Write-Host "Existing signature detected; it will not be replaced: $project\$binaryName"
            if (-not $hasValidSignature) {
                throw "The existing Authenticode signature could not be verified " +
                    "and will not be replaced: '$stagedFile'."
            }
        } elseif ($certificate -and $resolvedSignTool) {
            Sign-Binary -Path $stagedFile -Certificate $certificate -ToolPath $resolvedSignTool `
                -RequestedSignerName $SignerName -TimestampUrl $TimestampServer
            $hasValidSignature = $true
        } else {
            $unsignedBinaries.Add("$project\$binaryName") | Out-Null
        }

        if ($hasValidSignature) {
            if (-not $resolvedSignTool) {
                throw "signtool.exe is required for verbose verification of '$stagedFile'."
            }
            Confirm-BinarySignature -Path $stagedFile -ToolPath $resolvedSignTool
        }

        Copy-Item -LiteralPath $license -Destination (Join-Path $destination "license.txt")
    }

    $sevenZip = Find-SevenZip
    if ($sevenZip) {
        Push-Location $packageDirectory
        try {
            & $sevenZip a -tzip -mx=9 -mmt=on -y $packageArchive "*"
            if ($LASTEXITCODE -ne 0) {
                throw "7-Zip failed to create '$archive'."
            }
        } finally {
            Pop-Location
        }
    } else {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::CreateFromDirectory(
            $packageDirectory, $packageArchive, [IO.Compression.CompressionLevel]::Optimal, $false)
    }

    Move-Item -LiteralPath $packageArchive -Destination $archive -Force
    Write-Host "Created solution package: $archive"
    if ($unsignedBinaries.Count -eq 0) {
        Write-Host "The package contains only verified Authenticode-signed binaries."
    } else {
        Write-Warning ("The package contains unsigned binaries: " + ($unsignedBinaries -join ", "))
    }
} finally {
    if (Test-Path -LiteralPath $staging) {
        $resolvedStaging = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $staging).ProviderPath)
        $temporaryDirectory = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar)
        if ([IO.Path]::GetDirectoryName($resolvedStaging) -ine $temporaryDirectory) {
            throw "The staging directory is outside the temporary directory: $resolvedStaging"
        }
        Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
    }
}
