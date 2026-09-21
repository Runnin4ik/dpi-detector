[CmdletBinding()]
param(
    [string]$InstallDir = "",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$AppArgs
)

$ErrorActionPreference = 'Stop'

# Windows PowerShell negotiates SSL3+TLS on the older builds this installer
# supports, and GitHub refuses anything below TLS 1.2, so 1.2 is OR-ed into
# whatever the host already had. The flag is written as its raw value (3072) and
# not as `[Net.SecurityProtocolType]::Tls12` because that member does not exist
# in the .NET 3.5 that ships with PowerShell 2.0. A runtime that reports
# `SystemDefault` (0) is left alone: .NET 4.7+ and PowerShell 7 already negotiate
# the best the OS offers, TLS 1.3 included, and naming 1.2 there takes it away.
$sp = [int][Net.ServicePointManager]::SecurityProtocol
if ($sp -ne 0 -and ($sp -band 3072) -eq 0) {
    try { [Net.ServicePointManager]::SecurityProtocol = $sp -bor 3072 } catch {}
}

$repo = "Runnin4ik/dpi-detector"
$version = if ($env:DPI_VERSION) { $env:DPI_VERSION } else { "v5.0.0-alpha.19" }

# Architecture detection with 32-bit WoW64 fallback protection. The release
# carries one x86_64 build per Windows generation and nothing for a 32-bit host,
# so one is refused here rather than after a download that would not start.
# `ARM64` passes: x86_64 runs there emulated. Only a value that is known to be
# 32-bit refuses the install — an environment that does not set the variable at
# all is not evidence of a 32-bit machine.
$rawArch = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) {
    $rawArch = $env:PROCESSOR_ARCHITEW6432
}
if ($rawArch -eq "x86" -or $rawArch -eq "ARM" -or $rawArch -eq "IA64") {
    Write-Host "Error: unsupported architecture ${rawArch}: DPI Detector needs 64-bit Windows." -ForegroundColor Red
    exit 1
}

$isLegacyWin = [System.Environment]::OSVersion.Version.Major -lt 10
$target = if ($isLegacyWin) { "dpi-detector-windows-7-x86_64.exe" } else { "dpi-detector-windows-x86_64.exe" }

$outDir = if ($InstallDir -ne "") {
    $InstallDir
} elseif ($env:DPI_INSTALL_DIR) {
    $env:DPI_INSTALL_DIR
} else {
    $env:TEMP
}

if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$out = Join-Path $outDir "dpi-detector.exe"
$tmp = Join-Path $outDir "dpi-detector.tmp.$([System.Diagnostics.Process]::GetCurrentProcess().Id).exe"

# The asset's URL on GitHub itself: the release the manifest is checked against,
# and the head of the list below. `DPI_RELEASE_BASE` replaces the
# `https://github.com/<repo>/releases` prefix for a source that mirrors the same
# layout — CI points it at a local fixture, which is what puts the
# canonical-first manifest lookup below under test.
function Get-ReleaseUrl([string]$fileName) {
    $base = if ($env:DPI_RELEASE_BASE) { $env:DPI_RELEASE_BASE.TrimEnd('/') } else { "https://github.com/$repo/releases" }
    if ($version -eq "latest") {
        return "$base/latest/download/$fileName"
    }
    return "$base/download/$version/$fileName"
}

# Every release asset this script fetches — the binary and `SHA256SUMS.txt` — is
# looked for at the same set of sources, so the list is built from the asset name
# rather than written twice. The proxy hosts are the same six `install.sh`
# carries, and the check workflow compares the two lists: a host added to one
# installer and forgotten in the other is a source that platform cannot reach.
function Get-ReleaseUrlList([string]$fileName) {
    $list = New-Object 'System.Collections.Generic.List[string]'
    if ($env:DPI_MIRRORS) {
        foreach ($m in $env:DPI_MIRRORS.Split(" ,;`t", [System.StringSplitOptions]::RemoveEmptyEntries)) {
            $list.Add("$($m.TrimEnd('/'))/$fileName")
        }
    }
    $gh = Get-ReleaseUrl $fileName
    $list.Add($gh)
    $list.Add("https://ghfast.top/$gh")
    $list.Add("https://ghproxy.net/$gh")
    $list.Add("https://gh-proxy.com/$gh")
    $list.Add("https://ghproxy.vip/$gh")
    $list.Add("https://gh-proxy.org/$gh")
    $list.Add("https://github.boki.moe/$gh")
    return $list
}

# Whether the failure was an answer from a server or a host that could not be
# reached. PowerShell wraps a failing .NET call in its own exception (both hosts
# measured do: `MethodInvocationException` around a `WebException`), and only the
# inner one carries the response, so the chain is walked for it.
function Test-Answered($err) {
    $e = $err.Exception
    while ($e) {
        if ($e -is [System.Net.WebException] -and $e.Response) { return $true }
        $e = $e.InnerException
    }
    return $false
}

# A whole small file as text, over the same request settings the binary download
# below uses. Throws on any HTTP or transport error; `Test-Answered` tells the
# two apart for the caller.
function Get-UrlText([string]$url) {
    $req = [System.Net.HttpWebRequest]::Create($url)
    $req.Timeout = 5000
    $req.ReadWriteTimeout = 60000
    $req.UserAgent = "curl/8.0"
    $resp = $req.GetResponse()
    $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
    try {
        return $reader.ReadToEnd()
    } finally {
        $reader.Close()
        $resp.Close()
    }
}

# The hash of a file, from the cmdlet when the host has one and from .NET when it
# does not: `Get-FileHash` arrived in PowerShell 4.0, and the Windows 7 this
# script supports ships 2.0.
function Get-FileSha256([string]$path) {
    if (Get-Command Get-FileHash -ErrorAction SilentlyContinue) {
        return (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLower()
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($path)
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLower()
    } finally {
        $stream.Close()
        $sha.Clear()
    }
}

# The release publishes `SHA256SUMS.txt` beside the binaries and the download is
# checked against it before it is installed: that catches a mirror that truncated
# the file, a proxy that rewrote a byte, a CDN still serving an older build. It
# cannot catch a mirror serving a manifest of its own — the manifest travels the
# same channels as the binary, so this is an integrity check, not a signature. A
# release from before the manifest existed simply has none, and then the check is
# skipped with a warning instead of failing an install that would otherwise work.
#
# It is looked for in two places and not in every source: the release itself,
# whose answer settles whether the release has a manifest at all — a mirror only
# has what the release has, so an HTTP error there ends the search — and then the
# source the binary actually came from, which is the case this script exists for
# on a filtered network. Asking all thirteen sources costs five seconds each, and
# the sweep would run after the binary is already on disk, which is why
# `install.sh` does not do it either.
$script:manifestText = $null
# "" until the manifest has been looked for, then "ok" or "missing".
$script:manifestState = ""
# Set once the reason for an unchecked install has been said: the loop below runs
# per source and would otherwise repeat the same warning for every mirror.
$script:manifestNoteShown = $false

function Get-Manifest([string]$nearUrl) {
    if ($script:manifestState) { return }
    $near = ""
    if ($nearUrl) { $near = $nearUrl.Substring(0, $nearUrl.LastIndexOf('/') + 1) + "SHA256SUMS.txt" }
    $seen = ""
    foreach ($u in @((Get-ReleaseUrl "SHA256SUMS.txt"), $near)) {
        if (-not $u -or $u -eq $seen) { continue }
        $seen = $u
        try {
            $script:manifestText = Get-UrlText $u
            $script:manifestState = "ok"
            return
        } catch {
            # An answer from the release is final: a release that publishes no
            # manifest does not gain one by being asked through a mirror.
            if (Test-Answered $_) { break }
        }
    }
    $script:manifestText = $null
    $script:manifestState = "missing"
}

# The published hash for one asset name, `$null` when the manifest lists none.
# The name is compared whole — `$fields[-1]` is the file column in both
# `hash  name` and `hash *name` — so a target that is a prefix of another cannot
# match the wrong line.
function Get-ExpectedHash([string]$name) {
    if (-not $script:manifestText) { return $null }
    foreach ($line in ($script:manifestText -split "`n")) {
        $fields = $line.Trim() -split '\s+'
        if ($fields.Count -ge 2 -and $fields[-1].TrimStart('*') -eq $name) {
            return $fields[0].ToLower()
        }
    }
    return $null
}

function Write-ManifestNote([string]$text) {
    if ($script:manifestNoteShown) { return }
    $script:manifestNoteShown = $true
    Write-Host "Warning: $text" -ForegroundColor Yellow
}

# A destination that already holds this release is not downloaded again: the
# reason to run the installer a second time is to run the tester, and the file
# that is there is the one it would have fetched. `latest` is left out — there is
# no fixed string to compare the file's own report against.
$installedVersion = ""
if (Test-Path $out) {
    try {
        $reported = (& $out --version 2>$null | Out-String).Trim()
        if ($reported) { $installedVersion = ($reported -split '\s+')[-1].TrimStart('v') }
    } catch {
        $installedVersion = ""
    }
}
$alreadyCurrent = $false
if ($installedVersion -and $version -ne "latest") {
    if ($installedVersion -eq $version.TrimStart('v')) {
        $alreadyCurrent = $true
        Write-Host "Already installed: dpi-detector $installedVersion at $out - nothing to download." -ForegroundColor Green
    } else {
        Write-Host "Installed: dpi-detector $installedVersion, this installer carries $($version.TrimStart('v')) - installing that release." -ForegroundColor Yellow
    }
}

if (-not $alreadyCurrent) {
    $urls = Get-ReleaseUrlList $target
    Write-Host "Downloading DPI Detector ($version)..." -ForegroundColor Cyan

    $downloaded = $false
    foreach ($u in $urls) {
        Write-Host "Fetching from: $u ..." -ForegroundColor DarkGray
        try {
            $req = [System.Net.HttpWebRequest]::Create($u)
            $req.Timeout = 5000
            $req.ReadWriteTimeout = 60000
            $req.UserAgent = "curl/8.0"
            $resp = $req.GetResponse()
            $stream = $resp.GetResponseStream()
            $fs = [System.IO.File]::Create($tmp)
            try {
                # `Stream.CopyTo` is .NET 4.0; the read loop is what the .NET 3.5
                # under PowerShell 2.0 has.
                $buffer = New-Object byte[] 65536
                while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $fs.Write($buffer, 0, $read)
                }
            } finally {
                $fs.Close()
                $stream.Close()
                $resp.Close()
            }
        } catch {
            Remove-Item -Force $tmp -ErrorAction SilentlyContinue
            continue
        }
        if ((Get-Item $tmp).Length -le 100000) {
            Remove-Item -Force $tmp -ErrorAction SilentlyContinue
            continue
        }

        # The manifest is looked for beside the file it describes, so it is asked
        # once the first candidate is on disk — the order `install.sh` uses.
        Get-Manifest $u
        if ($script:manifestState -eq "ok") {
            $expectedHash = Get-ExpectedHash $target
            if (-not $expectedHash) {
                Write-ManifestNote "$target is not listed in SHA256SUMS.txt; installing without a checksum check."
            }
        } else {
            $expectedHash = $null
            Write-ManifestNote "this release has no SHA256SUMS.txt; installing without a checksum check."
        }
        if ($expectedHash) {
            $actual = Get-FileSha256 $tmp
            if ($actual -ne $expectedHash) {
                Write-Host "Warning: checksum mismatch for $target from $u (expected $expectedHash, got $actual); trying the next mirror." -ForegroundColor Yellow
                Remove-Item -Force $tmp -ErrorAction SilentlyContinue
                continue
            }
            Write-Host "Checksum verified: $actual" -ForegroundColor Green
        }
        $downloaded = $true
        break
    }

    if (-not $downloaded) {
        Write-Error "Failed to download $target from all mirrors."
        exit 1
    }

    try {
        Move-Item -Force $tmp $out
    } catch {
        # Windows refuses to replace the image of a running process, and the
        # access-denied it answers with does not say why.
        if (Get-Process -Name "dpi-detector" -ErrorAction SilentlyContinue) {
            Remove-Item -Force $tmp -ErrorAction SilentlyContinue
            Write-Host "Error: $out is in use - stop dpi-detector and run this installer again." -ForegroundColor Red
            exit 1
        }
        throw
    }
}

Write-Host "Binary: $out" -ForegroundColor Cyan
Write-Host "Menu:   & `"$out`"" -ForegroundColor Cyan
Write-Host "Help:   & `"$out`" --help" -ForegroundColor Cyan
Write-Host "Starting DPI Detector..." -ForegroundColor Green
if ($AppArgs -and $AppArgs.Count -gt 0) {
    & $out @AppArgs
} else {
    & $out
}
