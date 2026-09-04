[CmdletBinding()]
param(
    [string]$InstallDir = "",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$AppArgs
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$repo = "Runnin4ik/dpi-detector"
$version = if ($env:DPI_VERSION) { $env:DPI_VERSION } else { "v5.0.0-alpha.1" }

# Architecture detection with 32-bit WoW64 fallback protection
$rawArch = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) {
    $rawArch = $env:PROCESSOR_ARCHITEW6432
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

$urls = [System.Collections.Generic.List[string]]::new()
if ($env:DPI_MIRRORS) {
    foreach ($m in $env:DPI_MIRRORS.Split(" ,;`t", [System.StringSplitOptions]::RemoveEmptyEntries)) {
        $urls.Add("$($m.TrimEnd('/'))/$target")
    }
}
$ghUrl = if ($version -eq "latest") {
    "https://github.com/$repo/releases/latest/download/$target"
} else {
    "https://github.com/$repo/releases/download/$version/$target"
}

$urls.Add($ghUrl)
$urls.Add("https://ghfast.top/$ghUrl")
$urls.Add("https://ghproxy.net/$ghUrl")
$urls.Add("https://gh-proxy.com/$ghUrl")
$urls.Add("https://ghproxy.vip/$ghUrl")
$urls.Add("https://gh-proxy.org/$ghUrl")
$urls.Add("https://github.boki.moe/$ghUrl")
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
        $stream.CopyTo($fs)
        $fs.Close()
        $resp.Close()
        if ((Get-Item $tmp).Length -gt 100000) {
            $downloaded = $true
            break
        }
    } catch {
        Remove-Item -Force $tmp -ErrorAction SilentlyContinue
    }
}

if (-not $downloaded) {
    Write-Error "Failed to download $target from all mirrors."
    exit 1
}

Move-Item -Force $tmp $out

Write-Host "Binary: $out" -ForegroundColor Cyan
Write-Host "Run:    & `"$out`" -t 1" -ForegroundColor Cyan
Write-Host "Menu:   & `"$out`"" -ForegroundColor Cyan
Write-Host "Starting DPI Detector..." -ForegroundColor Green
if ($AppArgs -and $AppArgs.Count -gt 0) {
    & $out @AppArgs
} else {
    & $out
}
