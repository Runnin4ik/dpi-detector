$ErrorActionPreference = 'Stop'
$repo = "Runnin4ik/dpi-detector"
$version = if ($env:DPI_VERSION) { $env:DPI_VERSION } else { "latest" }
$target = "dpi-detector-windows-x86_64.exe"
$out = "$env:TEMP\dpi-detector.exe"
$tmp = "$env:TEMP\dpi-detector.tmp.$([System.Diagnostics.Process]::GetCurrentProcess().Id).exe"

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
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

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
Write-Host "Run:    & `"$out`" -t 1 --batch" -ForegroundColor Cyan
Write-Host "Starting DPI Detector..." -ForegroundColor Green
& $out @args
