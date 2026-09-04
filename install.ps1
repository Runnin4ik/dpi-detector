$ErrorActionPreference = 'Stop'
$repo = "Runnin4ik/dpi-detector"
$version = "v5.0.0-alpha.2"
$url = "https://github.com/$repo/releases/download/$version/dpi-detector-windows-x86_64.exe"
$out = "$env:TEMP\dpi-detector.exe"

Write-Host "Downloading DPI Detector ($version)..." -ForegroundColor Cyan
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $url -OutFile $out

Write-Host "Binary: $out" -ForegroundColor Cyan
Write-Host "Run:    & `"$out`" -t 1 --batch" -ForegroundColor Cyan
Write-Host "Starting DPI Detector..." -ForegroundColor Green
& $out @args
