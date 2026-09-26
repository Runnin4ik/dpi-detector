# Capture while one client runs, in one step.
#
# Started by hand ten times in a row, `dumpcap` in the background is a coin flip:
# its stdout is a pipe nobody drains, so it blocks before its own duration fires
# and the next capture finds the interface busy. This runs the capture, then the
# client, then waits for the capture to finish by itself.
#
#   pwsh -NoProfile -File scripts/quic/capture-run.ps1 `
#     -Out target/validation/hello-ours.pcapng -Exe ./target/release-local/dpi-detector.exe `
#     -ExeArgs '--tests 2 -d www.apkmirror.com --lang en'
#
# `-Filter` defaults to the QUIC column's traffic; `tcp port 443` captures the TLS
# columns instead, which is what a TLS handshake that never completes needs.
#
# `-ExeArgs` is one string split on whitespace: bound as an array from `-File`,
# PowerShell joins it back into a single argument and the client sees
# `--tests,2,-d,...`.
param(
    [Parameter(Mandatory = $true)][string]$Out,
    [Parameter(Mandatory = $true)][string]$Exe,
    [string]$ExeArgs = '',
    [int]$Seconds = 30,
    [string]$Filter = 'udp port 443',
    [string]$Interface = '\Device\NPF_{2D03CDCB-E549-4703-89C3-A8BFD9BC8A5F}'
)

$ErrorActionPreference = 'Stop'
$dumpcap = 'C:\Program Files\Wireshark\dumpcap.exe'
$tshark = 'C:\Program Files\Wireshark\tshark.exe'
$full = Join-Path (Get-Location) $Out
$log = "$full.dumpcap.log"

# Any leftover capture holds the interface; nothing here should outlive its own
# duration, so clearing them is safe.
Get-Process dumpcap -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

# `-WindowStyle Hidden` with nobody reading its output hid a capture that never
# opened the adapter: the file came out empty and the script still said
# "capture: ...". The log below is what makes that failure visible.
$capture = Start-Process -FilePath $dumpcap `
    -ArgumentList "-i `"$Interface`" -f `"$Filter`" -w `"$full`" -a duration:$Seconds" `
    -PassThru -WindowStyle Hidden -RedirectStandardError $log
Start-Sleep -Seconds 3

$arguments = @($ExeArgs -split '\s+' | Where-Object { $_ -ne '' })
Write-Output "running: $Exe $($arguments -join ' ')"
& $Exe @arguments | Out-Null

$capture.WaitForExit()

$packets = (& $tshark -r $full -T fields -e frame.number 2>$null | Measure-Object -Line).Lines
if ($packets -eq 0) {
    Write-Output "capture: $Out — NOTHING CAPTURED"
    if (Test-Path $log) { Get-Content $log | Write-Output }
    exit 1
}
Write-Output "capture: $Out ($packets packets)"
