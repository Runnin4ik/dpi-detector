<#
.SYNOPSIS
  Collects the DNS/TLS facts behind a test-1 report on a Windows machine.

.DESCRIPTION
  Built for the case where test 1 (DNS availability) shows an endpoint failure
  such as NO CA BUNDLE for DoH/DoT. One run gathers, into a single text file:

    1. host, PowerShell and process context;
    2. dpi-detector --version, and which config.yml the tool reads;
    3. a test-1 run with --json, with the per-endpoint failures[] it reports
       (status + detail), plus a test-0 run, which uses the only other
       certificate-verifying client in the program;
    4. the TLS chain Windows itself sees for each DoH/DoT host, with the top
       root named and marked against the roots Mozilla no longer trusts for
       server authentication -- an absent root is what NO CA BUNDLE means;
    5. the roots in the Windows store that fall in the same absent set;
    6. certificate roots on the machine that look like local TLS interception
       (antivirus web shields, corporate filters);
    7. resolution, hosts-file and NRPT entries for those host names;
    8. a reading of what was found.

  It changes nothing, needs no admin rights, and needs no Rust, cargo or build
  tools: it is one file that runs on the Windows PowerShell every Windows has
  (5.1) as well as on PowerShell 7.

  The detector is optional. A report without it still carries sections 4-8, and
  those are where a certificate-path question is answered; run with it, and the
  report also carries what the tool itself says about the endpoints.

.FOR WHOEVER SENDS THIS OUT
  Send this one file, and tell the user to unpack the detector somewhere (any
  folder) and then run, from the folder they saved the script in:

    powershell -NoProfile -ExecutionPolicy Bypass -File .\dns-ca-report.ps1

  When the user reported one endpoint -- `NO CA BUNDLE` on a single DoH row --
  give them the command with `-Endpoint <the URL from that row>`, so the report
  is about that endpoint instead of the whole list:

    powershell -NoProfile -ExecutionPolicy Bypass -File .\dns-ca-report.ps1 -Endpoint https://security.cloudflare-dns.com/dns-query

  Both commands work with PowerShell 7 (`pwsh`) as they are. A file that
  arrived by mail or chat carries the mark of the web, and Windows refuses to
  run it under the default policy; -ExecutionPolicy Bypass runs it for that one
  process and changes nothing on the machine. If the detector is not in PATH or
  in one of the usual places, the script asks for its folder (or takes
  -Tool <folder-or-exe>; a dragged folder comes in quoted, which is fine). It
  writes the report to the Desktop, prints its path, and that file is what comes
  back.

  What the report contains: machine and user name, the external IP, the
  machine's DNS servers, hosts-file and NRPT entries, and certificate names.
  Nothing else, and no credentials.

.PARAMETER Tool
  The detector: a path to dpi-detector.exe, or a folder that holds it (an
  unpacked release archive, wherever it was unpacked). A path given here is
  checked first, and when it holds nothing the search below runs anyway -- the
  report says which of the two produced the path, so a wrong folder does not
  quietly become a different binary. When -Tool is omitted, or holds nothing,
  the script looks on PATH, next to itself and one level around it, on the
  Desktop, in the profile, in Downloads, and in C:\tools and
  %LOCALAPPDATA%\Programs -- and a candidate whose folder also holds a
  config.yml wins, because that is an install rather than a stray copy. If
  nothing is found it asks; an empty answer skips sections 2 and 3 and the rest
  still runs.

.PARAMETER OutDir
  Where the report is written. Default: the Desktop folder this user really has
  (OneDrive moves it), or the profile when there is none.

.PARAMETER Endpoint
  The one DoH endpoint that misbehaved, exactly as the tool's table printed it:
  `https://security.cloudflare-dns.com/dns-query`. A bare host or `host:port` is
  accepted too. With it the report narrows to that endpoint:

    * section 2 measures it alone -- the tool is run from a temporary folder
      holding a copy of the config whose DNS_AVAILABILITY_SERVERS lists nothing
      else, so one endpoint gets one verdict with every other key untouched;
    * sections 4 and 6 ask only that host, and both 443 and 853 are reported even
      when one of them answers, because a name that answers on one port while the
      other hands over a chain the tool cannot complete is the finding;
    * section 7 says so, so the report is not mistaken for a whole-machine one.

  The URL from the config is used when the config has a row for that host, so the
  focused run asks the same URL the user's run asked.

.PARAMETER Hosts
  DoH/DoT endpoints to inspect when no -Endpoint is given. Default: dns.google,
  cloudflare-dns.com, dns.quad9.net, dns.adguard-dns.com, dns.sb,
  common.dot.dns.yandex.net.

.PARAMETER Ports
  Ports tried per host, in order. Default: 443 (DoH) then 853 (DoT).

.PARAMETER TimeoutMs
  Connect/read timeout per attempt, milliseconds. Default: 6000.

.PARAMETER NoPrompt
  Never ask for the detector. For scripted runs: the report is written with
  whatever was found, and sections 2 and 3 are skipped when nothing was.

.PARAMETER SkipTests
  Do not run dpi-detector at all (sections 4-8 only).

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\dns-ca-report.ps1

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\dns-ca-report.ps1 -Endpoint https://security.cloudflare-dns.com/dns-query

.EXAMPLE
  pwsh -NoProfile -File dns-ca-report.ps1 -Tool 'D:\Downloads\dpi-detector-windows-x86_64'

.EXAMPLE
  pwsh -NoProfile -File dns-ca-report.ps1 -Tool C:\tools\dpi-detector.exe -Hosts security.cloudflare-dns.com
#>
[CmdletBinding()]
param(
    [string]$Tool = '',
    [string]$OutDir = '',
    [string]$Endpoint = '',
    [string[]]$Hosts = @(
        'dns.google', 'cloudflare-dns.com', 'dns.quad9.net',
        'dns.adguard-dns.com', 'dns.sb', 'common.dot.dns.yandex.net'
    ),
    [int[]]$Ports = @(443, 853),
    [int]$TimeoutMs = 6000,
    [switch]$NoPrompt,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
$OutputEncoding = [System.Text.Encoding]::UTF8

# Certificate names Mozilla no longer trusts for TLS server authentication, and
# which are therefore absent from the root bundle the detector compiles in
# (webpki-roots 1.0.9). Windows keeps its own view of these and still trusts
# them, which is why a browser on the same machine is happy while the tool
# answers NO CA BUNDLE. Matched against the root's Common Name, exactly.
$LegacyRoots = @(
    'AAA Certificate Services'
    'AddTrust External CA Root'
    'Baltimore CyberTrust Root'
    'DST Root CA X3'
    'DigiCert Assured ID Root CA'
    'DigiCert Global Root CA'
    'DigiCert High Assurance EV Root CA'
    'Entrust Root Certification Authority'
    'Entrust Root Certification Authority - EC1'
    'Entrust Root Certification Authority - G2'
    'Entrust.net Certification Authority (2048)'
    'GlobalSign Root CA'
    'GlobalSign Root CA - R2'
    'Go Daddy Class 2 Certification Authority'
    'QuoVadis Root CA 2'
    'QuoVadis Root CA 3'
    'SecureTrust CA'
    'Starfield Class 2 Certification Authority'
    'thawte Primary Root CA'
    'thawte Primary Root CA - G2'
    'thawte Primary Root CA - G3'
    'VeriSign Class 3 Public Primary Certification Authority - G3'
    'VeriSign Class 3 Public Primary Certification Authority - G4'
    'VeriSign Class 3 Public Primary Certification Authority - G5'
    'VeriSign Universal Root Certification Authority'
)

# Roots installed by TLS-inspecting software. A chain that runs through one of
# these is a local proxy, not the endpoint's own certificate.
$InterceptionRoots = 'Kaspersky|ESET|Dr\.?Web|AdGuard|Avast|AVG|Bitdefender|Sophos|Netskope|Zscaler|Fortinet|Check Point|Palo Alto|Fiddler|Charles|mitmproxy|Burp|Web Security|SSL Inspection|Anti-?Virus'

$script:Lines = New-Object System.Collections.Generic.List[string]

function Emit {
    param([Parameter(ValueFromPipeline = $true)]$InputObject)
    process {
        $text = if ($InputObject -is [string]) { $InputObject } else { $InputObject | Out-String -Width 200 }
        foreach ($line in ($text -split "`r?`n")) {
            $script:Lines.Add($line)
            Write-Host $line
        }
    }
}

function Section {
    param([string]$Title)
    Emit ''
    Emit ("--- " + $Title + " ---")
}

function Format-Cert {
    param($Certificate)
    if ($null -eq $Certificate) { return '(none)' }
    return ($Certificate.Subject -replace '\s*,\s*', ', ')
}

function Get-CommonName {
    param([string]$DistinguishedName)
    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return '' }
    foreach ($rdn in ($DistinguishedName -split ',')) {
        if ($rdn -match '^\s*CN=(.+)$') { return $Matches[1].Trim() }
    }
    foreach ($rdn in ($DistinguishedName -split ',')) {
        if ($rdn -match '^\s*OU=(.+)$') { return $Matches[1].Trim() }
    }
    return $DistinguishedName.Trim()
}

function Test-LegacyRoot {
    param([string]$Name)
    foreach ($legacy in $LegacyRoots) {
        if ($Name -eq $legacy) { return $true }
    }
    return $false
}

function Test-InterceptionName {
    param([string]$Name)
    # Case-sensitive on purpose: at case-insensitive matching the host name of
    # an endpoint whose brand is also an inspection vendor ("dns.adguard-dns.com")
    # reads as an intercepting certificate.
    return ($Name -cmatch $InterceptionRoots)
}

function Test-PrivateAddress {
    param([string]$Address)
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$ip)) { return $false }
    if ([System.Net.IPAddress]::IsLoopback($ip)) { return $true }
    $bytes = $ip.GetAddressBytes()
    if ($bytes.Length -eq 4) {
        if ($bytes[0] -eq 0) { return $true }
        if ($bytes[0] -eq 10) { return $true }
        if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $true }
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $true }
        if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) { return $true }
        if ($bytes[0] -eq 198 -and $bytes[1] -ge 18 -and $bytes[1] -le 19) { return $true }
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return $true }
    }
    return $false
}

# A release archive unpacks either straight into the chosen folder or into one
# subfolder of it (`dpi-detector-windows-x86_64/`), so one level down is scanned
# too. The subfolder scan is bounded: the folder a user picks to unpack into is
# a Downloads or a Desktop, not a drive root, and nothing here should ever walk
# a whole disk on a stranger's machine.
function Find-DetectorIn {
    param([string]$Directory)
    if (-not $Directory) { return }
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { return }
    $dirs = @($Directory)
    $dirs += @(Get-ChildItem -LiteralPath $Directory -Directory -ErrorAction SilentlyContinue |
        Select-Object -First 25 | ForEach-Object { $_.FullName })
    foreach ($dir in $dirs) {
        Get-ChildItem -LiteralPath $dir -Filter 'dpi-detector*.exe' -File -ErrorAction SilentlyContinue |
            ForEach-Object { $_.FullName }
    }
}

# The banner of a candidate that this machine can actually start, or '' when it
# cannot. A release is eleven artifacts, and a folder where one was unpacked
# often also holds a copy for another platform -- `dpi-detector-windows-x86_64.exe`
# that is a Linux build refuses to start, and the report must not be about a file
# that never ran. An empty answer is a failed start, a wrong banner, or a
# non-zero exit, and the caller moves on to the next candidate.
function Test-DetectorRuns {
    param([string]$Exe)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $text = (& $Exe --version 2>&1 | Out-String).Trim()
    } catch {
        return ''
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($text -match 'dpi[-_ ]?detector') { return $text }
    return ''
}

# The exe to report on, or $null. What the caller named is checked first; when
# it holds nothing the usual-places search runs anyway, and the caller says which
# of the two produced the path -- a report that quietly used another copy while
# implying the user pointed at the right one is worse than one that admits the
# path was wrong.
#
# A candidate whose folder also holds a config.yml wins over one that does not:
# that is an unpacked install rather than a stray exe, and it is the config the
# tool falls back to when the working directory has none.
function Resolve-DetectorTool {
    param([string]$Preferred)

    $candidates = New-Object System.Collections.Generic.List[string]
    $searched = New-Object System.Collections.Generic.List[string]

    # The usual places an unpacked release archive ends up: the tool on PATH, the
    # script's own folder and its parent (the archive sent next to the script),
    # the working directory, the Desktop and the profile, Downloads, and the two
    # folders a "portable app" is customarily unpacked into.
    $scriptRoot = $PSScriptRoot
    $scanUsualPlaces = {
        $onPath = Get-Command 'dpi-detector.exe' -ErrorAction SilentlyContinue
        if ($onPath) { $candidates.Add($onPath.Source) }

        $dirs = New-Object System.Collections.Generic.List[string]
        if ($scriptRoot) {
            $dirs.Add($scriptRoot)
            $parent = Split-Path -Parent $scriptRoot
            if ($parent) { $dirs.Add($parent) }
        }
        $dirs.Add((Get-Location).Path)
        foreach ($known in @('Desktop', 'UserProfile')) {
            $path = [Environment]::GetFolderPath($known)
            if ($path) { $dirs.Add($path) }
        }
        if ($env:USERPROFILE) { $dirs.Add((Join-Path $env:USERPROFILE 'Downloads')) }
        if ($env:LOCALAPPDATA) { $dirs.Add((Join-Path $env:LOCALAPPDATA 'Programs')) }
        $dirs.Add('C:\tools')

        foreach ($dir in $dirs) {
            if (-not $dir) { continue }
            $searched.Add($dir)
            Find-DetectorIn $dir | ForEach-Object { $candidates.Add($_) }
        }
    }

    $script:ToolHintFailed = $false
    if ($Preferred) {
        # A folder dragged into the console arrives with quotes around it.
        $text = $Preferred.Trim().Trim('"').Trim("'")
        $item = Get-Item -LiteralPath $text -ErrorAction SilentlyContinue
        if ($item -and $item.PSIsContainer) {
            $searched.Add($text)
            Find-DetectorIn $text | ForEach-Object { $candidates.Add($_) }
        } elseif ($item) {
            $candidates.Add($item.FullName)
        } else {
            $onPath = Get-Command $text -ErrorAction SilentlyContinue
            if ($onPath) { $candidates.Add($onPath.Source) } else { $searched.Add($text) }
        }
        if ($candidates.Count -eq 0) {
            # What was named held nothing. The search still runs, because the
            # user who pastes the wrong path usually has the detector somewhere
            # sensible -- but the report says which path came from where, so a
            # named folder never turns into a different binary unannounced.
            $script:ToolHintFailed = $true
            & $scanUsualPlaces
        }
    } else {
        & $scanUsualPlaces
    }

    $script:ToolSearched = @($searched | Select-Object -Unique)
    $script:ToolVersion = ''
    $script:ToolUnusable = ''
    $unique = @($candidates | Where-Object { $_ } | Select-Object -Unique)
    $installed = @($unique | Where-Object {
        Test-Path -LiteralPath (Join-Path (Split-Path -Parent $_) 'config.yml')
    })
    # An install first, then whatever else turned up; the first one that answers
    # `--version` is the tool. A file this machine cannot start is not chosen,
    # and when nothing answers the first candidate is still named, so the report
    # can say which file was wrong rather than only that nothing worked.
    $ordered = @($installed) + @($unique | Where-Object { $installed -notcontains $_ })
    foreach ($candidate in $ordered) {
        $banner = Test-DetectorRuns -Exe $candidate
        if ($banner) {
            $script:ToolVersion = $banner
            return $candidate
        }
    }
    if ($ordered.Count -gt 0) { $script:ToolUnusable = $ordered[0] }
    return $null
}

$script:ToolSearched = @()
$script:ToolVersion = ''
$script:ToolUnusable = ''

# Runs the detector where the script was started, and joins stdout with stderr:
# `--json` writes one document to stdout while warnings go to stderr, and the
# report needs both.
#
# The working directory is deliberately left alone. The tool reads config.yml
# from the working directory first and from the folder the exe sits in second
# (`config.rs::find_config_file`), so running it from somewhere else would put a
# different endpoint list in the report than the one the user actually saw.
function Invoke-Detector {
    param([string]$Exe, [string[]]$Arguments)
    return (& $Exe @Arguments 2>&1 | Out-String)
}

# The one endpoint the report is about. The tool's table prints it as a URL
# (`https://security.cloudflare-dns.com/dns-query`), which is what gets pasted,
# but a bare host and a `host:port` pair are pasted too. `Port` is the port to
# try first: an explicit one wins, `http://` defaults to 80, everything else 443.
function ConvertTo-EndpointTarget {
    param([string]$Text)

    $value = $Text.Trim().Trim('"').Trim("'")
    $hostName = $value
    $port = 443
    if ($value -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') {
        $uri = $null
        if ([System.Uri]::TryCreate($value, [System.UriKind]::Absolute, [ref]$uri)) {
            $hostName = $uri.Host
            if ($uri.IsDefaultPort) {
                if ($uri.Scheme -eq 'http') { $port = 80 }
            } else {
                $port = $uri.Port
            }
        }
    } elseif ($value -match '^\[(.+)\]:(\d+)$') {
        $hostName = $Matches[1]
        $port = [int]$Matches[2]
    } elseif ($value -match '^([^:/]+):(\d+)$') {
        $hostName = $Matches[1]
        $port = [int]$Matches[2]
    }
    return [pscustomobject]@{ Raw = $value; Host = $hostName; Port = $port }
}

# The `DNS_AVAILABILITY_SERVERS` rows of a config.yml, as
# (address, provider, kind, port). Only the shape this file needs is understood:
# a YAML parser is not the point here, and a line it cannot read is skipped
# rather than guessed at.
function Get-DnsServerRows {
    param([string]$Path)
    $rows = @()
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $rows }
    foreach ($line in [System.IO.File]::ReadAllLines($Path, [System.Text.Encoding]::UTF8)) {
        if ($line -match '^\s*-\s*\[\s*"([^"]+)"\s*,\s*"([^"]*)"\s*,\s*"(udp|doh_wire|dot)"\s*(?:,\s*(\d+)\s*)?\]') {
            $port = 0
            if ($Matches[4]) { $port = [int]$Matches[4] }
            $rows += [pscustomobject]@{
                Address = $Matches[1]
                Provider = $Matches[2]
                Kind = $Matches[3]
                Port = $port
            }
        }
    }
    return $rows
}

# The tool's own row for the endpoint that misbehaved, so the focused run asks
# the same URL it asked before -- a synthesised `https://host/dns-query` would be
# a different request whenever the real path is not that one. `$null` when the
# config has no DoH row for the host, and the caller falls back to the guess.
function Get-DohRowForHost {
    param([string]$ConfigPath, [string]$HostName)
    foreach ($row in (Get-DnsServerRows -Path $ConfigPath)) {
        if ($row.Kind -ne 'doh_wire') { continue }
        $uri = $null
        $rowHost = $row.Address
        if ([System.Uri]::TryCreate($row.Address, [System.UriKind]::Absolute, [ref]$uri)) { $rowHost = $uri.Host }
        if ($rowHost -ieq $HostName) { return $row }
    }
    return $null
}

# A copy of the config that lists nothing but this endpoint, written into a
# folder of its own: the tool reads config.yml from the working directory first,
# so running it there is how a single endpoint gets measured in isolation, with
# every other key of the user's config untouched. The file is read and written
# as UTF-8 explicitly -- `Get-Content` would mangle the Russian comments on
# Windows PowerShell 5.1, and the tool's YAML parser reads bytes.
function New-FocusedConfig {
    param([string]$BasePath, [string]$Address, [string]$Provider, [int]$Port, [string]$Directory)

    $row = '["' + $Address + '", "' + $Provider + '", "doh_wire"'
    if ($Port -gt 0) { $row += ', ' + $Port }
    $row += ']'

    $source = @()
    if ($BasePath -and (Test-Path -LiteralPath $BasePath)) {
        $source = @([System.IO.File]::ReadAllLines($BasePath, [System.Text.Encoding]::UTF8))
    }

    $out = New-Object System.Collections.Generic.List[string]
    $replaced = $false
    $inside = $false
    foreach ($line in $source) {
        if ($line -match '^DNS_AVAILABILITY_SERVERS:') {
            $out.Add('DNS_AVAILABILITY_SERVERS:')
            $out.Add('  - ' + $row)
            $replaced = $true
            $inside = $true
            continue
        }
        if ($inside) {
            # The list ends at the next key that starts at column 0.
            if ($line -match '^[A-Za-z0-9_]+:') { $inside = $false } else { continue }
        }
        $out.Add($line)
    }
    if (-not $replaced) {
        $out.Add('DNS_AVAILABILITY_SERVERS:')
        $out.Add('  - ' + $row)
    }
    $null = New-Item -ItemType Directory -Path $Directory -Force
    [System.IO.File]::WriteAllLines(
        (Join-Path $Directory 'config.yml'),
        [string[]]$out,
        (New-Object System.Text.UTF8Encoding($false)))
    return (Join-Path $Directory 'config.yml')
}

# -- 0. Context ---------------------------------------------------------------

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $OutDir) {
    # GetFolderPath knows about a OneDrive-redirected Desktop; $env:USERPROFILE\Desktop
    # does not exist on such a machine and the report would land on the floor.
    $OutDir = [Environment]::GetFolderPath('Desktop')
    if (-not $OutDir) { $OutDir = $env:USERPROFILE }
}
if (-not (Test-Path -LiteralPath $OutDir)) { $null = New-Item -ItemType Directory -Path $OutDir -Force }
$reportPath = Join-Path $OutDir ("dpi-dns-ca-report-" + $env:COMPUTERNAME + "-" + $stamp + ".txt")

Emit '=== DPI Detector / DNS trust report ==='
Emit ("generated  : " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'))

$os = $null
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    Emit ("machine    : " + $env:COMPUTERNAME + "  (" + $os.Caption + " " + $os.Version + ", " + $os.OSArchitecture + ")")
} catch {
    Emit ("machine    : " + $env:COMPUTERNAME + "  (OS details unavailable: " + $_.Exception.Message + ")")
}
Emit ("powershell : " + $PSVersionTable.PSVersion.ToString() + " (" + $PSVersionTable.PSEdition + ")")
try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = (New-Object System.Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator)
    Emit ("user       : " + $identity.Name + "  (elevated: " + $admin + ")")
} catch { }
Emit ("location   : " + (Get-Location).Path)
Emit ("report     : " + $reportPath)

# -- 1. Tool ------------------------------------------------------------------

Section '1. dpi-detector'

$toolPath = Resolve-DetectorTool -Preferred $Tool
$script:ToolHintFailed = [bool]$script:ToolHintFailed
$toolDir = $null
if (-not $toolPath -and $script:ToolUnusable -and
    [Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
    Write-Host ''
    Write-Host ("the dpi-detector file found does not run on this machine: " + $script:ToolUnusable)
}
if (-not $toolPath -and -not $NoPrompt -and
    [Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
    Write-Host ''
    Write-Host 'dpi-detector.exe was not found in the usual places.'
    Write-Host 'Paste the folder it was unpacked into (or the path to the exe), or press Enter to skip:'
    for ($attempt = 0; $attempt -lt 3 -and -not $toolPath; $attempt++) {
        $answer = Read-Host 'folder or exe'
        if (-not $answer) { break }
        Write-Host ("looking in " + $answer + ' ...')
        $toolPath = Resolve-DetectorTool -Preferred $answer
        if (-not $toolPath) {
            if ($script:ToolUnusable) {
                Write-Host ("that file does not run on this machine: " + $script:ToolUnusable)
            }
            Write-Host 'nothing usable there; try another folder, or press Enter to skip.'
        }
    }
}

if ($toolPath) {
    Emit ("tool       : " + $toolPath)
    $toolDir = Split-Path -Parent $toolPath
    if ($script:ToolHintFailed) {
        Emit 'note       : nothing was found at the path given; this one came from the search below'
    }
    Emit ("version    : " + $script:ToolVersion)
} else {
    if ($script:ToolUnusable) {
        # Found, but this machine cannot start it: a release archive holds one
        # artifact per platform, and the wrong one lands in a folder beside the
        # right one easily. Said out loud, and the run continues without it --
        # sections 4-8 answer the certificate question on their own.
        Emit ("tool       : " + $script:ToolUnusable)
        Emit 'warning    : this file does not run on this machine (a build for another platform?), or it is not dpi-detector'
        Emit '             sections 2 and 3 are skipped; sections 4-8 still run'
        Emit '             if the detector is elsewhere, run this script again with -Tool <its folder>'
    } else {
        Emit 'tool       : not found -- sections 2 and 3 are skipped, sections 4-8 still run'
    }
    if ($script:ToolSearched.Count -gt 0) {
        Emit ('searched   : ' + ($script:ToolSearched -join '; '))
    }
    $toolPath = $null
}

# The tool reads config.yml from the working directory first, from the folder the
# exe sits in second, and uses the copy compiled into the binary when neither has
# one (`config.rs::find_config_file`). The run below happens in the folder the
# script was started from -- exactly as the tool is used normally -- so this is
# the order the report has to state: naming the wrong file would describe a
# different endpoint list than the one the user saw.
$cfgHere = Join-Path (Get-Location).Path 'config.yml'
$cfgBeside = if ($toolDir) { Join-Path $toolDir 'config.yml' } else { '' }
if ($toolPath) {
    Emit ("tool dir   : " + $toolDir)
}
if (Test-Path -LiteralPath $cfgHere) {
    Emit ("config     : " + $cfgHere + "  (the working directory -- the tool reads this one)")
} elseif ($cfgBeside -and (Test-Path -LiteralPath $cfgBeside)) {
    Emit ("config     : " + $cfgBeside + "  (nothing in the working directory; the tool falls back to the one beside the exe)")
} else {
    Emit 'config     : none in the working directory or beside the exe -- the built-in defaults are used'
}

# -- 1b. The one endpoint that misbehaved, when one was named -----------------

# Everything below narrows to this endpoint: the tool measures it alone (a copy
# of the config that lists nothing else, run from its own folder), and the chain
# and resolution sections ask only its host, on the endpoint's own port first and
# on the other of 443/853 second -- the pair is the interesting comparison, since
# one port of a name answering while the other does not is what a chain served
# per edge looks like.
$target = $null
$focusedBaseConfig = ''
if ($Endpoint) {
    $target = ConvertTo-EndpointTarget -Text $Endpoint
    $focusedBaseConfig = if (Test-Path -LiteralPath $cfgHere) { $cfgHere }
        elseif ($cfgBeside -and (Test-Path -LiteralPath $cfgBeside)) { $cfgBeside } else { '' }
    $toolRow = Get-DohRowForHost -ConfigPath $focusedBaseConfig -HostName $target.Host
    $focusedAddress = 'https://' + $target.Host + '/dns-query'
    $focusedProvider = 'endpoint'
    $focusedPort = 0
    if ($toolRow) {
        $focusedAddress = $toolRow.Address
        $focusedProvider = $toolRow.Provider
        $focusedPort = $toolRow.Port
    }
    Emit ''
    Emit ("endpoint   : " + $focusedAddress)
    Emit ("             host " + $target.Host + ", port " + $target.Port + " first")
    if ($toolRow) {
        Emit ("             as this config lists it (provider " + $toolRow.Provider + ")")
    } else {
        if ($focusedBaseConfig) {
            Emit '             no DoH row for this host in the config: the URL above is the usual guess'
        } else {
            Emit '             no config.yml to read a row from: the URL above is the usual guess'
        }
    }
    Emit ("hosts      : only " + $target.Host + " is inspected; the default host list is ignored")
    $Hosts = @($target.Host)
    if ($target.Port -eq 853) { $Ports = @(853, 443) } else { $Ports = @($target.Port, 853) }
}

# -- 2. Test 1 and test 0 as the tool reports them ----------------------------

$dnsFailures = @()
$focusedDir = ''
if ($toolPath -and -not $SkipTests) {
    Section '2. test 1 - DNS availability (--json)'
    try {
        if ($target) {
            # The focused run: a copy of the config that lists only this endpoint,
            # and the tool started inside that folder, which is where it reads
            # config.yml from first. Everything else in the copy is the user's
            # own config, so timeouts and domain lists stay comparable with their
            # own run.
            $focusedDir = Join-Path ([System.IO.Path]::GetTempPath()) ('dpi-ca-report-' + $stamp)
            $focusedConfig = New-FocusedConfig -BasePath $focusedBaseConfig -Address $focusedAddress -Provider $focusedProvider -Port $focusedPort -Directory $focusedDir
            Emit ("config used: " + $focusedConfig + "  (written for this run: DNS_AVAILABILITY_SERVERS holds this one endpoint)")
            if (-not $focusedBaseConfig) { Emit '             (no config.yml was found to copy: the rest of the keys are the built-in defaults)' }
            Write-Host 'running dpi-detector --tests 1 against the one endpoint...'
            Push-Location -LiteralPath $focusedDir
            try {
                $json = (Invoke-Detector -Exe $toolPath -Arguments @('--tests', '1', '--json'))
            } finally {
                Pop-Location
            }
        } else {
            Write-Host 'running dpi-detector --tests 1 (about 20 s)...'
            $json = (Invoke-Detector -Exe $toolPath -Arguments @('--tests', '1', '--json'))
        }
        $payload = $json | ConvertFrom-Json
        $dns = $payload.results.dns_availability
        if ($null -eq $dns) {
            Emit 'no dns_availability block in the payload:'
            Emit $json
        } else {
            Emit ("doh " + $dns.doh_ok + "/" + $dns.doh_total + "   dot " + $dns.dot_ok + "/" + $dns.dot_total + "   udp " + $dns.udp_ok + "/" + $dns.udp_total)
            Emit ("hijacked_brands: " + (($dns.hijacked_brands | ForEach-Object { $_ }) -join ', '))
            $dnsFailures = @()
            # An empty `failures: []` is falsy in PowerShell, so the property has
            # to be asked for by name: a clean run used to read as a build too
            # old to have the field at all.
            if ($dns.PSObject.Properties.Name -contains 'failures') {
                $dnsFailures = @($dns.failures)
            } else {
                Emit 'failures[]: absent from this build (it appeared after 5.0.0-alpha.19; the table in the tool output has the same tokens)'
            }
            Emit ("failures: " + $dnsFailures.Count)
            if ($dnsFailures.Count -eq 0) {
                Emit '  (every endpoint answered every domain it was asked)'
            }
            foreach ($failure in $dnsFailures) {
                $reason = ''
                if ($failure.PSObject.Properties.Name -contains 'status' -and $failure.status) {
                    $reason = $failure.status + ' / ' + $failure.detail
                } else {
                    $reason = '(no connection-level failure recorded)'
                }
                Emit ("  [" + $failure.protocol + "] " + $failure.provider + "  " + $failure.endpoint + "  ok " + $failure.ok + "/" + $failure.total + "  " + $reason)
            }
            if (-not ($dnsFailures | Where-Object { $_.status -eq 'no_ca_bundle' })) {
                Emit 'no endpoint reported no_ca_bundle in this run'
            }
        }
    } catch {
        Emit ("test 1 FAILED: " + $_.Exception.Message)
    }

    Section '3. test 0 - external IP (the program''s other verifying client)'
    try {
        Write-Host 'running dpi-detector --tests 0 ...'
        $json0 = (Invoke-Detector -Exe $toolPath -Arguments @('--tests', '0', '--json'))
        $payload0 = $json0 | ConvertFrom-Json
        $net = $payload0.results.network_info
        if ($null -eq $net) {
            Emit 'no network_info block in the payload:'
            Emit $json0
        } else {
            if ($net.ipv4) { Emit ("ipv4 : " + $net.ipv4.ip + "  (" + $net.ipv4.latency_ms + " ms)") } else { Emit 'ipv4 : (not determined)' }
            if ($net.ipv6) { Emit ("ipv6 : " + $net.ipv6.ip) } else { Emit 'ipv6 : (not determined)' }
            Emit ("system dns : " + (($net.system_dns | ForEach-Object { $_ }) -join ', '))
            Emit ("tun        : " + (($net.tun | ForEach-Object { $_ }) -join ', '))
            Emit ("bypass     : " + (($net.bypass_tools | ForEach-Object { $_ }) -join ', '))
            Emit 'a missing ipv4 here while https browsing works means the interception covers this machine, not only DoH/DoT'
        }
    } catch {
        Emit ("test 0 FAILED: " + $_.Exception.Message)
    }
} elseif ($SkipTests) {
    Section '2. test 1 - skipped (-SkipTests)'
} else {
    Section '2. test 1 - skipped (no tool found)'
}

# -- 4. The chain Windows sees for each DoH/DoT host --------------------------

Section '4. TLS chain per DoH/DoT host (Windows trust store)'

$observedRoots = @()
$interceptionEvidence = @()
$validator = [System.Net.Security.RemoteCertificateValidationCallback]{ param($sender, $certificate, $chain, $errors) return $true }

Write-Host ("probing TLS chains for " + $Hosts.Count + " host(s) on ports " + ($Ports -join ', ') + ' ...')
# For the default list the chain of a host is the same on both ports, so the
# first one that answers is enough; for the one endpoint under investigation the
# pair is the point -- a name that answers on 853 while 443 hands over a chain
# the tool cannot complete is exactly what the report is for.
$everyPort = [bool]$target
foreach ($hostName in $Hosts) {
    $connected = $false
    $lastError = ''
    foreach ($port in $Ports) {
        if ($connected -and -not $everyPort) { continue }
        $tcp = $null
        $ssl = $null
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $task = $tcp.ConnectAsync($hostName, $port)
            if (-not $task.Wait($TimeoutMs)) { throw 'connect timeout' }
            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $validator)
            $ssl.AuthenticateAsClient($hostName)
            $leaf = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            Emit ''
            Emit ("[" + $hostName + ":" + $port + "]")
            Emit ("  leaf       : " + (Format-Cert $leaf))
            Emit ("  leaf issuer: " + ($leaf.Issuer -replace '\s*,\s*', ', '))
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $chain.ChainPolicy.RevocationMode = 'NoCheck'
            $built = $chain.Build($leaf)
            Emit ("  chain      : " + (($chain.ChainElements | ForEach-Object { Get-CommonName $_.Certificate.Subject }) -join '  ->  '))
            $windowsVerdict = 'trusted'
            if (-not $built) {
                $windowsVerdict = 'REJECTED (' + (($chain.ChainStatus | ForEach-Object { $_.Status }) -join ',') + ')'
            }
            Emit ("  windows    : " + $windowsVerdict)
            if ($chain.ChainElements.Count -gt 0) {
                $top = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
                $topName = Get-CommonName $top.Subject
                $observedRoots += $topName
                if (Test-LegacyRoot $topName) {
                    Emit ("  top root   : " + $topName)
                    Emit '               legacy for the tool: Mozilla kept this root for email only, so a chain that ends here reads NO CA BUNDLE'
                    Emit '               a chain that also carries a modern cross-signed root still verifies - the tool''s own no_ca_bundle verdicts are the proof'
                } elseif (Test-InterceptionName $topName) {
                    Emit ("  top root   : " + $topName + "  <-- local TLS interception")
                } else {
                    Emit ("  top root   : " + $topName + "  (not in the known-legacy list)")
                }
            }
            # The leaf is the endpoint's own certificate, not a CA: interception
            # shows in the certificates that signed it.
            for ($index = 1; $index -lt $chain.ChainElements.Count; $index++) {
                $name = Get-CommonName $chain.ChainElements[$index].Certificate.Subject
                if (Test-InterceptionName $name) {
                    Emit ("  interception: chain runs through an inspection certificate: " + $name)
                    $interceptionEvidence += ($hostName + " via " + $name)
                }
            }
            $connected = $true
        } catch {
            $lastError = $_.Exception.Message
            # With one endpoint under investigation every port is reported: a
            # port that fails while the other answers is the finding, and it
            # would otherwise be swallowed by the success of the other one.
            if ($everyPort) {
                Emit ''
                Emit ("[" + $hostName + ":" + $port + "] no TLS: " + $lastError)
            }
        } finally {
            if ($ssl) { $ssl.Dispose() }
            if ($tcp) { $tcp.Dispose() }
        }
    }
    if (-not $connected) {
        Emit ''
        Emit ("[" + $hostName + "] unreachable on ports " + ($Ports -join ',') + ": " + $lastError)
    }
}

# -- 5. Windows store roots that the tool cannot use --------------------------

Section '5. Windows store roots in the same absent set'

try {
    $roots = @(Get-ChildItem 'Cert:\LocalMachine\Root' -ErrorAction Stop)
    Emit ("LocalMachine\Root: " + $roots.Count + " certificates")
    $flagged = @()
    foreach ($root in $roots) {
        $name = Get-CommonName $root.Subject
        if ((Test-LegacyRoot $name) -or (Test-InterceptionName $name)) {
            $flagged += [pscustomobject]@{ Name = $name; NotAfter = $root.NotAfter.ToString('yyyy-MM-dd') }
        }
    }
    if ($flagged.Count -eq 0) {
        Emit '  none of the known-absent or interception roots is installed'
    } else {
        foreach ($item in ($flagged | Sort-Object Name)) {
            Emit ("  " + $item.Name + "  (expires " + $item.NotAfter + ")")
        }
    }
} catch {
    Emit ("store read FAILED: " + $_.Exception.Message)
}

$currentUserRoots = @()
try {
    $currentUserRoots = @(Get-ChildItem 'Cert:\CurrentUser\Root' -ErrorAction SilentlyContinue)
    Emit ("CurrentUser\Root: " + $currentUserRoots.Count + " certificates")
    foreach ($root in $currentUserRoots) {
        $name = Get-CommonName $root.Subject
        if (Test-InterceptionName $name) {
            Emit ("  " + $name + "  <-- inspection root in the user store")
        }
    }
} catch { }

# -- 6. Resolution, hosts file, NRPT ------------------------------------------

Section '6. Resolution, hosts file, NRPT'

foreach ($hostName in $Hosts) {
    foreach ($recordType in @('A', 'AAAA')) {
        try {
            $answers = @(Resolve-DnsName -Name $hostName -Type $recordType -ErrorAction Stop | Where-Object { $_.IPAddress })
            foreach ($answer in $answers) {
                $flag = if (Test-PrivateAddress $answer.IPAddress) { '  <-- loopback/private/reserved (VPN or local filter)' } else { '' }
                Emit ("  " + $hostName.PadRight(30) + $recordType.PadRight(5) + $answer.IPAddress + $flag)
            }
        } catch { }
    }
}

$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
try {
    $patterns = @('dns\.google', 'cloudflare-dns', 'quad9', 'adguard-dns', 'dns\.sb', 'yandex', 'dns-query', 'dot\.sb')
    $hits = @(Select-String -Path $hostsPath -Pattern $patterns -ErrorAction Stop)
    if ($hits.Count -eq 0) {
        Emit ("  hosts file: no entry matching " + ($patterns -join ', '))
    } else {
        foreach ($hit in $hits) { Emit ("  hosts file:" + $hit.LineNumber + ": " + $hit.Line.Trim()) }
    }
} catch {
    Emit ("  hosts file read FAILED: " + $_.Exception.Message)
}

try {
    if (Get-Command 'Get-DnsClientNrptPolicy' -ErrorAction SilentlyContinue) {
        $nrpt = @(Get-DnsClientNrptPolicy -ErrorAction Stop)
        if ($nrpt.Count -eq 0) {
            Emit '  NRPT: no policy'
        } else {
            foreach ($rule in $nrpt) {
                Emit ("  NRPT: " + (($rule.Namespace | ForEach-Object { $_ }) -join ',') + "  ->  " + (($rule.NameServers | ForEach-Object { $_ }) -join ','))
            }
        }
    } else {
        Emit '  NRPT: cmdlet unavailable'
    }
} catch {
    Emit ("  NRPT read FAILED: " + $_.Exception.Message)
}

try {
    $servers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.ServerAddresses })
    foreach ($server in $servers) {
        Emit ("  DNS server: " + $server.InterfaceAlias + " -> " + (($server.ServerAddresses | ForEach-Object { $_ }) -join ', '))
    }
} catch { }

# -- 7. Reading --------------------------------------------------------------

Section '7. Reading'

$noCa = @($dnsFailures | Where-Object { $_.status -eq 'no_ca_bundle' })
$legacySeen = @($observedRoots | Where-Object { Test-LegacyRoot $_ } | Select-Object -Unique)
$inspectSeen = @()
try {
    $allRoots = @(Get-ChildItem 'Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root' -ErrorAction SilentlyContinue)
    $inspectSeen = @($allRoots | ForEach-Object { Get-CommonName $_.Subject } | Where-Object { Test-InterceptionName $_ } | Select-Object -Unique)
} catch { }

if ($noCa.Count -gt 0) {
    Emit ("the tool reported no_ca_bundle for " + $noCa.Count + " endpoint(s): the chain it saw did not reach a root in its own bundle")
    Emit '  the endpoints and their details are listed in section 2'
}
if ($legacySeen.Count -gt 0) {
    Emit ("Windows chains topped out at roots the tool cannot use: " + ($legacySeen -join ', '))
    if ($noCa.Count -gt 0) {
        Emit '  the tool reported no_ca_bundle in the same run: this is the explanation'
    } else {
        Emit '  but the tool reported no no_ca_bundle in this run: Windows may simply prefer a cross-signed'
        Emit '  path here, while the tool verifies through the modern root the same chain carries'
    }
}
if ($interceptionEvidence.Count -gt 0) {
    Emit ("TLS interception seen in a live chain: " + ($interceptionEvidence -join '; '))
    Emit '  the connection was not to the endpoint itself - this machine trusts the interceptor, the tool does not'
} elseif ($inspectSeen.Count -gt 0) {
    Emit ("inspection roots are installed but did not appear in the chains above: " + ($inspectSeen -join ', '))
    Emit '  if the tool reports no_ca_bundle for every DoH/DoT endpoint while plain https works, such a root'
    Emit '  may be intercepting those host names only'
}
if ($noCa.Count -eq 0 -and $legacySeen.Count -eq 0 -and $interceptionEvidence.Count -eq 0 -and $inspectSeen.Count -eq 0) {
    Emit 'nothing on this machine explains a trust failure: send the report as it is'
}
if ($target) {
    Emit ''
    Emit ("this report is about one endpoint only: " + $focusedAddress)
    Emit ("  ports " + ($Ports -join ' then ') + " were both tried: a chain Windows completes through a root the tool")
    Emit '  does not carry, or one served differently per port, is what NO CA BUNDLE for a single endpoint looks like'
}

$focusedRemoved = $false
if ($focusedDir -and (Test-Path -LiteralPath $focusedDir)) {
    try { Remove-Item -LiteralPath $focusedDir -Recurse -Force; $focusedRemoved = $true } catch { }
}
if ($focusedDir) {
    if ($focusedRemoved) {
        Emit '(the single-endpoint config this run used was temporary and is gone)'
    } else {
        Emit ("(the single-endpoint config is still at " + $focusedDir + " - delete it when done)")
    }
}

Emit ''
Emit 'Send this file to whoever asked for it.'
if (-not $toolPath) {
    Emit '(no detector was found on this machine, so sections 2 and 3 are missing; the rest stands on its own)'
}

# -- Write -------------------------------------------------------------------

$written = $false
try {
    # UTF-8 with a BOM: the tool answers in Russian on a Russian machine, and
    # this file is read in Notepad, sent through a chat and opened by someone
    # else's editor -- a BOM is what keeps the non-ASCII lines readable there.
    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllLines($reportPath, [string[]]$script:Lines, $utf8Bom)
    $written = $true
} catch {
    try {
        Set-Content -LiteralPath $reportPath -Value $script:Lines -Encoding UTF8
        $written = $true
    } catch {
        Write-Host ''
        Write-Host ("could not write " + $reportPath + ": " + $_.Exception.Message)
        Write-Host 'copy the text above from this window and send that instead'
    }
}
if ($written) {
    $size = 0
    try { $size = (Get-Item -LiteralPath $reportPath).Length } catch { }
    Write-Host ''
    Write-Host 'done. send this file back:'
    Write-Host ('  ' + $reportPath + '  (' + [math]::Round($size / 1kb, 1) + ' KB)')
    Write-Host 'it contains machine and certificate names, the external IP and DNS settings -'
    Write-Host 'nothing else, and no credentials.'
}
