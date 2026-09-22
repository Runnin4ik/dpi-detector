<#
.SYNOPSIS
  Collects the DNS/TLS facts behind a test-1 report on a Windows machine.

.DESCRIPTION
  Built for the case where test 1 (DNS availability) shows an endpoint failure
  such as NO CA BUNDLE for DoH/DoT. One run gathers, into a single text file:

    1. host, PowerShell and process context;
    2. dpi-detector --version, and whether a config.yml was picked up;
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

  It changes nothing and needs no admin rights.

.PARAMETER Tool
  Path to dpi-detector.exe. When omitted, the script looks in PATH, next to
  itself, and in the current directory; if it finds none, sections 2 and 3 are
  skipped and the rest still runs.

.PARAMETER OutDir
  Where the report is written. Default: the Desktop.

.PARAMETER Hosts
  DoH/DoT endpoints to inspect. Default: dns.google, cloudflare-dns.com,
  dns.quad9.net, dns.adguard-dns.com, dns.sb, common.dot.dns.yandex.net.

.PARAMETER Ports
  Ports tried per host, in order. Default: 443 (DoH) then 853 (DoT).

.PARAMETER TimeoutMs
  Connect/read timeout per attempt, milliseconds. Default: 6000.

.PARAMETER SkipTests
  Do not run dpi-detector (no network probing from the tool; sections 4-7 only).

.EXAMPLE
  pwsh -NoProfile -File dns-ca-report.ps1
.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File dns-ca-report.ps1 -Tool C:\tools\dpi-detector.exe
#>
[CmdletBinding()]
param(
    [string]$Tool = '',
    [string]$OutDir = "$env:USERPROFILE\Desktop",
    [string[]]$Hosts = @(
        'dns.google', 'cloudflare-dns.com', 'dns.quad9.net',
        'dns.adguard-dns.com', 'dns.sb', 'common.dot.dns.yandex.net'
    ),
    [int[]]$Ports = @(443, 853),
    [int]$TimeoutMs = 6000,
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

# -- 0. Context ---------------------------------------------------------------

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
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

$toolPath = $Tool
if (-not $toolPath) {
    $candidates = @()
    $cmd = Get-Command 'dpi-detector.exe' -ErrorAction SilentlyContinue
    if ($cmd) { $candidates += $cmd.Source }
    if ($PSScriptRoot) { $candidates += (Join-Path $PSScriptRoot 'dpi-detector.exe') }
    $candidates += (Join-Path (Get-Location).Path 'dpi-detector.exe')
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { $toolPath = $candidate; break }
    }
}
if ($toolPath -and (Test-Path -LiteralPath $toolPath)) {
    Emit ("tool       : " + $toolPath)
    try { Emit ("version    : " + ((& $toolPath --version 2>&1 | Out-String).Trim())) }
    catch { Emit ("version    : FAILED " + $_.Exception.Message) }
} else {
    $toolPath = $null
    Emit 'tool       : not found (pass -Tool <path>; sections 3 and 4 will be skipped)'
}

$configHere = Join-Path (Get-Location).Path 'config.yml'
if (Test-Path -LiteralPath $configHere) {
    Emit ("config     : " + $configHere)
} else {
    Emit ("config     : no config.yml in " + (Get-Location).Path + " (built-in defaults are used)")
}

# -- 2. Test 1 and test 0 as the tool reports them ----------------------------

$dnsFailures = @()
if ($toolPath -and -not $SkipTests) {
    Section '2. test 1 - DNS availability (--json)'
    try {
        $json = (& $toolPath --tests 1 --json 2>&1 | Out-String)
        $payload = $json | ConvertFrom-Json
        $dns = $payload.results.dns_availability
        if ($null -eq $dns) {
            Emit 'no dns_availability block in the payload:'
            Emit $json
        } else {
            Emit ("doh " + $dns.doh_ok + "/" + $dns.doh_total + "   dot " + $dns.dot_ok + "/" + $dns.dot_total + "   udp " + $dns.udp_ok + "/" + $dns.udp_total)
            Emit ("hijacked_brands: " + (($dns.hijacked_brands | ForEach-Object { $_ }) -join ', '))
            $dnsFailures = @()
            if ($dns.PSObject.Properties.Name -contains 'failures' -and $dns.failures) {
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
        $json0 = (& $toolPath --tests 0 --json 2>&1 | Out-String)
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

foreach ($hostName in $Hosts) {
    $connected = $false
    $lastError = ''
    foreach ($port in $Ports) {
        if ($connected) { continue }
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
Emit ''
Emit 'Send this file, together with the tool output if it was skipped, to whoever asked for it.'

# -- Write -------------------------------------------------------------------

try {
    Set-Content -LiteralPath $reportPath -Value $script:Lines -Encoding UTF8
    Write-Host ''
    Write-Host ("report written: " + $reportPath)
} catch {
    Write-Host ("could not write " + $reportPath + ": " + $_.Exception.Message)
}
