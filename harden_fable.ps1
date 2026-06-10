<#
================================================================================
 Harden-WindowsSandbox.ps1
================================================================================
 PURPOSE
   One-shot, self-contained, idempotent hardening script for a running
   Microsoft Windows Sandbox instance whose SOLE purpose is browsing the
   public internet with Microsoft Edge over HTTPS. Everything not required
   for that single task is treated as attack surface and removed/disabled.

 LAYERING / ASSUMPTIONS
   * The PRIMARY isolation layer is the host-side .wsb configuration:
       - vGPU:                       Disable   (kills GPU driver escape surface)
       - MappedFolders:              none      (no host filesystem exposure)
       - ClipboardRedirection:       Disable
       - PrinterRedirection:         Disable
       - AudioInput / VideoInput:    Disable
       - ProtectedClient:            Enable    (runs RDP/VAIL stack in AppContainer)
       - Networking:                 Default   (NAT; required for browsing)
     This script is the SECONDARY, in-guest defense-in-depth layer. It cannot
     substitute for the .wsb settings above.
   * The sandbox user (WDAGUtilityAccount) is a local Administrator. Nothing
     done in-guest is therefore a hard security *boundary* against code that
     already runs as that admin; the goal is to deny easy wins: shrink the
     reachable attack surface pre-exploit, and starve post-exploit tooling,
     C2, lateral movement and persistence (persistence is mostly moot anyway,
     since the sandbox is ephemeral and resets on close).
   * The sandbox is ephemeral. "Idempotent / safe to re-run" is interpreted
     as: re-running causes no errors and no duplicated state. NOTE: the very
     last step places future PowerShell processes into Constrained Language
     Mode; to re-run this script in the SAME session you would have to remove
     the __PSLockdownPolicy machine env var first (or just restart the
     sandbox, which resets everything).
   * KNOWN LIMITATION: Windows Sandbox ships WITHOUT Microsoft Defender AV
     running in the guest by default (by design - the host's Defender is
     considered authoritative). The Defender/ASR section below detects this
     and logs SKIPPED rather than failing. If your image does have Defender
     (e.g. newer builds / custom images), it will be maximized.
   * No external downloads, no dependencies. Pure in-box cmdlets + registry.

 USAGE
   Run elevated (the sandbox user is admin by default) inside the sandbox:
     powershell.exe -ExecutionPolicy Bypass -File .\Harden-WindowsSandbox.ps1
================================================================================
#>

#Requires -RunAsAdministrator

# ------------------------------------------------------------------------------
# 0. LOGGING & RESULT-TRACKING SCAFFOLDING
#    - Timestamped transcript written inside the sandbox.
#    - Every hardening unit runs through Invoke-Hardening, which gives each
#      logical section its own try/catch so one failure never aborts the rest,
#      and records Applied / Skipped / Failed for the final summary.
# ------------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$LogDir   = 'C:\HardenLogs'
$null     = New-Item -Path $LogDir -ItemType Directory -Force
$Stamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogFile  = Join-Path $LogDir "Harden-WindowsSandbox-$Stamp.log"
try { Start-Transcript -Path $LogFile -Force | Out-Null } catch { Write-Warning "Transcript could not start: $_" }

$script:Results = New-Object System.Collections.Generic.List[object]

function Invoke-Hardening {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    Write-Host "==> $Name" -ForegroundColor Cyan
    try {
        $out = & $Action
        if ($out -eq 'SKIPPED') {
            $script:Results.Add([pscustomobject]@{ Section = $Name; Status = 'SKIPPED'; Detail = 'Not applicable in this image' })
            Write-Host "    SKIPPED" -ForegroundColor Yellow
        } else {
            $script:Results.Add([pscustomobject]@{ Section = $Name; Status = 'APPLIED'; Detail = '' })
            Write-Host "    OK" -ForegroundColor Green
        }
    } catch {
        $script:Results.Add([pscustomobject]@{ Section = $Name; Status = 'FAILED'; Detail = $_.Exception.Message })
        Write-Host "    FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Helper: create/overwrite a registry value, creating the key path if needed.
function Set-RegValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('DWord','QWord','String','ExpandString','MultiString','Binary')]
        [string]$Type = 'DWord'
    )
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

# Resolve the Edge binary once. If Edge is missing we still harden everything
# else, but the Edge firewall allow-rule and policies are pointless without it.
$EdgeExe = @(
    "$Env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe",
    "$Env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1


# ==============================================================================
# 1. SERVICES - disable everything not needed to render HTTPS pages in Edge.
#    WHY: every running service is reachable code (local RPC/ALPC surface at
#    minimum, network surface at worst). Killing them removes exploit targets,
#    lateral-movement listeners (SMB/RDP/WinRM), and common C2/persistence
#    helpers (BITS-style transfer via WebClient, spooler bugs, etc.).
# ==============================================================================
Invoke-Hardening 'Services: stop & disable non-essential services' {
    $services = @(
        'Spooler',          # Print Spooler - PrintNightmare-class bugs; no printing in sandbox
        'RemoteRegistry',   # Remote registry access - pure lateral-movement surface
        'TermService',      # Remote Desktop - inbound remote control surface
        'UmRdpService',     # RDP device redirection
        'SessionEnv',       # RDP configuration
        'WinRM',            # PowerShell remoting / WSMan - classic lateral movement
        'sshd',             # OpenSSH server, if present
        'ssh-agent',        # SSH key agent, if present
        'SSDPSRV',          # SSDP discovery (UPnP) - multicast noise + discovery surface
        'upnphost',         # UPnP device host
        'TapiSrv',          # Telephony - not needed for browsing
        'Fax',              # Fax - not needed
        'LanmanServer',     # SMB SERVER - kills inbound 445/139 file-share surface entirely
        'LanmanWorkstation',# SMB CLIENT - Edge does not need SMB; kills outbound NTLM-leak
                            #   via file://UNC tricks. TRADE-OFF: breaks any \\share access
                            #   (none is intended in this sandbox).
        'RpcLocator',       # Legacy RPC locator - dead weight
        'WebClient',        # WebDAV client - classic UNC/NTLM-leak + payload-fetch vector
        'WSearch',          # Windows Search/indexer - OPTIONAL; not needed for browsing
        'RemoteAccess',     # Routing & RAS
        'lmhosts',          # TCP/IP NetBIOS Helper - NetBIOS support code
        'p2psvc','p2pimsvc','PNRPsvc','PNRPAutoReg', # Peer networking stack
        'FDResPub','fdPHost',                        # Network discovery/publication
        'icssvc',           # Mobile hotspot
        'PhoneSvc',         # Phone service
        'RetailDemo',       # Retail demo content
        'MapsBroker',       # Downloaded maps manager - background egress
        'lfsvc',            # Geolocation
        'WerSvc',           # Windows Error Reporting - background egress, info leak
        'DiagTrack',        # Connected User Experiences & Telemetry - background egress
        'dmwappushservice', # WAP push telemetry routing
        'SCardSvr',         # Smart card - unused
        'SharedAccess',     # Internet Connection Sharing
        'XblAuthManager','XblGameSave','XboxGipSvc','XboxNetApiSvc' # Xbox stack
    )
    foreach ($svc in $services) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($null -eq $s) { continue }                              # absent in this image -> nothing to do
        try { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue } catch {}
        try { Set-Service  -Name $svc -StartupType Disabled -ErrorAction Stop }
        catch {
            # Some services protect their Start value from SCM; fall back to registry.
            Set-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name 'Start' -Value 4
        }
    }
}

# ==============================================================================
# 2. SMB PROTOCOL - belt-and-braces on top of disabling the services above.
#    WHY: SMB is the #1 lateral-movement and guest-network-probing protocol.
#    Disabling it server-side (and the SMB1 client bits) removes EternalBlue-
#    class surface even if a service were somehow re-enabled.
# ==============================================================================
Invoke-Hardening 'SMB: disable SMBv1/v2/v3 server side + SMB1 client feature' {
    # Server side: refuse to speak SMB at all (LanmanServer is also disabled above).
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force -ErrorAction SilentlyContinue
    # SMB1 client/feature removal (best effort; DISM features can be limited in Sandbox).
    foreach ($f in 'SMB1Protocol','SMB1Protocol-Client','SMB1Protocol-Server') {
        try { Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction Stop | Out-Null } catch {}
    }
    # Insecure guest auth off (defensive default even with the client disabled).
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
                 -Name 'AllowInsecureGuestAuth' -Value 0
}

# ==============================================================================
# 3. NAME-RESOLUTION POISONING SURFACE: NetBIOS, LLMNR, mDNS, WebDAV
#    WHY: LLMNR/NBT-NS/mDNS answer-spoofing is the classic way an attacker on
#    the same network segment harvests NTLM hashes or redirects traffic. Web
#    browsing needs only unicast DNS, so all multicast resolution is disabled.
# ==============================================================================
Invoke-Hardening 'Name resolution: disable NetBIOS over TCP/IP, LLMNR, mDNS' {
    # NetBIOS over TCP/IP -> off on every interface (NetbiosOptions = 2)
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue |
        ForEach-Object { Set-RegValue -Path $_.PSPath -Name 'NetbiosOptions' -Value 2 }
    # LLMNR off via DNS Client policy
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0
    # mDNS off in the DNS cache service
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'EnableMDNS' -Value 0
    # Disable Smart Multi-Homed Name Resolution (prevents parallel leaky queries)
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'DisableSmartNameResolution' -Value 1
}

# ==============================================================================
# 4. DNS - point at a malware-filtering resolver. *** TUNABLE ***
#    WHY: a filtering resolver (Quad9 / Cloudflare-for-Families) blocks known
#    malware/C2 domains at resolution time - cheap, broad drive-by mitigation.
#    Set $UseFilteringDns = $false to keep the NAT-provided resolver instead.
# ==============================================================================
Invoke-Hardening 'DNS: switch to malware-filtering resolver (Quad9)' {
    $UseFilteringDns = $true
    $Resolvers       = @('9.9.9.9','149.112.112.112')      # Quad9 (malware-blocking)
    # Alternative: @('1.1.1.2','1.0.0.2')                  # Cloudflare malware-filtering
    if (-not $UseFilteringDns) { return 'SKIPPED' }
    Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
        Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses $Resolvers
    }
    Clear-DnsClientCache
}

# ==============================================================================
# 5. WINDOWS FIREWALL - block ALL inbound; outbound default-DENY with a
#    minimal allow-list for browsing.
#    WHY: outbound default-deny is the single biggest post-exploit chokepoint:
#    a payload that does run cannot reach C2 unless it injects into Edge or a
#    permitted svchost service. Inbound hard-block removes every remotely
#    reachable listener regardless of service state.
#
#    ALLOWED OUTBOUND (and nothing else):
#      - DNS  (svchost/Dnscache, TCP+UDP 53)
#      - DHCP (svchost/Dhcp, UDP 67/68)              - sandbox NAT needs this
#      - Edge (msedge.exe) TCP 80/443 + UDP 443      - UDP 443 = QUIC/HTTP3.
#        TRADE-OFF: TCP 80 allows plain HTTP and CRL fetches by Edge itself;
#        remove it for HTTPS-only at the cost of some redirect breakage.
#      - CryptSvc TCP 80/443                          - CRL/OCSP revocation checks
#      - NlaSvc  TCP 80                               - NCSI connectivity probe;
#        purely cosmetic ("no internet" icon) - remove if you prefer.
#      - Defender service (WinDefend) TCP 443         - cloud-delivered protection
#        (only matters if Defender exists in the image; harmless otherwise).
#    NOT allowed: Edge updater (sandbox is ephemeral - updates are pointless),
#    Windows Update, time sync, everything else.
# ==============================================================================
Invoke-Hardening 'Firewall: inbound block-all, outbound default-deny + allow-list' {
    $Group = 'WSB-Hardening'
    # Idempotency: remove any rules from a previous run before re-creating.
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule

    # Profile posture. AllowInboundRules:False ignores even pre-existing inbound
    # allow rules => truly nothing inbound. NotifyOnListen off = no popups.
    Set-NetFirewallProfile -All -Enabled True `
        -DefaultInboundAction Block -DefaultOutboundAction Block `
        -AllowInboundRules False -NotifyOnListen False -LogBlocked True `
        -LogFileName "$LogDir\pfirewall.log" -LogMaxSizeKilobytes 8192

    # --- Outbound allow-list -------------------------------------------------
    New-NetFirewallRule -Group $Group -DisplayName 'WSB Allow DNS (Dnscache)' `
        -Direction Outbound -Action Allow -Service Dnscache `
        -Protocol UDP -RemotePort 53 | Out-Null
    New-NetFirewallRule -Group $Group -DisplayName 'WSB Allow DNS-TCP (Dnscache)' `
        -Direction Outbound -Action Allow -Service Dnscache `
        -Protocol TCP -RemotePort 53 | Out-Null
    New-NetFirewallRule -Group $Group -DisplayName 'WSB Allow DHCP client' `
        -Direction Outbound -Action Allow -Service Dhcp `
        -Protocol UDP -LocalPort 68 -RemotePort 67 | Out-Null
    New-NetFirewallRule -Group $Group -DisplayName 'WSB Allow CRL/OCSP (CryptSvc)' `
        -Direction Outbound -Action Allow -Service CryptSvc `
        -Protocol TCP -RemotePort 80,443 | Out-Null
    New-NetFirewallRule -Group $Group -DisplayName 'WSB Allow NCSI probe (NlaSvc)' `
        -Direction Outbound -Action Allow -Service NlaSvc `
        -Protocol TCP -RemotePort 80 | Out-Null
    New-NetFirewallRule -Group $Group -DisplayName 'WSB Allow Defender cloud (WinDefend)' `
        -Direction Outbound -Action Allow -Service WinDefend `
        -Protocol TCP -RemotePort 443 -ErrorAction SilentlyContinue | Out-Null

    if ($EdgeExe) {
        New-NetFirewallRule -Group $Group -DisplayName 'WSB Allow Edge HTTP/HTTPS' `
            -Direction Outbound -Action Allow -Program $EdgeExe `
            -Protocol TCP -RemotePort 80,443 | Out-Null
        New-NetFirewallRule -Group $Group -DisplayName 'WSB Allow Edge QUIC' `
            -Direction Outbound -Action Allow -Program $EdgeExe `
            -Protocol UDP -RemotePort 443 | Out-Null
    }

    # --- Explicit hard BLOCKS ------------------------------------------------
    # Default-deny already covers these, but explicit block rules win over any
    # built-in/local allow rule (block > allow in WFP), making the posture
    # robust even if something re-enables a stock allow rule.
    $blockPorts = @(
        @{ N='SMB';      P='TCP'; Ports=@(139,445) },
        @{ N='RPC';      P='TCP'; Ports=@(135) },
        @{ N='NetBIOS';  P='UDP'; Ports=@(137,138) },
        @{ N='LLMNR';    P='UDP'; Ports=@(5355) },
        @{ N='mDNS';     P='UDP'; Ports=@(5353) },
        @{ N='RDP';      P='TCP'; Ports=@(3389) },
        @{ N='WinRM';    P='TCP'; Ports=@(5985,5986) },
        @{ N='SSH';      P='TCP'; Ports=@(22) }
    )
    foreach ($b in $blockPorts) {
        foreach ($dir in 'Inbound','Outbound') {
            New-NetFirewallRule -Group $Group -DisplayName "WSB Block $($b.N) $dir" `
                -Direction $dir -Action Block -Protocol $b.P -RemotePort $b.Ports | Out-Null
        }
    }

    # Deny network egress to script hosts / LOLBins even if they execute:
    # a dropped payload running via these binaries cannot phone home.
    $noNetBins = @(
        "$Env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe",
        "$Env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
        "$Env:SystemRoot\System32\cmd.exe",
        "$Env:SystemRoot\System32\wscript.exe",
        "$Env:SystemRoot\System32\cscript.exe",
        "$Env:SystemRoot\System32\mshta.exe",
        "$Env:SystemRoot\System32\certutil.exe",
        "$Env:SystemRoot\System32\bitsadmin.exe",
        "$Env:SystemRoot\System32\curl.exe",
        "$Env:SystemRoot\System32\rundll32.exe",
        "$Env:SystemRoot\System32\regsvr32.exe"
    )
    foreach ($bin in ($noNetBins | Where-Object { Test-Path $_ })) {
        New-NetFirewallRule -Group $Group `
            -DisplayName "WSB Block egress: $([IO.Path]::GetFileName($bin))" `
            -Direction Outbound -Action Block -Program $bin | Out-Null
    }
}

# ==============================================================================
# 6. SCRIPTING & EXECUTION LOCKDOWN
#    WHY: drive-by payloads overwhelmingly stage through script hosts and
#    LOLBins. None of these are needed to *browse*. NOTE: because the sandbox
#    user is admin, these are tamper-resistant speed bumps, not boundaries -
#    but they break every off-the-shelf stager that assumes they work.
# ==============================================================================
Invoke-Hardening 'Scripting: disable Windows Script Host (wscript/cscript)' {
    # Machine-wide WSH kill switch: .vbs/.js/.wsf files will refuse to run.
    Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name 'Enabled' -Value 0
}

Invoke-Hardening 'Scripting: disable PowerShell v2 engine' {
    # PSv2 lacks AMSI, script-block logging and CLM enforcement -> classic
    # downgrade-attack target. Remove the optional feature if present.
    $found = $false
    foreach ($f in 'MicrosoftWindowsPowerShellV2Root','MicrosoftWindowsPowerShellV2') {
        $feat = Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction SilentlyContinue
        if ($feat -and $feat.State -eq 'Enabled') {
            Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart | Out-Null
            $found = $true
        }
    }
    if (-not $found) { return 'SKIPPED' }   # already absent in this image
}

Invoke-Hardening 'Scripting: restrict cmd.exe for the interactive user' {
    # DisableCMD=1 blocks both interactive cmd AND .bat/.cmd scripts (value 2
    # would still allow batch files). TRADE-OFF: some legitimate tooling uses
    # cmd /c; nothing required for Edge browsing does. This is per-user (HKCU)
    # policy, so the running PowerShell session is unaffected and the session
    # cannot be bricked by it.
    Set-RegValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\System' -Name 'DisableCMD' -Value 1
}

Invoke-Hardening 'Scripting: neuter common LOLBins via IFEO debugger redirect' {
    # Image File Execution Options "Debugger" pointing at a non-existent stub
    # makes every launch of these binaries fail instantly. They are favourite
    # proxy-execution / download-cradle binaries and none are needed to browse.
    # TRADE-OFFS:
    #  - certutil: blocks manual cert manipulation (CryptSvc CRL checks are a
    #    service, NOT certutil.exe, so revocation checking still works).
    #  - regsvr32: rare legitimate in-session COM registration would fail -
    #    acceptable in a browse-only disposable VM.
    #  - This is admin-removable; defense-in-depth, not a boundary.
    $lolbins = @(
        'mshta.exe','wscript.exe','cscript.exe','wmic.exe','cmstp.exe',
        'msbuild.exe','installutil.exe','regsvcs.exe','regasm.exe',
        'mavinject.exe','bitsadmin.exe','certutil.exe','certreq.exe',
        'regsvr32.exe','hh.exe','ftp.exe','forfiles.exe','scriptrunner.exe',
        'runscripthelper.exe','presentationhost.exe'
    )
    $stub = 'C:\Windows\System32\BlockedByHardeningPolicy.exe'   # intentionally non-existent
    foreach ($bin in $lolbins) {
        Set-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$bin" `
                     -Name 'Debugger' -Value $stub -Type String
    }
}

Invoke-Hardening 'AutoRun/AutoPlay: disable everywhere' {
    # Stops removable-media / mounted-ISO auto-execution tricks (malicious
    # downloads that mount as ISO are a common SmartScreen bypass).
    foreach ($hive in 'HKLM:','HKCU:') {
        Set-RegValue -Path "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveTypeAutoRun' -Value 255
        Set-RegValue -Path "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoAutorun' -Value 1
    }
    Set-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' -Name 'DisableAutoplay' -Value 1
}

# ==============================================================================
# 7. MICROSOFT DEFENDER - keep ENABLED and maximize, IF present.
#    WHY: real-time + cloud + PUA + Network Protection + all ASR rules in
#    Block mode is the strongest in-box anti-exploit/anti-stager package.
#    CAVEAT (logged as SKIPPED if hit): stock Windows Sandbox does NOT run
#    Defender in the guest; the host's Defender covers sandbox-visible I/O.
# ==============================================================================
Invoke-Hardening 'Defender: maximize real-time/cloud/PUA/Network Protection + ASR' {
    $wd = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    if (-not $wd -or $wd.Status -ne 'Running') { return 'SKIPPED' }   # not in this image

    Set-MpPreference -DisableRealtimeMonitoring  $false
    Set-MpPreference -DisableBehaviorMonitoring  $false
    Set-MpPreference -DisableIOAVProtection      $false
    Set-MpPreference -DisableScriptScanning      $false
    Set-MpPreference -MAPSReporting              Advanced     # cloud-delivered protection
    Set-MpPreference -SubmitSamplesConsent       SendSafeSamples
    Set-MpPreference -PUAProtection              Enabled      # block PUA/PUP
    Set-MpPreference -EnableNetworkProtection    Enabled      # block mode: blocks C2/phish domains OS-wide
    Set-MpPreference -CloudBlockLevel            High
    Set-MpPreference -CloudExtendedTimeout       50

    # All published ASR rules -> Block (1). Office/Adobe rules are harmless
    # no-ops when those apps are absent.
    $asr = @(
        '56a863a9-875e-4185-98a7-b882c64b5ce5', # Abuse of exploited vulnerable signed drivers
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c', # Adobe Reader child processes
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a', # Office apps creating child processes
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', # lsass credential stealing
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', # Executable content from email
        '01443614-cd74-433a-b99e-2ecdc07bfc25', # Executables unless prevalence/age/trust criteria
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc', # Obfuscated scripts
        'd3e037e1-3eb8-44c8-a917-57927947596d', # JS/VBS launching downloaded executable content
        '3b576869-a4ec-4529-8536-b80a7769e899', # Office creating executable content
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84', # Office injecting into other processes
        '26190899-1602-49e8-8b27-eb1d0a1ce869', # Office comms apps creating child processes
        'e6db77e5-3df2-4cf1-b95a-636979351e5b', # Persistence through WMI event subscription
        'd1e49aac-8f56-4280-b9ba-993a6d77406c', # Process creations from PSExec/WMI
        '33ddedf1-c6e0-47cb-833e-de6133960387', # Rebooting machine in Safe Mode
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4', # Untrusted/unsigned processes from USB
        'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb', # Copied/impersonated system tools
        'a8f5898e-1dc8-49a9-9878-85004b8a61e6', # Webshell creation for servers
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b', # Win32 API calls from Office macros
        'c1db55ab-c21a-4637-bb3f-a12568109d35'  # Advanced ransomware protection
    )
    foreach ($id in $asr) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled
    }
}

# ==============================================================================
# 8. SYSTEM-WIDE EXPLOIT MITIGATIONS (Set-ProcessMitigation)
#    WHY: raises the cost of memory-corruption exploitation for EVERY process:
#    DEP (no executing data pages), SEHOP (SEH overwrite protection), bottom-up
#    + high-entropy ASLR (address randomization), CFG (indirect-call integrity).
#    NOTE: ForceRelocateImages (mandatory ASLR) is deliberately NOT forced
#    system-wide - it can crash old non-/DYNAMICBASE binaries; the protections
#    below are the safe-everywhere set. Edge additionally ships its own
#    hardened sandbox + CIG/ACG internally.
# ==============================================================================
Invoke-Hardening 'Exploit protection: system-wide DEP/SEHOP/ASLR/CFG' {
    Set-ProcessMitigation -System -Enable DEP,SEHOP,BottomUp,HighEntropy,CFG
}

# ==============================================================================
# 9. MICROSOFT EDGE POLICIES (HKLM\SOFTWARE\Policies\Microsoft\Edge)
#    WHY: Enhanced Security Mode (strict) disables the JS JIT and enables extra
#    OS mitigations inside renderers - the single most effective drive-by
#    mitigation Edge offers (cost: some heavy web apps get slower).
#    Everything an attacker could leverage (extensions, devtools, downloads,
#    protocol handlers, stored credentials) is switched off.
# ==============================================================================
Invoke-Hardening 'Edge: enforce hardened browsing policy set' {
    if (-not $EdgeExe) { return 'SKIPPED' }
    $E = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'

    # --- Enhanced Security Mode: 2 = Strict on ALL sites (JIT off everywhere).
    Set-RegValue -Path $E -Name 'EnhanceSecurityMode' -Value 2

    # --- SmartScreen: on, unbypassable, including for downloads; PUA blocking.
    Set-RegValue -Path $E -Name 'SmartScreenEnabled' -Value 1
    Set-RegValue -Path $E -Name 'SmartScreenPuaEnabled' -Value 1
    Set-RegValue -Path $E -Name 'PreventSmartScreenPromptOverride' -Value 1
    Set-RegValue -Path $E -Name 'PreventSmartScreenPromptOverrideForFiles' -Value 1
    Set-RegValue -Path $E -Name 'SmartScreenForTrustedDownloadsEnabled' -Value 1

    # --- Downloads: 3 = BLOCK ALL downloads. Safest for a browse-only box.
    # TRADE-OFF: set to 1 (block dangerous types) if you must download files;
    # if you do, also set DefaultDownloadDirectory below to confine them.
    Set-RegValue -Path $E -Name 'DownloadRestrictions' -Value 3
    Set-RegValue -Path $E -Name 'DefaultDownloadDirectory' -Value 'C:\SandboxDownloads' -Type String
    $null = New-Item -Path 'C:\SandboxDownloads' -ItemType Directory -Force

    # --- Extensions: hard-block everything (no sideload, no store installs).
    Set-RegValue -Path "$E\ExtensionInstallBlocklist" -Name '1' -Value '*' -Type String

    # --- Developer tools off (2 = disallowed everywhere): removes an easy
    #     in-renderer scripting/injection console for both users and pages.
    Set-RegValue -Path $E -Name 'DeveloperToolsAvailability' -Value 2

    # --- No credential storage / autofill: nothing for an infostealer to steal.
    Set-RegValue -Path $E -Name 'PasswordManagerEnabled' -Value 0
    Set-RegValue -Path $E -Name 'AutofillAddressEnabled' -Value 0
    Set-RegValue -Path $E -Name 'AutofillCreditCardEnabled' -Value 0
    Set-RegValue -Path $E -Name 'ImportOnEachLaunch' -Value 0

    # --- External protocol / local-scheme launches: block the browser-to-OS
    #     handoff tricks (ms-msdt:, search-ms:, file:, etc.).
    Set-RegValue -Path $E -Name 'ExternalProtocolDialogShowAlwaysOpenCheckbox' -Value 0
    $i = 1
    foreach ($u in 'file://*','ftp://*') {
        Set-RegValue -Path "$E\URLBlocklist" -Name "$i" -Value $u -Type String; $i++
    }

    # --- Transport & isolation hygiene
    Set-RegValue -Path $E -Name 'SSLVersionMin' -Value 'tls1.2' -Type String
    Set-RegValue -Path $E -Name 'SitePerProcess' -Value 1            # full site isolation
    Set-RegValue -Path $E -Name 'BasicAuthOverHttpEnabled' -Value 0  # no creds over plaintext
    Set-RegValue -Path $E -Name 'InsecurePrivateNetworkRequestsAllowed' -Value 0  # web pages cannot probe RFC1918
    Set-RegValue -Path $E -Name 'EnableOnlineRevocationChecks' -Value 1
    Set-RegValue -Path $E -Name 'TyposquattingCheckerEnabled' -Value 1

    # --- Identity/sync/background noise off (less egress, nothing to exfil)
    Set-RegValue -Path $E -Name 'BrowserSignin' -Value 0
    Set-RegValue -Path $E -Name 'SyncDisabled' -Value 1
    Set-RegValue -Path $E -Name 'BackgroundModeEnabled' -Value 0
    Set-RegValue -Path $E -Name 'StartupBoostEnabled' -Value 0
    Set-RegValue -Path $E -Name 'NetworkPredictionOptions' -Value 2   # no speculative prefetch
    Set-RegValue -Path $E -Name 'PromotionalTabsEnabled' -Value 0
    Set-RegValue -Path $E -Name 'PersonalizationReportingEnabled' -Value 0
    Set-RegValue -Path $E -Name 'DiagnosticData' -Value 0
}

# ==============================================================================
# 10. TELEMETRY / NOISE REDUCTION
#     WHY: every background phone-home is (a) egress noise that hides real C2
#     in firewall logs and (b) code paths you don't need. Cosmetic privacy is
#     a side benefit; the security goal is a QUIET baseline.
# ==============================================================================
Invoke-Hardening 'Telemetry: Cortana, web search, consumer features, diag data' {
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 0
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -Value 0
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWeb' -Value 0
    Set-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'BingSearchEnabled' -Value 0
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableSoftLanding' -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Value 0
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -Name 'DisabledByGroupPolicy' -Value 1
    # Error reporting (service already disabled; policy makes it explicit)
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Value 1
}

Invoke-Hardening 'Scheduled tasks: disable outbound/telemetry tasks' {
    $tasks = @(
        '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
        '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
        '\Microsoft\Windows\Application Experience\StartupAppTask',
        '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
        '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
        '\Microsoft\Windows\Autochk\Proxy',
        '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
        '\Microsoft\Windows\Maps\MapsUpdateTask',
        '\Microsoft\Windows\Maps\MapsToastTask',
        '\Microsoft\Windows\Windows Error Reporting\QueueReporting',
        '\Microsoft\Windows\Feedback\Siuf\DmClient',
        '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload',
        '\MicrosoftEdgeUpdateTaskMachineCore',
        '\MicrosoftEdgeUpdateTaskMachineUA'
    )
    foreach ($t in $tasks) {
        $path = Split-Path $t; $name = Split-Path $t -Leaf
        $task = Get-ScheduledTask -TaskPath "$path\" -TaskName $name -ErrorAction SilentlyContinue
        if ($task) { $task | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null }
    }
}

# ==============================================================================
# 11. POWERSHELL CONSTRAINED LANGUAGE MODE - applied LAST.
#     WHY: CLM strips Add-Type, COM, .NET method invocation, etc. from any
#     NEW PowerShell process, breaking the vast majority of PS-based stagers
#     and post-exploitation frameworks.
#     HONEST CAVEATS:
#       * __PSLockdownPolicy is the documented-adjacent env-var mechanism; a
#         local admin (which a successful exploit may be) can unset it. It is
#         a tamper-resistant speed bump here, not a boundary - the real
#         boundary remains the Hyper-V isolation of the sandbox itself.
#       * Done LAST because this very script needs Full Language. New PS
#         processes started after this point are constrained. To re-run the
#         script in the SAME session, remove the env var first - or simply
#         restart the sandbox (everything resets anyway).
# ==============================================================================
Invoke-Hardening 'PowerShell: Constrained Language Mode for new sessions' {
    [Environment]::SetEnvironmentVariable('__PSLockdownPolicy','4','Machine')
}


# ------------------------------------------------------------------------------
# 12. VERIFICATION - sanity checks that browsing prerequisites still stand.
#     (Does not generate traffic by itself beyond one DNS query.)
# ------------------------------------------------------------------------------
Invoke-Hardening 'Verify: Edge present, DNS resolves, firewall allows 443 for Edge' {
    if (-not $EdgeExe) { throw 'msedge.exe not found - browsing target missing' }
    $dns = Resolve-DnsName 'www.msftconnecttest.com' -Type A -ErrorAction Stop
    if (-not $dns) { throw 'DNS resolution failed' }
    $rule = Get-NetFirewallRule -DisplayName 'WSB Allow Edge HTTP/HTTPS' -ErrorAction Stop
    if ($rule.Enabled -ne 'True') { throw 'Edge outbound allow rule is not enabled' }
}


# ------------------------------------------------------------------------------
# FINAL SUMMARY
# ------------------------------------------------------------------------------
Write-Host ''
Write-Host '==================== HARDENING SUMMARY ====================' -ForegroundColor White
$Results | Format-Table -AutoSize Section, Status, Detail | Out-String | Write-Host

$applied = @($Results | Where-Object Status -eq 'APPLIED').Count
$skipped = @($Results | Where-Object Status -eq 'SKIPPED').Count
$failed  = @($Results | Where-Object Status -eq 'FAILED').Count

Write-Host ("APPLIED: {0}   SKIPPED: {1}   FAILED: {2}" -f $applied, $skipped, $failed) -ForegroundColor White
Write-Host "Full transcript: $LogFile"
Write-Host "Firewall drop log: $LogDir\pfirewall.log"
if ($failed -gt 0) {
    Write-Host 'One or more sections FAILED - review the transcript before trusting this posture.' -ForegroundColor Red
}

# ------------------------------------------------------------------------------
# COMPLETION MARKER - drop success.txt on the desktop as a visual "done" signal.
# Only written when ZERO sections failed (SKIPPED is fine - it means the item
# was not applicable in this image, e.g. Defender absent in stock Sandbox).
# If sections failed, any stale marker from a previous run is removed instead,
# so the file's presence is always a truthful signal. Idempotent: overwrites.
# ------------------------------------------------------------------------------
try {
    $Desktop    = [Environment]::GetFolderPath('Desktop')
    $MarkerFile = Join-Path $Desktop 'success.txt'
    if ($failed -eq 0) {
        @(
            "Windows Sandbox hardening completed successfully."
            "Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            "Applied   : $applied"
            "Skipped   : $skipped (not applicable in this image)"
            "Failed    : 0"
            "Log file  : $LogFile"
        ) | Set-Content -Path $MarkerFile -Encoding UTF8 -Force
        Write-Host "Success marker written: $MarkerFile" -ForegroundColor Green
    } else {
        Remove-Item -Path $MarkerFile -Force -ErrorAction SilentlyContinue
        Write-Host 'No success marker written (failures occurred); any stale marker removed.' -ForegroundColor Yellow
    }
} catch {
    Write-Host "Could not write success marker: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host 'Reminder: host-side .wsb config (no vGPU, no mapped folders, no redirection,' -ForegroundColor DarkGray
Write-Host 'ProtectedClient on) is the primary isolation layer; this script is layer two.' -ForegroundColor DarkGray

try { Stop-Transcript | Out-Null } catch {}