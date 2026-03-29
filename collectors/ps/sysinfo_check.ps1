<#
.SYNOPSIS
    Collects system information for BlueSentinel v2.0 threat assessment.
.DESCRIPTION
    Gathers OS version, installed patches, user accounts, security settings,
    and running services. Outputs structured JSON.
.OUTPUTS
    JSON object written to stdout and cache/sysinfo_<timestamp>.json
.EXAMPLE
    .\sysinfo_check.ps1 -Verbose
#>
[CmdletBinding()]
param(
    [string]$OutputDir = "cache",
    [switch]$Verbose
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

function Get-SystemInfo {
    [CmdletBinding()]
    param()

    $info = @{}

    # OS Information
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $info.os = @{
            caption       = $os.Caption
            version       = $os.Version
            build_number  = $os.BuildNumber
            architecture  = $os.OSArchitecture
            install_date  = $os.InstallDate.ToString("o")
            last_boot     = $os.LastBootUpTime.ToString("o")
            hostname      = $env:COMPUTERNAME
            domain        = $env:USERDOMAIN
        }
    } catch {
        Write-Warning "OS info failed: $_"
        $info.os = @{ error = $_.ToString() }
    }

    # Installed Hotfixes (last 90 days)
    try {
        $cutoff = (Get-Date).AddDays(-90)
        $hotfixes = Get-HotFix | Where-Object { $_.InstalledOn -gt $cutoff } |
            Select-Object HotFixID, Description, InstalledOn, InstalledBy |
            ForEach-Object {
                @{
                    hotfix_id    = $_.HotFixID
                    description  = $_.Description
                    installed_on = if ($_.InstalledOn) { $_.InstalledOn.ToString("o") } else { "Unknown" }
                    installed_by = $_.InstalledBy
                }
            }
        $info.recent_hotfixes = @($hotfixes)
    } catch {
        Write-Warning "Hotfix collection failed: $_"
        $info.recent_hotfixes = @()
    }

    # Local User Accounts
    try {
        $users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordExpires |
            ForEach-Object {
                @{
                    name               = $_.Name
                    enabled            = $_.Enabled
                    last_logon         = if ($_.LastLogon) { $_.LastLogon.ToString("o") } else { $null }
                    password_required  = $_.PasswordRequired
                    password_expires   = $_.PasswordExpires
                }
            }
        $info.local_users = @($users)
    } catch {
        Write-Warning "Local users failed: $_"
        $info.local_users = @()
    }

    # Local Administrators
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
            ForEach-Object { @{ name = $_.Name; principal_source = $_.PrincipalSource.ToString() } }
        $info.local_admins = @($admins)
    } catch {
        Write-Warning "Admin group failed: $_"
        $info.local_admins = @()
    }

    # Running Services (non-Microsoft, non-default)
    try {
        $services = Get-CimInstance -ClassName Win32_Service |
            Where-Object { $_.State -eq "Running" } |
            ForEach-Object {
                @{
                    name         = $_.Name
                    display_name = $_.DisplayName
                    state        = $_.State
                    start_mode   = $_.StartMode
                    path_name    = $_.PathName
                    process_id   = $_.ProcessId
                }
            }
        $info.running_services = @($services)
    } catch {
        Write-Warning "Services failed: $_"
        $info.running_services = @()
    }

    # Windows Defender Status
    try {
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        $info.defender = @{
            enabled                 = $defender.AntivirusEnabled
            real_time_protection    = $defender.RealTimeProtectionEnabled
            definition_version      = $defender.AntivirusSignatureVersion
            definition_age_days     = $defender.AntivirusSignatureAge
        }
    } catch {
        Write-Warning "Defender status failed: $_"
        $info.defender = @{ error = "Defender status unavailable" }
    }

    # Firewall Status
    try {
        $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $info.firewall = @($fw | ForEach-Object {
            @{
                profile  = $_.Name
                enabled  = $_.Enabled
                inbound  = $_.DefaultInboundAction.ToString()
                outbound = $_.DefaultOutboundAction.ToString()
            }
        })
    } catch {
        Write-Warning "Firewall status failed: $_"
        $info.firewall = @()
    }

    return $info
}

try {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $result = @{
        collected_at = (Get-Date).ToUniversalTime().ToString("o")
        system_info  = Get-SystemInfo
    }

    $json = $result | ConvertTo-Json -Depth 10 -Compress:$false

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    $outFile = Join-Path $OutputDir "sysinfo_$timestamp.json"
    $json | Out-File -FilePath $outFile -Encoding UTF8
    Write-Verbose "Saved system info to $outFile"
    Write-Output $json
} catch {
    Write-Error "sysinfo_check.ps1 fatal error: $_"
    exit 1
}
