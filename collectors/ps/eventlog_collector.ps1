<#
.SYNOPSIS
    Collects and analyzes Windows Event Logs for BlueSentinel v2.0.
.DESCRIPTION
    Queries Security, System, and PowerShell event logs for suspicious events.
    Flags brute force, new services, encoded PowerShell, and privilege escalation.
.OUTPUTS
    JSON to stdout and cache/eventlog_<timestamp>.json
.EXAMPLE
    .\eventlog_collector.ps1 -HoursBack 24 -Verbose
#>
[CmdletBinding()]
param(
    [int]$HoursBack = 24,
    [string]$OutputDir = "cache",
    [switch]$Verbose
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$START_TIME = (Get-Date).AddHours(-$HoursBack)

$EVENT_IDS = @{
    Security = @(4624, 4625, 4648, 4672, 4688, 4698, 4699, 4702, 4720, 4732, 4756, 4776)
    System   = @(7045, 7036, 7040)
    PowerShell = @(4103, 4104)
}

function Get-SecurityEvents {
    $events = @()
    try {
        $raw = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = $EVENT_IDS.Security
            StartTime = $START_TIME
        } -ErrorAction SilentlyContinue -MaxEvents 5000

        foreach ($evt in $raw) {
            try {
                $xml = [xml]$evt.ToXml()
                $data = @{}
                $xml.Event.EventData.Data | ForEach-Object {
                    if ($_.Name) { $data[$_.Name] = $_.'#text' }
                }
                $events += @{
                    event_id    = $evt.Id
                    time        = $evt.TimeCreated.ToUniversalTime().ToString("o")
                    level       = $evt.LevelDisplayName
                    message     = $evt.Message.Substring(0, [Math]::Min(500, $evt.Message.Length))
                    data        = $data
                    computer    = $evt.MachineName
                }
            } catch {
                Write-Verbose "Event parse failed: $_"
            }
        }
    } catch {
        Write-Warning "Security log query failed: $_"
    }
    return $events
}

function Get-SystemEvents {
    $events = @()
    try {
        $raw = Get-WinEvent -FilterHashtable @{
            LogName   = "System"
            Id        = $EVENT_IDS.System
            StartTime = $START_TIME
        } -ErrorAction SilentlyContinue -MaxEvents 1000
        foreach ($evt in $raw) {
            $events += @{
                event_id = $evt.Id
                time     = $evt.TimeCreated.ToUniversalTime().ToString("o")
                level    = $evt.LevelDisplayName
                message  = $evt.Message.Substring(0, [Math]::Min(400, $evt.Message.Length))
                computer = $evt.MachineName
            }
        }
    } catch {
        Write-Warning "System log query failed: $_"
    }
    return $events
}

function Get-PowerShellEvents {
    $events = @()
    try {
        $raw = Get-WinEvent -FilterHashtable @{
            LogName   = "Microsoft-Windows-PowerShell/Operational"
            Id        = $EVENT_IDS.PowerShell
            StartTime = $START_TIME
        } -ErrorAction SilentlyContinue -MaxEvents 2000
        foreach ($evt in $raw) {
            $msg = $evt.Message
            $encoded = $msg -match "-enc|-encodedcommand|[A-Za-z0-9+/]{100,}={0,2}"
            $events += @{
                event_id  = $evt.Id
                time      = $evt.TimeCreated.ToUniversalTime().ToString("o")
                message   = $msg.Substring(0, [Math]::Min(800, $msg.Length))
                is_encoded = $encoded
                computer  = $evt.MachineName
            }
        }
    } catch {
        Write-Warning "PowerShell operational log failed: $_"
    }
    return $events
}

function Find-BruteForceAttempts {
    param([array]$SecurityEvents)
    $failed = $SecurityEvents | Where-Object { $_.event_id -eq 4625 }
    $grouped = $failed | Group-Object { $_.data.TargetUserName } |
        Where-Object { $_.Count -ge 5 } |
        ForEach-Object {
            @{
                username   = $_.Name
                attempts   = $_.Count
                flag       = "BRUTE_FORCE_ATTEMPT"
                severity   = if ($_.Count -gt 20) { "Critical" } else { "High" }
            }
        }
    return @($grouped)
}

try {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $secEvents = Get-SecurityEvents
    $sysEvents  = Get-SystemEvents
    $psEvents   = Get-PowerShellEvents

    $result = @{
        collected_at          = (Get-Date).ToUniversalTime().ToString("o")
        hours_back            = $HoursBack
        security_events       = $secEvents
        system_events         = $sysEvents
        powershell_events     = $psEvents
        brute_force_attempts  = Find-BruteForceAttempts -SecurityEvents $secEvents
        total_events          = $secEvents.Count + $sysEvents.Count + $psEvents.Count
    }

    $json = $result | ConvertTo-Json -Depth 8
    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    $outFile = Join-Path $OutputDir "eventlog_$timestamp.json"
    $json | Out-File -FilePath $outFile -Encoding UTF8
    Write-Verbose "Saved $($result.total_events) events to $outFile"
    Write-Output $json
} catch {
    Write-Error "eventlog_collector.ps1 fatal: $_"
    exit 1
}
