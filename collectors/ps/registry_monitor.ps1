<#
.SYNOPSIS
    Monitors Windows Registry persistence locations for BlueSentinel v2.0.
.DESCRIPTION
    Enumerates all standard persistence keys, exports values, and compares
    against a previous snapshot to detect new or modified entries.
.OUTPUTS
    JSON to stdout and cache/registry_<timestamp>.json
.EXAMPLE
    .\registry_monitor.ps1 -Verbose
#>
[CmdletBinding()]
param(
    [string]$OutputDir = "cache",
    [string]$BaselineFile = "cache\registry_baseline.json",
    [switch]$Verbose
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$PERSISTENCE_KEYS = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SYSTEM\CurrentControlSet\Services",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute"
)

function Get-RegistryValues {
    param([string]$KeyPath)
    $values = @()
    try {
        if (Test-Path $KeyPath) {
            $item = Get-Item -Path $KeyPath -ErrorAction Stop
            foreach ($valueName in $item.Property) {
                try {
                    $data = $item.GetValue($valueName)
                    $dataStr = if ($data -is [array]) { ($data -join " ") } else { [string]$data }
                    $values += @{
                        key_path    = $KeyPath
                        name        = $valueName
                        data        = $dataStr.Substring(0, [Math]::Min(500, $dataStr.Length))
                        value_type  = $item.GetValueKind($valueName).ToString()
                    }
                } catch {
                    Write-Verbose "  Failed to read value '$valueName': $_"
                }
            }
        }
    } catch {
        Write-Warning "Failed to read key $KeyPath : $_"
    }
    return $values
}

function Compare-WithBaseline {
    param([array]$CurrentValues, [string]$BaselinePath)
    $changes = @{ new = @(); modified = @(); removed = @() }
    if (-not (Test-Path $BaselinePath)) {
        Write-Verbose "No baseline found — all entries treated as new."
        $changes.new = $CurrentValues
        return $changes
    }
    try {
        $baseline = Get-Content -Path $BaselinePath -Raw | ConvertFrom-Json
        $baselineMap = @{}
        foreach ($entry in $baseline) {
            $key = "$($entry.key_path)|$($entry.name)"
            $baselineMap[$key] = $entry
        }
        $currentMap = @{}
        foreach ($entry in $CurrentValues) {
            $key = "$($entry.key_path)|$($entry.name)"
            $currentMap[$key] = $entry
            if (-not $baselineMap.ContainsKey($key)) {
                $entry.change_type = "NEW"
                $changes.new += $entry
            } elseif ($baselineMap[$key].data -ne $entry.data) {
                $entry.change_type = "MODIFIED"
                $entry.previous_data = $baselineMap[$key].data
                $changes.modified += $entry
            }
        }
        foreach ($key in $baselineMap.Keys) {
            if (-not $currentMap.ContainsKey($key)) {
                $changes.removed += $baselineMap[$key]
            }
        }
    } catch {
        Write-Warning "Baseline comparison failed: $_"
    }
    return $changes
}

try {
    $allValues = @()
    foreach ($key in $PERSISTENCE_KEYS) {
        $allValues += Get-RegistryValues -KeyPath $key
    }

    $changes = Compare-WithBaseline -CurrentValues $allValues -BaselinePath $BaselineFile

    # Save new baseline
    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    $allValues | ConvertTo-Json -Depth 5 | Out-File -FilePath $BaselineFile -Encoding UTF8
    Write-Verbose "Baseline updated: $BaselineFile"

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $result = @{
        collected_at  = (Get-Date).ToUniversalTime().ToString("o")
        total_values  = $allValues.Count
        all_values    = $allValues
        changes       = $changes
        new_count     = $changes.new.Count
        modified_count = $changes.modified.Count
    }

    $json = $result | ConvertTo-Json -Depth 10
    $outFile = Join-Path $OutputDir "registry_$timestamp.json"
    $json | Out-File -FilePath $outFile -Encoding UTF8
    Write-Verbose "Saved to $outFile"
    Write-Output $json
} catch {
    Write-Error "registry_monitor.ps1 fatal: $_"
    exit 1
}
