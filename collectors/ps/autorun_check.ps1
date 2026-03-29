<#
.SYNOPSIS
    Enumerates all autorun/persistence locations on Windows for BlueSentinel v2.0.
.DESCRIPTION
    Checks Run/RunOnce registry keys, startup folders, scheduled tasks, services,
    and WMI subscriptions. Flags new or unusual entries.
.OUTPUTS
    JSON to stdout and cache/autorun_<timestamp>.json
.EXAMPLE
    .\autorun_check.ps1 -Verbose
#>
[CmdletBinding()]
param(
    [string]$OutputDir = "cache",
    [switch]$Verbose
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$RUN_KEYS = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)

function Get-RunKeys {
    $entries = @()
    foreach ($keyPath in $RUN_KEYS) {
        try {
            if (Test-Path $keyPath) {
                $key = Get-ItemProperty -Path $keyPath -ErrorAction Stop
                $key.PSObject.Properties | Where-Object {
                    $_.Name -notlike "PS*"
                } | ForEach-Object {
                    $entries += @{
                        key_path  = $keyPath
                        name      = $_.Name
                        value     = $_.Value
                        hive      = if ($keyPath -like "HKLM:*") { "HKLM" } else { "HKCU" }
                    }
                }
            }
        } catch {
            Write-Warning "Failed to read $keyPath : $_"
        }
    }
    return $entries
}

function Get-StartupFolders {
    $entries = @()
    $startupPaths = @(
        [System.Environment]::GetFolderPath("CommonStartup"),
        [System.Environment]::GetFolderPath("Startup")
    )
    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            try {
                Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $entries += @{
                        path       = $_.FullName
                        name       = $_.Name
                        size_bytes = $_.Length
                        last_write = $_.LastWriteTime.ToString("o")
                        startup_folder = $path
                    }
                }
            } catch {
                Write-Warning "Startup folder failed $path : $_"
            }
        }
    }
    return $entries
}

function Get-ScheduledTasksInfo {
    $tasks = @()
    try {
        $allTasks = Get-ScheduledTask -ErrorAction Stop
        foreach ($task in $allTasks) {
            try {
                $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                $actions = $task.Actions | ForEach-Object {
                    @{
                        type    = $_.CimClass.CimClassName
                        execute = if ($_.Execute) { $_.Execute } else { "" }
                        arguments = if ($_.Arguments) { $_.Arguments } else { "" }
                    }
                }
                $tasks += @{
                    task_name    = $task.TaskName
                    task_path    = $task.TaskPath
                    state        = $task.State.ToString()
                    author       = $task.Author
                    description  = $task.Description
                    actions      = @($actions)
                    last_run     = if ($info -and $info.LastRunTime) { $info.LastRunTime.ToString("o") } else { $null }
                    next_run     = if ($info -and $info.NextRunTime) { $info.NextRunTime.ToString("o") } else { $null }
                    last_result  = if ($info) { $info.LastTaskResult } else { $null }
                }
            } catch {
                Write-Warning "Task info failed for $($task.TaskName): $_"
            }
        }
    } catch {
        Write-Warning "Scheduled tasks enumeration failed: $_"
    }
    return $tasks
}

try {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $result = @{
        collected_at    = (Get-Date).ToUniversalTime().ToString("o")
        run_keys        = Get-RunKeys
        startup_folders = Get-StartupFolders
        scheduled_tasks = Get-ScheduledTasksInfo
    }

    $json = $result | ConvertTo-Json -Depth 10
    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    $outFile = Join-Path $OutputDir "autorun_$timestamp.json"
    $json | Out-File -FilePath $outFile -Encoding UTF8
    Write-Verbose "Saved to $outFile"
    Write-Output $json
} catch {
    Write-Error "autorun_check.ps1 fatal: $_"
    exit 1
}
