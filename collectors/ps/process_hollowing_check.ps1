<#
.SYNOPSIS
    Detects process hollowing and injection indicators for BlueSentinel v2.0.
.DESCRIPTION
    Checks for exe path mismatches, processes without disk files, unusual
    parent-child relationships, and svchost not spawned from services.exe.
.OUTPUTS
    JSON to stdout and cache/hollowing_<timestamp>.json
.EXAMPLE
    .\process_hollowing_check.ps1 -Verbose
#>
[CmdletBinding()]
param(
    [string]$OutputDir = "cache",
    [switch]$Verbose
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$EXPECTED_PARENTS = @{
    "svchost.exe"    = @("services.exe", "svchost.exe")
    "lsass.exe"      = @("wininit.exe")
    "spoolsv.exe"    = @("services.exe")
    "taskhost.exe"   = @("services.exe", "svchost.exe")
    "taskhostw.exe"  = @("services.exe", "svchost.exe")
    "winlogon.exe"   = @("smss.exe", "wininit.exe")
    "csrss.exe"      = @("smss.exe")
    "wininit.exe"    = @("smss.exe")
    "smss.exe"       = @("system")
    "explorer.exe"   = @("userinit.exe", "winlogon.exe")
}

function Get-ProcessTree {
    $tree = @{}
    try {
        $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
        foreach ($p in $procs) {
            $tree[$p.ProcessId] = @{
                pid         = $p.ProcessId
                ppid        = $p.ParentProcessId
                name        = $p.Name.ToLower()
                exe_path    = $p.ExecutablePath
                cmdline     = $p.CommandLine
                create_time = $p.CreationDate
            }
        }
    } catch {
        Write-Warning "Process tree collection failed: $_"
    }
    return $tree
}

function Find-SuspiciousProcesses {
    param([hashtable]$Tree)
    $findings = @()

    foreach ($pid in $Tree.Keys) {
        $proc = $Tree[$pid]
        $procName = $proc.name
        $exePath = $proc.exe_path

        # 1. Process exists but no executable on disk
        if ($exePath -and -not (Test-Path $exePath -ErrorAction SilentlyContinue)) {
            $findings += @{
                pid          = $pid
                process_name = $procName
                exe_path     = $exePath
                finding      = "NO_DISK_FILE"
                severity     = "High"
                description  = "Process running but executable not found on disk"
            }
        }

        # 2. Check expected parent relationships
        if ($EXPECTED_PARENTS.ContainsKey($procName)) {
            $expectedParentNames = $EXPECTED_PARENTS[$procName]
            $parentPid = $proc.ppid
            if ($parentPid -gt 0 -and $Tree.ContainsKey($parentPid)) {
                $parentName = $Tree[$parentPid].name
                if ($parentName -notin $expectedParentNames) {
                    $findings += @{
                        pid          = $pid
                        process_name = $procName
                        exe_path     = $exePath
                        parent_pid   = $parentPid
                        parent_name  = $parentName
                        finding      = "UNEXPECTED_PARENT"
                        severity     = "Critical"
                        description  = "$procName expected parent: $($expectedParentNames -join ','), got: $parentName"
                    }
                }
            }
        }

        # 3. Multiple instances of single-instance processes
        $singleInstance = @("lsass.exe", "wininit.exe", "csrss.exe", "smss.exe")
        if ($procName -in $singleInstance) {
            $count = ($Tree.Values | Where-Object { $_.name -eq $procName }).Count
            if ($count -gt 1) {
                $findings += @{
                    pid          = $pid
                    process_name = $procName
                    exe_path     = $exePath
                    finding      = "DUPLICATE_SINGLETON_PROCESS"
                    severity     = "Critical"
                    description  = "Multiple instances of $procName ($count) — possible process masquerading"
                    instance_count = $count
                }
            }
        }

        # 4. Processes named like system processes but running from unusual paths
        $systemNames = @("svchost", "lsass", "winlogon", "csrss", "smss", "wininit", "services")
        $nameWithout = ($procName -replace "\.exe$", "")
        if ($nameWithout -in $systemNames -and $exePath) {
            $normalPaths = @("C:\Windows\System32", "C:\Windows\SysWOW64")
            $inNormalPath = $false
            foreach ($np in $normalPaths) {
                if ($exePath -like "$np\*") { $inNormalPath = $true; break }
            }
            if (-not $inNormalPath) {
                $findings += @{
                    pid          = $pid
                    process_name = $procName
                    exe_path     = $exePath
                    finding      = "SYSTEM_PROCESS_WRONG_PATH"
                    severity     = "Critical"
                    description  = "System process running from non-standard path: $exePath"
                }
            }
        }
    }

    # Deduplicate
    $unique = @{}
    foreach ($f in $findings) {
        $key = "$($f.pid)-$($f.finding)"
        if (-not $unique.ContainsKey($key)) { $unique[$key] = $f }
    }
    return @($unique.Values)
}

try {
    $tree = Get-ProcessTree
    $findings = Find-SuspiciousProcesses -Tree $tree

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $result = @{
        collected_at    = (Get-Date).ToUniversalTime().ToString("o")
        total_processes = $tree.Count
        findings        = $findings
        critical_count  = ($findings | Where-Object { $_.severity -eq "Critical" }).Count
        high_count      = ($findings | Where-Object { $_.severity -eq "High" }).Count
    }

    $json = $result | ConvertTo-Json -Depth 8
    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    $outFile = Join-Path $OutputDir "hollowing_$timestamp.json"
    $json | Out-File -FilePath $outFile -Encoding UTF8
    Write-Verbose "Saved $($findings.Count) findings to $outFile"
    Write-Output $json
} catch {
    Write-Error "process_hollowing_check.ps1 fatal: $_"
    exit 1
}
