<#
.SYNOPSIS
    Collects active network connections and DNS cache for BlueSentinel v2.0.
.DESCRIPTION
    Enumerates all TCP/UDP connections, listening ports, DNS cache, and ARP table.
    Flags connections to suspicious ports or private->external long-lived sessions.
.OUTPUTS
    JSON to stdout and cache/network_<timestamp>.json
.EXAMPLE
    .\network_check.ps1 -Verbose
#>
[CmdletBinding()]
param(
    [string]$OutputDir = "cache",
    [switch]$Verbose
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$SUSPICIOUS_PORTS = @(4444, 4445, 4446, 1234, 31337, 8888, 9999, 6666, 6667, 6668, 6669)
$COMMON_PORTS = @(80, 443, 53, 22, 25, 587, 993, 465, 3389, 445, 139, 135)

function Get-NetworkConnections {
    $connections = @()
    try {
        $tcpConns = Get-NetTCPConnection -ErrorAction Stop
        $processCache = @{}
        foreach ($conn in $tcpConns) {
            $procName = "Unknown"
            $procPath = ""
            if ($conn.OwningProcess -gt 0) {
                if (-not $processCache.ContainsKey($conn.OwningProcess)) {
                    try {
                        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                        $processCache[$conn.OwningProcess] = @{
                            name = if ($proc) { $proc.ProcessName } else { "Unknown" }
                            path = if ($proc) { try { $proc.MainModule.FileName } catch { "" } } else { "" }
                        }
                    } catch {
                        $processCache[$conn.OwningProcess] = @{ name = "Unknown"; path = "" }
                    }
                }
                $procName = $processCache[$conn.OwningProcess].name
                $procPath = $processCache[$conn.OwningProcess].path
            }

            $suspicious = ($conn.RemotePort -in $SUSPICIOUS_PORTS) -or
                          ($conn.State -eq "Established" -and $conn.RemoteAddress -notin @("0.0.0.0","::","127.0.0.1","::1") -and $conn.RemotePort -notin $COMMON_PORTS)

            $connections += @{
                protocol       = "TCP"
                local_address  = $conn.LocalAddress
                local_port     = $conn.LocalPort
                remote_address = $conn.RemoteAddress
                remote_port    = $conn.RemotePort
                state          = $conn.State
                pid            = $conn.OwningProcess
                process_name   = $procName
                process_path   = $procPath
                suspicious     = $suspicious
            }
        }
    } catch {
        Write-Warning "TCP connection collection failed: $_"
    }
    return $connections
}

function Get-DnsCache {
    $cache = @()
    try {
        $dnsEntries = Get-DnsClientCache -ErrorAction Stop
        foreach ($entry in $dnsEntries) {
            $cache += @{
                entry        = $entry.Entry
                record_name  = $entry.RecordName
                record_type  = $entry.RecordType
                status       = $entry.Status
                section      = $entry.Section
                time_to_live = $entry.TimeToLive
                data_length  = $entry.DataLength
                data         = $entry.Data
            }
        }
    } catch {
        Write-Warning "DNS cache collection failed: $_"
    }
    return $cache
}

function Get-ArpTable {
    $arp = @()
    try {
        $arpEntries = Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Unreachable" }
        foreach ($entry in $arpEntries) {
            $arp += @{
                ip_address   = $entry.IPAddress
                link_layer   = $entry.LinkLayerAddress
                state        = $entry.State
                interface    = $entry.InterfaceAlias
            }
        }
    } catch {
        Write-Warning "ARP table failed: $_"
    }
    return $arp
}

try {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $result = @{
        collected_at    = (Get-Date).ToUniversalTime().ToString("o")
        connections     = Get-NetworkConnections
        dns_cache       = Get-DnsCache
        arp_table       = Get-ArpTable
        suspicious_count = 0
    }
    $result.suspicious_count = ($result.connections | Where-Object { $_.suspicious }).Count

    $json = $result | ConvertTo-Json -Depth 10

    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    $outFile = Join-Path $OutputDir "network_$timestamp.json"
    $json | Out-File -FilePath $outFile -Encoding UTF8
    Write-Verbose "Saved to $outFile — $($result.suspicious_count) suspicious connections"
    Write-Output $json
} catch {
    Write-Error "network_check.ps1 fatal: $_"
    exit 1
}
