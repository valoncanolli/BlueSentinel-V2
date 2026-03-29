<#
.SYNOPSIS
    Captures network traffic using TShark for BlueSentinel v2.0 beaconing analysis.
.DESCRIPTION
    Runs a timed TShark capture, exports to JSON format for beaconing_detector analysis.
    Falls back gracefully if TShark is not installed.
.PARAMETER Duration
    Capture duration in seconds (default: 60)
.PARAMETER Interface
    Network interface to capture on (default: auto-detect)
.OUTPUTS
    JSON to cache/latest_capture.json
.EXAMPLE
    .\tshark_capture.ps1 -Duration 120 -Verbose
#>
[CmdletBinding()]
param(
    [int]$Duration = 60,
    [string]$Interface = "",
    [string]$OutputDir = "cache",
    [switch]$Verbose
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

function Find-TShark {
    $paths = @(
        "C:\Program Files\Wireshark\tshark.exe",
        "C:\Program Files (x86)\Wireshark\tshark.exe",
        (Get-Command tshark -ErrorAction SilentlyContinue)?.Source
    ) | Where-Object { $_ -and (Test-Path $_) }
    return $paths | Select-Object -First 1
}

function Get-DefaultInterface {
    try {
        $ifaces = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
        return $ifaces.InterfaceDescription
    } catch {
        return "1"
    }
}

function Start-TSharkCapture {
    param([string]$TSharkPath, [string]$Iface, [int]$Dur, [string]$OutDir)

    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    $pcapFile = Join-Path $OutDir "capture_$(Get-Date -Format 'yyyyMMdd_HHmmss').pcap"
    $jsonFile = Join-Path $OutDir "latest_capture.json"

    Write-Verbose "Starting $Dur second capture on interface: $Iface"
    $args = @("-i", "`"$Iface`"", "-a", "duration:$Dur", "-w", "`"$pcapFile`"", "-q")
    $proc = Start-Process -FilePath $TSharkPath -ArgumentList $args -Wait -PassThru -WindowStyle Hidden

    if ($proc.ExitCode -ne 0) {
        Write-Warning "TShark capture exited with code $($proc.ExitCode)"
        return $false
    }

    Write-Verbose "Converting pcap to JSON..."
    $tsharkArgs = @(
        "-r", "`"$pcapFile`"",
        "-T", "json",
        "-e", "frame.time_epoch",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "frame.len",
        "-e", "dns.qry.name",
        "-E", "header=y"
    )
    $jsonOutput = & $TSharkPath @tsharkArgs 2>$null

    if ($jsonOutput) {
        $jsonOutput | Out-File -FilePath $jsonFile -Encoding UTF8
        Write-Verbose "Capture saved to $jsonFile"
        return $true
    }
    return $false
}

try {
    $tshark = Find-TShark
    if (-not $tshark) {
        Write-Warning "TShark not found. Install Wireshark to enable network capture."
        $result = @{
            status    = "TSHARK_NOT_FOUND"
            message   = "Install Wireshark/TShark to enable packet capture"
            timestamp = (Get-Date).ToUniversalTime().ToString("o")
        }
        $result | ConvertTo-Json | Write-Output
        exit 0
    }

    $iface = if ($Interface) { $Interface } else { Get-DefaultInterface }
    Write-Verbose "Using TShark: $tshark, Interface: $iface, Duration: $Duration s"

    $success = Start-TSharkCapture -TSharkPath $tshark -Iface $iface -Dur $Duration -OutDir $OutputDir

    $result = @{
        status    = if ($success) { "SUCCESS" } else { "FAILED" }
        tshark    = $tshark
        interface = $iface
        duration  = $Duration
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        output    = Join-Path $OutputDir "latest_capture.json"
    }
    $result | ConvertTo-Json | Write-Output
} catch {
    Write-Error "tshark_capture.ps1 fatal: $_"
    exit 1
}
