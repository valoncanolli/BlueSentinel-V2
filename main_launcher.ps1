<#
.SYNOPSIS
    BlueSentinel v2.0 - AI-Augmented Threat Detection Platform
.DESCRIPTION
    Main launcher for BlueSentinel v2.0. Checks prerequisites,
    configures environment, and starts the selected scan mode.
.PARAMETER FullScan
    Run a complete scan: network, files, YARA, AI triage, report.
.PARAMETER QuickScan
    Run a reduced-scope scan on high-priority paths only.
.PARAMETER NetworkOnly
    Run network and beaconing analysis only.
.PARAMETER FileOnly
    Run YARA file scan only.
.PARAMETER Dashboard
    Launch the real-time Flask web dashboard.
.PARAMETER GenerateReport
    Generate executive report from the last scan results.
.PARAMETER Help
    Show this help message.
.EXAMPLE
    .\main_launcher.ps1 -FullScan
    .\main_launcher.ps1 -Dashboard
    .\main_launcher.ps1 -Help
#>

[CmdletBinding()]
param(
    [switch]$FullScan,
    [switch]$QuickScan,
    [switch]$NetworkOnly,
    [switch]$FileOnly,
    [switch]$Dashboard,
    [switch]$GenerateReport,
    [switch]$Help
)

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

# Banner
function Show-Banner {
    $cyan   = [System.ConsoleColor]::Cyan
    $blue   = [System.ConsoleColor]::Blue
    $white  = [System.ConsoleColor]::White
    $yellow = [System.ConsoleColor]::Yellow

    Write-Host "" 
    Write-Host "  ██████╗ ██╗     ██╗   ██╗███████╗███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     " -ForegroundColor $cyan
    Write-Host "  ██╔══██╗██║     ██║   ██║██╔════╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     " -ForegroundColor $cyan
    Write-Host "  ██████╔╝██║     ██║   ██║█████╗  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     " -ForegroundColor $blue
    Write-Host "  ██╔══██╗██║     ██║   ██║██╔══╝  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     " -ForegroundColor $blue
    Write-Host "  ██████╔╝███████╗╚██████╔╝███████╗███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗" -ForegroundColor $white
    Write-Host "  ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝" -ForegroundColor $white
    Write-Host ""
    Write-Host "  v2.0  |  AI-Augmented Threat Detection Platform  |  by Valon Canolli" -ForegroundColor $yellow
    Write-Host "  YARA  |  Beaconing Detection  |  MITRE ATT&CK  |  OpenAI / Anthropic" -ForegroundColor $yellow
    Write-Host ""
}

# Help
function Show-Help {
    Write-Host "USAGE:" -ForegroundColor Cyan
    Write-Host "  .\main_launcher.ps1 -FullScan        Full scan: network + files + AI triage + report"
    Write-Host "  .\main_launcher.ps1 -QuickScan       Reduced scope scan on high-priority paths"
    Write-Host "  .\main_launcher.ps1 -NetworkOnly     Network and beaconing analysis only"
    Write-Host "  .\main_launcher.ps1 -FileOnly        YARA file scan only"
    Write-Host "  .\main_launcher.ps1 -Dashboard       Launch real-time web dashboard (https://localhost:5000)"
    Write-Host "  .\main_launcher.ps1 -GenerateReport  Generate executive report from last scan"
    Write-Host "  .\main_launcher.ps1 -Help            Show this help message"
    Write-Host ""
    Write-Host "NOTES:" -ForegroundColor Cyan
    Write-Host "  - Run as Administrator for full functionality (memory scan, raw network capture)"
    Write-Host "  - Populate config\.env with API keys before first run (copy from config\.env.example)"
    Write-Host "  - TShark is optional but required for live packet capture"
    Write-Host ""
}

# Prerequisite check
function Invoke-PrerequisiteCheck {
    $ok = $true

    try {
        $pyver = & python --version 2>&1
        $match = [regex]::Match($pyver, "(\d+)\.(\d+)")
        if ($match.Success) {
            $maj = [int]$match.Groups[1].Value
            $min = [int]$match.Groups[2].Value
            if ($maj -ge 3 -and $min -ge 11) {
                Write-Host "  [OK] Python $maj.$min" -ForegroundColor Green
            } else {
                Write-Host "  [WARN] Python $maj.$min detected. Python 3.11+ recommended." -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "  [ERROR] Python not found. Install from https://python.org" -ForegroundColor Red
        $ok = $false
    }

    try {
        $null = & python -m pip --version 2>&1
        Write-Host "  [OK] pip available" -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] pip not found." -ForegroundColor Red
        $ok = $false
    }

    if (Test-Path "config\.env") {
        Write-Host "  [OK] config\.env file found" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] config\.env not found. Copying from config\.env.example..." -ForegroundColor Yellow
        if (Test-Path "config\.env.example") {
            Copy-Item "config\.env.example" "config\.env"
            Write-Host "  [INFO] config\.env created. Edit it and add your API keys." -ForegroundColor Cyan
        } else {
            Write-Host "  [ERROR] config\.env.example not found." -ForegroundColor Red
            $ok = $false
        }
    }

    if (Test-Path "requirements.txt") {
        Write-Host "  [OK] requirements.txt found" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] requirements.txt missing." -ForegroundColor Red
        $ok = $false
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-Host "  [OK] Running as Administrator" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Not running as Administrator. Some features may be limited." -ForegroundColor Yellow
    }

    try {
        $null = & tshark --version 2>&1
        Write-Host "  [OK] TShark available" -ForegroundColor Green
    } catch {
        Write-Host "  [INFO] TShark not found (optional). Live packet capture disabled." -ForegroundColor Gray
    }

    if (Test-Path "config\.env") {
        $envContent = Get-Content "config\.env" -Raw
        if ($envContent -match "AI_PROVIDER\s*=\s*(\w+)") {
            $provider = $Matches[1]
            Write-Host "  [OK] AI Provider: $provider" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] AI_PROVIDER not set in config\.env" -ForegroundColor Yellow
        }
    }

    return $ok
}

# Python runner
function Invoke-Python {
    param([string]$Arguments)
    try {
        $proc = Start-Process -FilePath "python" -ArgumentList $Arguments -NoNewWindow -Wait -PassThru
        return $proc.ExitCode
    } catch {
        Write-Host "  [ERROR] Failed to run Python: $_" -ForegroundColor Red
        return 1
    }
}

# Open report in browser
function Open-LatestReport {
    $reports = Get-ChildItem -Path "reports" -Filter "*.html" -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending
    if ($reports.Count -gt 0) {
        $report = $reports[0].FullName
        Write-Host ""
        Write-Host "  [INFO] Opening report: $report" -ForegroundColor Cyan
        Start-Process $report
    } else {
        Write-Host "  [INFO] No HTML report found in reports/" -ForegroundColor Gray
    }
}

# Main
Show-Banner

if ($Help -or (-not ($FullScan -or $QuickScan -or $NetworkOnly -or $FileOnly -or $Dashboard -or $GenerateReport))) {
    Show-Help
    exit 0
}

Write-Host "  Checking prerequisites..." -ForegroundColor Cyan
$prereqOk = Invoke-PrerequisiteCheck
Write-Host ""

if (-not $prereqOk) {
    Write-Host "  [ERROR] Prerequisite check failed. Fix the errors above and retry." -ForegroundColor Red
    exit 1
}

if ($FullScan) {
    Write-Host "  [*] Starting Full Scan..." -ForegroundColor Cyan
    $exit = Invoke-Python "-m core.orchestrator --full-scan"
    if ($exit -eq 0) { Open-LatestReport }
}
elseif ($QuickScan) {
    Write-Host "  [*] Starting Quick Scan..." -ForegroundColor Cyan
    Invoke-Python "-m core.orchestrator --quick-scan"
}
elseif ($NetworkOnly) {
    Write-Host "  [*] Starting Network Analysis..." -ForegroundColor Cyan
    Invoke-Python "-m core.orchestrator --network-only"
}
elseif ($FileOnly) {
    Write-Host "  [*] Starting YARA File Scan..." -ForegroundColor Cyan
    Invoke-Python "-m core.orchestrator --file-only"
}
elseif ($Dashboard) {
    Write-Host "  [*] Launching Dashboard at http://localhost:5000" -ForegroundColor Cyan
    Write-Host "  [*] Press Ctrl+C to stop." -ForegroundColor Gray
    Invoke-Python "dashboard/app.py"
}
elseif ($GenerateReport) {
    Write-Host "  [*] Generating Executive Report..." -ForegroundColor Cyan
    $exit = Invoke-Python "-m core.orchestrator --generate-report"
    if ($exit -eq 0) { Open-LatestReport }
}
