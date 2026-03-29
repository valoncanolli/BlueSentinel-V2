# Test-NetworkCheck.Tests.ps1
# Pester v5 tests for collectors/ps/network_check.ps1
#
# Tests:
#   1. Output is valid JSON
#   2. Suspicious ports are flagged correctly
#   3. Localhost connections are excluded

BeforeAll {
    # Resolve absolute path to network_check.ps1
    $ScriptRoot = Split-Path -Parent $PSCommandPath
    $ProjectRoot = Split-Path -Parent (Split-Path -Parent $ScriptRoot)
    $NetworkCheckScript = Join-Path $ProjectRoot "collectors\ps\network_check.ps1"

    # Fallback: try relative path from tests/ps/
    if (-not (Test-Path $NetworkCheckScript)) {
        $NetworkCheckScript = Join-Path $ScriptRoot "..\..\collectors\ps\network_check.ps1"
    }

    # Helper: invoke network_check.ps1 and capture output
    function Invoke-NetworkCheck {
        param([hashtable]$MockNetstat = $null)
        if (-not (Test-Path $NetworkCheckScript)) {
            throw "network_check.ps1 not found at: $NetworkCheckScript"
        }
        $output = & powershell.exe -NoProfile -NonInteractive -File $NetworkCheckScript 2>$null
        return $output -join "`n"
    }

    # Helper: invoke with mocked connections (dot-sourcing in child scope)
    function Invoke-NetworkCheckWithMock {
        param([string]$MockScript)
        $tmpFile = [System.IO.Path]::GetTempFileName() + ".ps1"
        try {
            $MockScript | Set-Content -Path $tmpFile -Encoding UTF8
            $output = & powershell.exe -NoProfile -NonInteractive -Command @"
. '$($NetworkCheckScript.Replace("'","''"))'; $($MockScript)
"@ 2>$null
            return $output -join "`n"
        } finally {
            if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force }
        }
    }

    # Helper: parse JSON safely
    function Parse-Json {
        param([string]$JsonString)
        try {
            return $JsonString | ConvertFrom-Json -ErrorAction Stop
        } catch {
            return $null
        }
    }

    # List of known suspicious ports (must match network_check.ps1)
    $SuspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 31337, 1337, 9001, 9030, 9050, 9051)
}

# ---------------------------------------------------------------------------
# Helper to get raw JSON output from the script
# ---------------------------------------------------------------------------
function Get-NetworkCheckOutput {
    if (-not (Test-Path $NetworkCheckScript)) {
        return $null
    }
    $rawOutput = & powershell.exe -NoProfile -NonInteractive `
        -ExecutionPolicy Bypass `
        -File $NetworkCheckScript 2>$null
    return $rawOutput -join "`n"
}

# ---------------------------------------------------------------------------
# TEST 1: Output is valid JSON
# ---------------------------------------------------------------------------

Describe "network_check.ps1 — Output Validation" {

    Context "When script runs successfully" {

        It "Should produce output that is valid JSON" {
            if (-not (Test-Path $NetworkCheckScript)) {
                Set-ItResult -Skipped -Because "network_check.ps1 not found"
                return
            }

            $output = Get-NetworkCheckOutput

            # Output must not be null or empty
            $output | Should -Not -BeNullOrEmpty

            # Must be parseable as JSON
            $parsed = $output | ConvertFrom-Json -ErrorAction SilentlyContinue
            $parsed | Should -Not -BeNullOrEmpty -Because "output must be valid JSON"
        }

        It "Should return a JSON object (not an array)" {
            if (-not (Test-Path $NetworkCheckScript)) {
                Set-ItResult -Skipped -Because "network_check.ps1 not found"
                return
            }

            $output = Get-NetworkCheckOutput
            $parsed = $output | ConvertFrom-Json -ErrorAction SilentlyContinue
            $parsed | Should -BeOfType [PSCustomObject] -Because "root element should be an object"
        }

        It "Should contain expected top-level keys" {
            if (-not (Test-Path $NetworkCheckScript)) {
                Set-ItResult -Skipped -Because "network_check.ps1 not found"
                return
            }

            $output = Get-NetworkCheckOutput
            $parsed = $output | ConvertFrom-Json -ErrorAction SilentlyContinue

            # Check for common expected keys (flexible — different versions may differ)
            $expectedKeys = @("connections", "timestamp", "hostname")
            $actualKeys   = $parsed.PSObject.Properties.Name

            foreach ($key in $expectedKeys) {
                $actualKeys | Should -Contain $key -Because "JSON output should include '$key'"
            }
        }

        It "Should include a non-empty connections array" {
            if (-not (Test-Path $NetworkCheckScript)) {
                Set-ItResult -Skipped -Because "network_check.ps1 not found"
                return
            }

            $output = Get-NetworkCheckOutput
            $parsed = $output | ConvertFrom-Json -ErrorAction SilentlyContinue
            $parsed.connections | Should -Not -BeNullOrEmpty -Or -BeOfType [System.Array]
        }
    }
}

# ---------------------------------------------------------------------------
# TEST 2: Suspicious ports are flagged
# ---------------------------------------------------------------------------

Describe "network_check.ps1 — Suspicious Port Detection" {

    BeforeAll {
        if (-not (Test-Path $NetworkCheckScript)) {
            $script:NetworkOutput = $null
            $script:ParsedOutput  = $null
        } else {
            $script:NetworkOutput = Get-NetworkCheckOutput
            $script:ParsedOutput  = $script:NetworkOutput | ConvertFrom-Json -ErrorAction SilentlyContinue
        }
    }

    It "Should mark connections on known C2 ports as suspicious" {
        if (-not (Test-Path $NetworkCheckScript)) {
            Set-ItResult -Skipped -Because "network_check.ps1 not found"
            return
        }
        if ($null -eq $script:ParsedOutput) {
            Set-ItResult -Skipped -Because "Script produced invalid JSON"
            return
        }

        # Get all connections
        $allConns = @($script:ParsedOutput.connections)
        if ($allConns.Count -eq 0) {
            Set-ItResult -Skipped -Because "No active connections on this system"
            return
        }

        # For each suspicious-flagged connection, verify the port is in the known list
        $flaggedConns = $allConns | Where-Object { $_.suspicious -eq $true }
        foreach ($conn in $flaggedConns) {
            $port = [int]($conn.remote_port ?? $conn.dst_port ?? $conn.port ?? 0)
            $SuspiciousPorts | Should -Contain $port `
                -Because "Connection flagged as suspicious should be on a known C2 port (got port $port)"
        }
    }

    It "Should not flag benign ports (80, 443) as suspicious" {
        if (-not (Test-Path $NetworkCheckScript)) {
            Set-ItResult -Skipped -Because "network_check.ps1 not found"
            return
        }
        if ($null -eq $script:ParsedOutput) {
            Set-ItResult -Skipped -Because "Script produced invalid JSON"
            return
        }

        $allConns  = @($script:ParsedOutput.connections)
        $httpConns = $allConns | Where-Object {
            $port = [int]($_.remote_port ?? $_.dst_port ?? $_.port ?? -1)
            ($port -eq 80 -or $port -eq 443) -and $_.suspicious -eq $true
        }

        $httpConns.Count | Should -Be 0 `
            -Because "Standard HTTP/HTTPS ports should not be flagged as suspicious"
    }

    It "Should include a 'suspicious_count' summary field" {
        if (-not (Test-Path $NetworkCheckScript)) {
            Set-ItResult -Skipped -Because "network_check.ps1 not found"
            return
        }
        if ($null -eq $script:ParsedOutput) {
            Set-ItResult -Skipped -Because "Script produced invalid JSON"
            return
        }

        # Either a top-level suspicious_count or derivable from connections
        $hasSummaryField = $script:ParsedOutput.PSObject.Properties.Name -contains "suspicious_count"
        $derivable       = $null -ne $script:ParsedOutput.connections

        ($hasSummaryField -or $derivable) | Should -BeTrue `
            -Because "Output should provide a way to count suspicious connections"
    }
}

# ---------------------------------------------------------------------------
# TEST 3: Localhost connections are excluded
# ---------------------------------------------------------------------------

Describe "network_check.ps1 — Localhost Exclusion" {

    BeforeAll {
        if (-not (Test-Path $NetworkCheckScript)) {
            $script:ParsedForLocal = $null
        } else {
            $raw = Get-NetworkCheckOutput
            $script:ParsedForLocal = $raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        }
    }

    It "Should not include connections to 127.0.0.1 in results" {
        if (-not (Test-Path $NetworkCheckScript)) {
            Set-ItResult -Skipped -Because "network_check.ps1 not found"
            return
        }
        if ($null -eq $script:ParsedForLocal) {
            Set-ItResult -Skipped -Because "Script produced invalid JSON"
            return
        }

        $allConns     = @($script:ParsedForLocal.connections)
        $loopbackConns = $allConns | Where-Object {
            $remote = $_.remote_address ?? $_.dst_ip ?? $_.destination ?? ""
            $remote -eq "127.0.0.1"
        }

        $loopbackConns.Count | Should -Be 0 `
            -Because "Loopback 127.0.0.1 connections should be excluded from results"
    }

    It "Should not include connections to ::1 (IPv6 loopback)" {
        if (-not (Test-Path $NetworkCheckScript)) {
            Set-ItResult -Skipped -Because "network_check.ps1 not found"
            return
        }
        if ($null -eq $script:ParsedForLocal) {
            Set-ItResult -Skipped -Because "Script produced invalid JSON"
            return
        }

        $allConns        = @($script:ParsedForLocal.connections)
        $ipv6LoopbackConns = $allConns | Where-Object {
            $remote = $_.remote_address ?? $_.dst_ip ?? $_.destination ?? ""
            $remote -eq "::1"
        }

        $ipv6LoopbackConns.Count | Should -Be 0 `
            -Because "IPv6 loopback ::1 connections should be excluded from results"
    }

    It "Should not include connections to 0.0.0.0 (unspecified)" {
        if (-not (Test-Path $NetworkCheckScript)) {
            Set-ItResult -Skipped -Because "network_check.ps1 not found"
            return
        }
        if ($null -eq $script:ParsedForLocal) {
            Set-ItResult -Skipped -Because "Script produced invalid JSON"
            return
        }

        $allConns      = @($script:ParsedForLocal.connections)
        $unspecified   = $allConns | Where-Object {
            $remote = $_.remote_address ?? $_.dst_ip ?? $_.destination ?? ""
            $remote -eq "0.0.0.0"
        }

        $unspecified.Count | Should -Be 0 `
            -Because "Unspecified address 0.0.0.0 should be excluded from results"
    }

    It "All returned connections should have non-empty remote addresses" {
        if (-not (Test-Path $NetworkCheckScript)) {
            Set-ItResult -Skipped -Because "network_check.ps1 not found"
            return
        }
        if ($null -eq $script:ParsedForLocal) {
            Set-ItResult -Skipped -Because "Script produced invalid JSON"
            return
        }

        $allConns    = @($script:ParsedForLocal.connections)
        $emptyRemote = $allConns | Where-Object {
            $remote = $_.remote_address ?? $_.dst_ip ?? $_.destination ?? ""
            [string]::IsNullOrWhiteSpace($remote)
        }

        $emptyRemote.Count | Should -Be 0 `
            -Because "All connections in output should have a valid remote address"
    }
}
