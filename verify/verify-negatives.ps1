# [install.win] verify-negatives - Atomic Negative-Case Runner (v2026.11)
# Runs the built-in negative scenarios against verify-signature.ps1.
# Each scenario spawns the verifier as a subprocess and asserts a nonzero exit
# code plus a FAIL-prefixed first token. Any scenario failure exits 1.
#
# Usage:
#   verify-negatives.ps1 -ProbeFile <signed.ps1> -ProducerFile <unsigned.ps1> `
#                        -KeyJson <root-public.json> [-Scenario <id>] [-Quick]
#
# Scenarios:
#   N1 tampered-body      : rewrite first line        -> BODY_DIGEST_MISMATCH
#   N2 tampered-signature : signature field -> 'AAAA' -> FAIL (MALFORMED_BLOCK or
#                            SIGNATURE_INVALID; exact-code assertion skipped in
#                            -Quick mode)
#   N3 no-block           : feed unsigned producer    -> NO_SIGNATURE_BLOCK
#   N4 missing-salt       : delete salt line          -> MALFORMED_BLOCK
#   N5 bad-salt           : salt field -> 'abc'       -> MALFORMED_BLOCK

param(
    [Parameter(Mandatory = $true)]
    [string]$ProbeFile,

    [Parameter(Mandatory = $true)]
    [string]$ProducerFile,

    [Parameter(Mandatory = $true)]
    [string]$KeyJson,

    [Parameter(Mandatory = $false)]
    [string]$Scenario,

    [Parameter(Mandatory = $false)]
    [switch]$Quick
)

$ErrorActionPreference = "Stop"

$verifierScript = Join-Path $PSScriptRoot "verify-signature.ps1"
if (-not (Test-Path -LiteralPath $verifierScript)) {
    Write-Error "verify-signature.ps1 not found next to verify-negatives.ps1"
    exit 1
}
if (-not (Test-Path -LiteralPath $ProbeFile)) {
    Write-Error "probe file not found: $ProbeFile"
    exit 1
}
if (-not (Test-Path -LiteralPath $ProducerFile)) {
    Write-Error "producer file not found: $ProducerFile"
    exit 1
}
if (-not (Test-Path -LiteralPath $KeyJson)) {
    Write-Error "key JSON not found: $KeyJson"
    exit 1
}

function New-TamperedCopy([byte[]]$Bytes, [string]$Suffix) {
    $tempDir = [System.IO.Path]::GetTempPath()
    $tempFile = Join-Path $tempDir ("verify-negatives-" + [System.Guid]::NewGuid().ToString("N") + "-" + $Suffix + ".ps1")
    [System.IO.File]::WriteAllBytes($tempFile, $Bytes)
    return $tempFile
}

function Invoke-Scenario {
    param(
        [string]$Id,
        [string]$Description,
        [scriptblock]$BuildFile,     # returns temp file path; $null = use ProducerFile directly
        [string[]]$AcceptCodes,      # acceptable failure codes (exact assertion)
        [switch]$FailPrefixOnly      # skip exact code assertion (assert FAIL prefix only)
    )

    $targetFile = $null
    try {
        $targetFile = & $BuildFile
        if ($null -eq $targetFile) { $targetFile = $ProducerFile }

        $output = & pwsh -NoProfile -File $verifierScript -File $targetFile -KeyJson $KeyJson 2>&1
        $exitCode = $LASTEXITCODE

        $firstToken = ""
        $failCode = ""
        foreach ($line in @($output)) {
            $text = "$line".Trim()
            if ($text.Length -gt 0) { $firstToken = $text; break }
        }
        if ($firstToken.StartsWith("FAIL ")) {
            $failCode = ($firstToken -split '\s+')[1]
        }

        $passed = ($exitCode -ne 0) -and $firstToken.StartsWith("FAIL ")
        if ($passed -and -not $FailPrefixOnly) {
            if ($AcceptCodes -notcontains $failCode) { $passed = $false }
        }

        if ($passed) {
            Write-Host ("NEG {0}: PASS ({1})" -f $Id, $failCode)
            return $true
        } else {
            Write-Host ("NEG {0}: FAIL (expected {1}, exit={2}, output='{3}')" -f $Id, ($AcceptCodes -join "|"), $exitCode, $firstToken)
            return $false
        }
    } finally {
        if ($targetFile -and ($targetFile -ne $ProducerFile) -and (Test-Path -LiteralPath $targetFile)) {
            Remove-Item -LiteralPath $targetFile -Force -ErrorAction SilentlyContinue
        }
    }
}

$probeBytes = [System.IO.File]::ReadAllBytes($ProbeFile)
$probeText = [System.Text.Encoding]::UTF8.GetString($probeBytes)

$results = @{}
$allScenarioIds = @("N1", "N2", "N3", "N4", "N5")
if ($Scenario -and ($allScenarioIds -notcontains $Scenario)) {
    Write-Error ("unknown scenario: {0} (valid: {1})" -f $Scenario, ($allScenarioIds -join ", "))
    exit 1
}

# --- N1: tampered body -------------------------------------------------------
if (-not $Scenario -or $Scenario -eq "N1") {
$results["N1"] = Invoke-Scenario -Id "N1" -Description "tampered-body" `
    -BuildFile {
        param()
        $text = [System.Text.Encoding]::UTF8.GetString($probeBytes)
        $lines = $text -split "`n"
        $lines[0] = "# TAMPERED FIRST LINE"
        $tampered = ($lines -join "`n")
        New-TamperedCopy ([System.Text.Encoding]::UTF8.GetBytes($tampered)) "tampered-body"
    } `
    -AcceptCodes @("BODY_DIGEST_MISMATCH")
}

# --- N2: tampered signature field -------------------------------------------
if (-not $Scenario -or $Scenario -eq "N2") {
$results["N2"] = Invoke-Scenario -Id "N2" -Description "tampered-signature" `
    -BuildFile {
        param()
        $text = [System.Text.Encoding]::UTF8.GetString($probeBytes)
        $tampered = $text -replace "# signature: [A-Za-z0-9+/=]*", "# signature: AAAA"
        New-TamperedCopy ([System.Text.Encoding]::UTF8.GetBytes($tampered)) "tampered-signature"
    } `
    -AcceptCodes @("MALFORMED_BLOCK", "SIGNATURE_INVALID") `
    -FailPrefixOnly:$Quick
}

# --- N3: no signature block ---------------------------------------------------
if (-not $Scenario -or $Scenario -eq "N3") {
$results["N3"] = Invoke-Scenario -Id "N3" -Description "no-block" `
    -BuildFile { param() $null } `
    -AcceptCodes @("NO_SIGNATURE_BLOCK")
}

# --- N4: missing salt field ---------------------------------------------------
if (-not $Scenario -or $Scenario -eq "N4") {
$results["N4"] = Invoke-Scenario -Id "N4" -Description "missing-salt" `
    -BuildFile {
        param()
        $text = [System.Text.Encoding]::UTF8.GetString($probeBytes)
        $tampered = ($text -split "`n" | Where-Object { $_ -notmatch "^# salt: " }) -join "`n"
        New-TamperedCopy ([System.Text.Encoding]::UTF8.GetBytes($tampered)) "missing-salt"
    } `
    -AcceptCodes @("MALFORMED_BLOCK")
}

# --- N5: bad salt value -------------------------------------------------------
if (-not $Scenario -or $Scenario -eq "N5") {
$results["N5"] = Invoke-Scenario -Id "N5" -Description "bad-salt" `
    -BuildFile {
        param()
        $text = [System.Text.Encoding]::UTF8.GetString($probeBytes)
        $tampered = $text -replace "# salt: [^\r\n]*", "# salt: abc"
        New-TamperedCopy ([System.Text.Encoding]::UTF8.GetBytes($tampered)) "bad-salt"
    } `
    -AcceptCodes @("MALFORMED_BLOCK")
}

# --- Summary ------------------------------------------------------------------
$selected = if ($Scenario) { @($Scenario) } else { $allScenarioIds }
$failed = 0
foreach ($id in $selected) {
    if (-not $results.ContainsKey($id) -or -not $results[$id]) { $failed++ }
}

if ($failed -gt 0) {
    Write-Output ("verify-negatives: {0} scenario(s) FAILED" -f $failed)
    exit 1
}
Write-Output "verify-negatives: all scenarios PASS"
exit 0
