param(
    [Parameter(Mandatory = $true)]
    [string]$File,

    [Parameter(Mandatory = $true)]
    [string]$KeyJson
)

function Fail([string]$Code, [string]$Detail) {
    Write-Output "FAIL $Code $Detail"
    exit 1
}

if (-not (Test-Path -LiteralPath $File)) { Fail "FILE_NOT_FOUND" "$File" }
if (-not (Test-Path -LiteralPath $KeyJson)) { Fail "KEY_FILE_NOT_FOUND" "$KeyJson" }

$rawBytes = [System.IO.File]::ReadAllBytes($File)

# --- Step 1: CRLF -> LF normalization ---
$normalized = New-Object System.Collections.Generic.List[byte]
$i = 0
while ($i -lt $rawBytes.Length) {
    $b = $rawBytes[$i]
    if ($b -eq 13 -and ($i + 1) -lt $rawBytes.Length -and $rawBytes[$i + 1] -eq 10) {
        $normalized.Add(10)
        $i += 2
    } else {
        $normalized.Add($b)
        $i += 1
    }
}
$bytes = $normalized.ToArray()

# --- Step 1: locate signature block ---
$headerText = "# --- install.win SIGNATURE ---"
$headerBytes = [System.Text.Encoding]::UTF8.GetBytes($headerText)
$blockStart = -1
for ($i = 0; $i -le ($bytes.Length - $headerBytes.Length); $i++) {
    $match = $true
    for ($j = 0; $j -lt $headerBytes.Length; $j++) {
        if ($bytes[$i + $j] -ne $headerBytes[$j]) { $match = $false; break }
    }
    if ($match) { $blockStart = $i; break }
}
if ($blockStart -lt 0) { Fail "NO_SIGNATURE_BLOCK" "signature header not found" }

$scriptBody = [byte[]]$bytes[0..($blockStart - 1)]
$blockBytes = [byte[]]$bytes[$blockStart..($bytes.Length - 1)]
$blockText = [System.Text.Encoding]::UTF8.GetString($blockBytes)
$blockLines = $blockText -split "`n"

# --- Step 2: parse fields and Base64 field values ---
$fields = @{}
function DecodeBase64ToBytes([string]$Value, [string]$FailureCode = "PLATFORM_UNSUPPORTED") {
    $chars = $Value.ToCharArray()
    $padding = 0
    if ($Value.EndsWith("==")) { $padding = 2 }
    elseif ($Value.EndsWith("=")) { $padding = 1 }
    $encodedLength = $chars.Length - $padding
    $result = New-Object byte[] ([int]($encodedLength * 3 / 4))
    $byteIndex = 0
    $accumulator = 0
    $bitsCollected = 0
    foreach ($c in $chars) {
        $cVal = 0
        if ($c -ge 'A' -and $c -le 'Z') { $cVal = [int][char]$c - 65 }
        elseif ($c -ge 'a' -and $c -le 'z') { $cVal = [int][char]$c - 97 + 26 }
        elseif ($c -ge '0' -and $c -le '9') { $cVal = [int][char]$c - 48 + 52 }
        elseif ($c -eq '+') { $cVal = 62 }
        elseif ($c -eq '/') { $cVal = 63 }
        elseif ($c -eq '=') { break }
        else { Fail "$FailureCode" "illegal base64 character: $c" }
        $accumulator = ($accumulator -shl 6) -bor $cVal
        $bitsCollected += 6
        if ($bitsCollected -ge 8) {
            $bitsCollected -= 8
            $result[$byteIndex] = [byte](($accumulator -shr $bitsCollected) -band 0xFF)
            $byteIndex += 1
        }
    }
    return [byte[]]$result[0..([Math]::Max(0, $byteIndex - 1))]
}

foreach ($line in $blockLines) {
    $trimmed = $line.TrimEnd("`r")
    if ($trimmed -eq "# --- install.win SIGNATURE ---") { continue }
    if ($trimmed -eq "# --- END SIGNATURE ---") { continue }
    if (-not $trimmed.StartsWith("# ") -and $trimmed.Length -gt 0) {
        Fail "MALFORMED_BLOCK" "unexpected line in signature block"
    }
    if ($trimmed.Length -le 2) { continue }
    $fieldText = $trimmed.Substring(2)
    $colonIndex = $fieldText.IndexOf(":")
    if ($colonIndex -lt 0) { Fail "MALFORMED_BLOCK" "missing colon in field line" }
    $fieldName = $fieldText.Substring(0, $colonIndex).Trim()
    $fieldValue = $fieldText.Substring($colonIndex + 1).Trim()
    if ($fields.ContainsKey($fieldName)) {
        Fail "MALFORMED_BLOCK" "duplicate field: $fieldName"
    }
    $fields[$fieldName] = $fieldValue
}

$requiredFields = @("key-id", "alg", "salt", "handle", "sha256", "signed-at", "signature")
foreach ($field in $requiredFields) {
    if (-not $fields.ContainsKey($field) -or [string]::IsNullOrEmpty($fields[$field])) {
        Fail "MALFORMED_BLOCK" "missing or empty field: $field"
    }
}

if ($fields["alg"] -ne "RSA-PSS/SHA-256/salt=32") {
    Fail "MALFORMED_BLOCK" "unexpected alg: $($fields['alg'])"
}
$saltLength = 0
if ($fields["salt"] -notmatch '^\d+$') {
    Fail "MALFORMED_BLOCK" "invalid salt format: $($fields['salt'])"
}
$saltLength = [int]$fields["salt"]
if ($saltLength -lt 1 -or $saltLength -gt 478) {
    Fail "MALFORMED_BLOCK" "salt out of range (1-478): $saltLength"
}
if ($fields["sha256"] -notmatch '^[0-9a-f]{64}$') {
    Fail "MALFORMED_BLOCK" "invalid sha256 format"
}
if ($fields["key-id"] -notmatch '^[0-9a-f]{32}$') {
    Fail "MALFORMED_BLOCK" "invalid key-id format"
}
if (-not $fields["signature"]) {
    Fail "MALFORMED_BLOCK" "missing or empty field: signature"
}
$signatureBytes = DecodeBase64ToBytes $fields["signature"] "MALFORMED_BLOCK"

# --- Step 3: load public key and verify key-id ---
$keyJsonText = [System.IO.File]::ReadAllText($KeyJson)
$keyData = $keyJsonText | ConvertFrom-Json

if (-not $keyData.PSObject.Properties["keyId"]) { Fail "PLATFORM_UNSUPPORTED" "key JSON missing keyId" }
if (-not $keyData.PSObject.Properties["modulus"]) { Fail "PLATFORM_UNSUPPORTED" "key JSON missing modulus" }
if (-not $keyData.PSObject.Properties["exponent"]) { Fail "PLATFORM_UNSUPPORTED" "key JSON missing exponent" }

if ($fields["key-id"] -ne $keyData.keyId) {
    Fail "KEY_ID_MISMATCH" "block key-id $($fields['key-id']) != key JSON $($keyData.keyId)"
}

try {
    $modulusBytes = DecodeBase64ToBytes $keyData.modulus
    $exponentBytes = DecodeBase64ToBytes $keyData.exponent
} catch {
    Fail "PLATFORM_UNSUPPORTED" "cannot decode public key material"
}

if ($modulusBytes.Length -eq 0 -or $exponentBytes.Length -eq 0) {
    Fail "PLATFORM_UNSUPPORTED" "public key material invalid"
}

$modulusHex = [System.BitConverter]::ToString($modulusBytes).Replace("-", "")
$exponentHex = [System.BitConverter]::ToString($exponentBytes).Replace("-", "")
try {
    $modulusBig = [System.Numerics.BigInteger]::Parse("0" + $modulusHex, [System.Globalization.NumberStyles]::HexNumber)
    $exponentBig = [System.Numerics.BigInteger]::Parse("0" + $exponentHex, [System.Globalization.NumberStyles]::HexNumber)
} catch {
    Fail "PLATFORM_UNSUPPORTED" "BigInteger not available on this platform: $($_.Exception.Message)"
}

# --- Step 4: recompute digest sha256(body || 0x00 || handle) ---
$handleAscii = [System.Text.Encoding]::ASCII.GetBytes($fields["handle"])
$digestInput = New-Object System.Collections.Generic.List[byte]
$digestInput.AddRange([byte[]]$scriptBody)
$digestInput.Add(0)
$digestInput.AddRange([byte[]]$handleAscii)

try {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
} catch {
    Fail "PLATFORM_UNSUPPORTED" "SHA256 not available on this platform: $($_.Exception.Message)"
}
$computedDigest = $sha256.ComputeHash($digestInput.ToArray())
$computedHex = [System.BitConverter]::ToString($computedDigest).Replace("-", "").ToLower()

if ($computedHex -ne $fields["sha256"]) {
    $sha256.Dispose()
    Fail "BODY_DIGEST_MISMATCH" "recomputed $computedHex != block $($fields['sha256'])"
}

# --- Step 5: explicit-salt PSS verification (RFC 8017 EMSA-PSS-VERIFY) ---
# RSA public-key operation via BigInteger.ModPow (platform-neutral; no RSACng).
# BigInteger(byte[]) is little-endian with sign bit: reverse bytes and append
# 0x00 to guarantee a positive value for big-endian RSA integers.
$sigLen = $signatureBytes.Length
$sigLe = New-Object byte[] ($sigLen + 1)
for ($i = 0; $i -lt $sigLen; $i++) { $sigLe[$i] = $signatureBytes[$sigLen - 1 - $i] }
$sigBig = New-Object System.Numerics.BigInteger (,[byte[]]$sigLe)
$sigBig = [System.Numerics.BigInteger]::ModPow($sigBig, $exponentBig, $modulusBig)

$k = $modulusBytes.Length
$emLe = $sigBig.ToByteArray()
# ToByteArray() is minimal two's-complement little-endian: a trailing 0x00 is
# the sign byte, present only when the top magnitude byte >= 0x80. Strip it,
# reverse to big-endian, and right-align (I2OSP) to k bytes.
$magLen = $emLe.Length
if ($emLe[$magLen - 1] -eq 0) { $magLen = $magLen - 1 }
if ($magLen -gt $k) {
    $sha256.Dispose()
    Fail "SIGNATURE_INVALID" "recovered encoded message longer than modulus"
}
$em = New-Object byte[] $k
for ($i = 0; $i -lt $magLen; $i++) { $em[$k - 1 - $i] = $emLe[$i] }

$hLen = 32
if ($em[$k - 1] -ne 0xbc) {
    $sha256.Dispose()
    Fail "SIGNATURE_INVALID" "encoded message trailer is not 0xbc"
}

$dbLen = $k - $hLen - 1
$maskedDb = [byte[]]$em[0..($dbLen - 1)]
$H = [byte[]]$em[$dbLen..($dbLen + $hLen - 1)]

# emBits = modBits - 1; the leftmost 8*k - emBits bits of maskedDB must be zero.
$modBits = 8 * ($k - 1)
$topByte = [int]$modulusBytes[0]
while ($topByte -gt 0) { $modBits++; $topByte = $topByte -shr 1 }
$excessBits = 8 * $k - ($modBits - 1)
if ($excessBits -gt 0) {
    $keepMask = 0xFF -shr $excessBits
    if (([int]$maskedDb[0] -band ((-bnot $keepMask) -band 0xFF)) -ne 0) {
        $sha256.Dispose()
        Fail "SIGNATURE_INVALID" "maskedDB leading bits not zero"
    }
}

# dbMask = MGF1(H, dbLen) (RFC 8017 B.2.1, SHA-256); DB = maskedDB XOR dbMask.
$dbMask = New-Object byte[] $dbLen
$mgfSeed = New-Object byte[] ($hLen + 4)
for ($i = 0; $i -lt $hLen; $i++) { $mgfSeed[$i] = $H[$i] }
$counter = 0
for ($offset = 0; $offset -lt $dbLen; $offset += $hLen) {
    $mgfSeed[$hLen]      = [byte](($counter -shr 24) -band 0xFF)
    $mgfSeed[$hLen + 1]  = [byte](($counter -shr 16) -band 0xFF)
    $mgfSeed[$hLen + 2]  = [byte](($counter -shr 8) -band 0xFF)
    $mgfSeed[$hLen + 3]  = [byte]($counter -band 0xFF)
    $mgfBlock = $sha256.ComputeHash($mgfSeed)
    $mgfCopy = [Math]::Min($hLen, $dbLen - $offset)
    for ($i = 0; $i -lt $mgfCopy; $i++) { $dbMask[$offset + $i] = $mgfBlock[$i] }
    $counter++
}
$db = New-Object byte[] $dbLen
for ($i = 0; $i -lt $dbLen; $i++) { $db[$i] = $maskedDb[$i] -bxor $dbMask[$i] }
if ($excessBits -gt 0) {
    $db[0] = $db[0] -band (0xFF -shr $excessBits)
}

# PS region: all 0x00 up to a single 0x01 separator (RFC 8017 step 6).
$separatorIndex = -1
for ($i = 0; $i -lt $dbLen; $i++) {
    if ($db[$i] -eq 0x01) { $separatorIndex = $i; break }
    if ($db[$i] -ne 0x00) {
        $sha256.Dispose()
        Fail "SIGNATURE_INVALID" "PS region contains nonzero byte before 0x01 separator"
    }
}
if ($separatorIndex -lt 0) {
    $sha256.Dispose()
    Fail "SIGNATURE_INVALID" "0x01 separator not found in DB"
}

$actualSaltLen = $dbLen - $separatorIndex - 1
if ($actualSaltLen -ne $saltLength) {
    $sha256.Dispose()
    Fail "SALT_MISMATCH" "recovered salt length $actualSaltLen != declared $saltLength"
}

# M' = 0x00*8 || mHash || salt; H' = SHA-256(M'); compare with H (RFC 8017 step 8).
$salt = [byte[]]$db[($separatorIndex + 1)..($dbLen - 1)]
$mpInput = New-Object System.Collections.Generic.List[byte]
$mpInput.AddRange([byte[]](0,0,0,0,0,0,0,0))
$mpInput.AddRange([byte[]]$computedDigest)
$mpInput.AddRange([byte[]]$salt)
$hPrime = $sha256.ComputeHash($mpInput.ToArray())
$sha256.Dispose()

$hHex = [System.BitConverter]::ToString($H).Replace("-", "").ToLower()
$hPrimeHex = [System.BitConverter]::ToString($hPrime).Replace("-", "").ToLower()
if ($hHex -ne $hPrimeHex) {
    Fail "SIGNATURE_INVALID" "H' mismatch: digest not signed with declared salt length"
}

# --- Step 6: all checks passed ---
Write-Output "PASS $($fields['handle'])"
exit 0
