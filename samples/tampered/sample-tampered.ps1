# install.win verification sample - TAMPERED variant
#
# WARNING: This is a deliberately broken "bad sample". It exists only to let
# you rehearse the failure path of verify-signature.ps1 locally. The extra
# line below corrupts the digest the signature block claims, and the
# signature block itself contains placeholder (fake) values - it is NOT a
# real publish body and was never signed by any key.

Write-Output "=== install.win verification sample ==="
Write-Output "PowerShell version:"
$PSVersionTable | Format-Table -AutoSize | Out-String | Write-Output
Write-Output "Machine: $env:COMPUTERNAME  User: $env:USERNAME"
Write-Output "TAMPERED: this extra line breaks the digest on purpose."
Write-Output "Sample execution complete."
Write-Output "This is a verification sample. It changes nothing."

# --- install.win SIGNATURE ---
# key-id: 00000000000000000000000000000000
# alg: RSA-PSS/SHA-256/salt=32
# salt: 32
# handle: sample
# sha256: 0000000000000000000000000000000000000000000000000000000000000000
# signed-at: 1970-01-01T00:00:00.000Z
# signature: AAAA
# --- END SIGNATURE ---
