# install.win verification sample - producer script
# This script is a harmless, read-only sample used to exercise the
# signature verification flow. It installs nothing, writes nothing,
# and performs no network operations.

Write-Output "=== install.win verification sample ==="
Write-Output "PowerShell version:"
$PSVersionTable | Format-Table -AutoSize | Out-String | Write-Output
Write-Output "Machine: $env:COMPUTERNAME  User: $env:USERNAME"
Write-Output "Sample execution complete."
Write-Output "This is a verification sample. It changes nothing."
