# Export Current Server Settings for Manual Verification
# This script exports all security settings to compare with scan results

$OutputFile = ".\reports\current-server-settings.txt"
$TempDir = $env:TEMP

Write-Host "Exporting current server security settings..." -ForegroundColor Cyan
Write-Host ""

$Output = @()

# Header
$Output += "=" * 80
$Output += "CURRENT SERVER SECURITY SETTINGS EXPORT"
$Output += "Server: $env:COMPUTERNAME"
$Output += "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$Output += "=" * 80
$Output += ""

# 1. Export Security Policy
$Output += "=" * 80
$Output += "SECTION 1: SECURITY POLICY (secedit)"
$Output += "=" * 80
$SecEditFile = "$TempDir\secedit-export.inf"
secedit /export /cfg $SecEditFile /quiet 2>&1 | Out-Null
if (Test-Path $SecEditFile) {
    $Output += Get-Content $SecEditFile
    Remove-Item $SecEditFile -Force
}
$Output += ""

# 2. Export Audit Policy
$Output += "=" * 80
$Output += "SECTION 2: AUDIT POLICY (auditpol)"
$Output += "=" * 80
$Output += auditpol /get /category:*
$Output += ""

# 3. Export Registry Settings
$Output += "=" * 80
$Output += "SECTION 3: REGISTRY SETTINGS"
$Output += "=" * 80

$RegistryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
    "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
    "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
    "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
)

foreach ($Path in $RegistryPaths) {
    if (Test-Path $Path) {
        $Output += ""
        $Output += "-" * 80
        $Output += "Registry Path: $Path"
        $Output += "-" * 80
        try {
            Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue | Format-List | Out-String | ForEach-Object { $Output += $_ }
        } catch {
            $Output += "Error reading: $_"
        }
    }
}
$Output += ""

# 4. Export Firewall Settings
$Output += "=" * 80
$Output += "SECTION 4: FIREWALL SETTINGS"
$Output += "=" * 80
$Output += netsh advfirewall show allprofiles
$Output += ""

# 5. Export Services
$Output += "=" * 80
$Output += "SECTION 5: SERVICES STATUS"
$Output += "=" * 80
Get-Service | Where-Object { $_.Name -match "Spooler|WinRM|RDP|RemoteRegistry" } | Format-Table Name, Status, StartType -AutoSize | Out-String | ForEach-Object { $Output += $_ }
$Output += ""

# 6. Export User Rights Assignment (Detailed)
$Output += "=" * 80
$Output += "SECTION 6: USER RIGHTS ASSIGNMENT (Detailed)"
$Output += "=" * 80
$SecEditFile = "$TempDir\secedit-rights.inf"
secedit /export /cfg $SecEditFile /areas USER_RIGHTS /quiet 2>&1 | Out-Null
if (Test-Path $SecEditFile) {
    $Output += Get-Content $SecEditFile | Where-Object { $_ -match "^Se" }
    Remove-Item $SecEditFile -Force
}
$Output += ""

# Save to file
$Output | Out-File -FilePath $OutputFile -Encoding UTF8

Write-Host "Export completed successfully!" -ForegroundColor Green
Write-Host "Output file: $OutputFile" -ForegroundColor Yellow
Write-Host ""
Write-Host "You can now compare this with the CSV scan results to identify false positives."
