<#
  Vijenex Windows CIS Scanner - Unified Entry Point
  Auto-detects Windows version and routes to appropriate scanner
#>

param(
  [string]$OutputDir,
  [string]$Profile = "Level1",
  [string[]]$Milestones,
  [string[]]$Include,
  [string[]]$Exclude,
  [ValidateSet('All','HTML','CSV','PDF','Word')][string[]]$OutputFormat = @('HTML','CSV')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Display Vijenex banner
Write-Host "`n" -ForegroundColor White
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "                        VIJENEX                              " -ForegroundColor Cyan
Write-Host "         Windows CIS Scanner - Auto-Detection Mode          " -ForegroundColor White
Write-Host "           Powered by Vijenex Security Platform             " -ForegroundColor Yellow
Write-Host "        https://github.com/vijenex/windows-cis-scanner       " -ForegroundColor Gray
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "`n" -ForegroundColor White

# Check admin privileges
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "ERROR: This scanner requires Administrator privileges." -ForegroundColor Red
  Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
  exit 1
}

# Detect Windows version
Write-Host "Detecting Windows version..." -ForegroundColor Cyan
$os = Get-CimInstance Win32_OperatingSystem
$build = [int]$os.BuildNumber
$caption = $os.Caption

Write-Host "Detected: $caption (Build $build)" -ForegroundColor Green

# Map build to version
$version = $null
$versionName = $null

if ($build -ge 26100) {
  $version = "2025"
  $versionName = "Windows Server 2025"
} elseif ($build -ge 20348 -and $build -lt 26100) {
  $version = "2022"
  $versionName = "Windows Server 2022"
} elseif ($build -ge 17763 -and $build -lt 20348) {
  $version = "2019"
  $versionName = "Windows Server 2019"
} else {
  Write-Host "`n" -ForegroundColor Red
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "                  UNSUPPORTED VERSION                        " -ForegroundColor Yellow
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "Detected Build: $build" -ForegroundColor Yellow
  Write-Host "`nThis Windows version is not currently supported." -ForegroundColor Red
  Write-Host "`nSupported versions:" -ForegroundColor Yellow
  Write-Host "  - Windows Server 2025 (Build 26100+)" -ForegroundColor White
  Write-Host "  - Windows Server 2019 (Build 17763+)" -ForegroundColor White
  Write-Host "`nWindows Server 2022 support coming soon." -ForegroundColor Gray
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "`n" -ForegroundColor White
  exit 1
}

# Check if scanner exists for this version
$scannerPath = Join-Path $PSScriptRoot "windows-$version\Scripts\vijenex-scanner.ps1"

if (-not (Test-Path $scannerPath)) {
  Write-Host "`n" -ForegroundColor Red
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "                  SCANNER NOT FOUND                          " -ForegroundColor Yellow
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "Version: $versionName" -ForegroundColor Yellow
  Write-Host "Expected path: $scannerPath" -ForegroundColor Yellow
  Write-Host "`nThe scanner for this Windows version is not installed." -ForegroundColor Red
  Write-Host "Please download the complete repository from:" -ForegroundColor Yellow
  Write-Host "https://github.com/vijenex/windows-cis-scanner" -ForegroundColor White
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "`n" -ForegroundColor White
  exit 1
}

# Display routing information
Write-Host "`nRouting to: $versionName Scanner" -ForegroundColor Green
Write-Host "Scanner path: $scannerPath" -ForegroundColor Gray
Write-Host "`n" -ForegroundColor White

# Build parameters for the scanner
$scannerParams = @{
  Profile = $Profile
  OutputFormat = $OutputFormat
}

if ($OutputDir) { $scannerParams['OutputDir'] = $OutputDir }
if ($Milestones) { $scannerParams['Milestones'] = $Milestones }
if ($Include) { $scannerParams['Include'] = $Include }
if ($Exclude) { $scannerParams['Exclude'] = $Exclude }

# Execute the appropriate scanner
try {
  & $scannerPath @scannerParams
  $exitCode = $LASTEXITCODE
  
  Write-Host "`n" -ForegroundColor White
  Write-Host "=============================================================" -ForegroundColor Cyan
  Write-Host "                  SCAN EXECUTION COMPLETE                    " -ForegroundColor Cyan
  Write-Host "=============================================================" -ForegroundColor Cyan
  Write-Host "Scanner: $versionName" -ForegroundColor White
  Write-Host "Exit Code: $exitCode" -ForegroundColor $(if($exitCode -eq 0){"Green"}else{"Yellow"})
  Write-Host "=============================================================" -ForegroundColor Cyan
  Write-Host "`n" -ForegroundColor White
  
  exit $exitCode
} catch {
  Write-Host "`n" -ForegroundColor Red
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "                    SCAN FAILED                              " -ForegroundColor Red
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Yellow
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "`n" -ForegroundColor White
  exit 1
}
