# Windows Server 2019 CIS Scanner with Exclusions
# This script runs the scanner and filters out excluded controls

param(
    [string]$ServerName = $env:COMPUTERNAME
)

# Load exclusions
$exclusionFile = Join-Path $PSScriptRoot "..\EXCLUSIONS_2019.txt"
$exclusions = @()
if (Test-Path $exclusionFile) {
    Get-Content $exclusionFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#') -and $line -match '^\d+\.\d+') {
            $exclusions += $line
        }
    }
}

Write-Host "Loaded $($exclusions.Count) exclusions" -ForegroundColor Cyan

# Run scanner
$scannerScript = Join-Path $PSScriptRoot "vijenex-scanner.ps1"
& $scannerScript

# Filter results
$reportDir = Join-Path $PSScriptRoot "..\reports"
$latestReport = Get-ChildItem $reportDir -Filter "*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($latestReport) {
    $results = Import-Csv $latestReport.FullName
    $filtered = $results | Where-Object { $_.'Control ID' -notin $exclusions }
    
    $finalReport = Join-Path $reportDir "FINAL_$($latestReport.Name)"
    $filtered | Export-Csv $finalReport -NoTypeInformation
    
    Write-Host "`n✅ Final report: $finalReport" -ForegroundColor Green
    Write-Host "   Total controls: $($filtered.Count)" -ForegroundColor Cyan
    Write-Host "   Excluded: $($exclusions.Count)" -ForegroundColor Yellow
    Write-Host "   Failed: $(($filtered | Where-Object Status -eq 'Fail').Count)" -ForegroundColor Red
    Write-Host "   Passed: $(($filtered | Where-Object Status -eq 'Pass').Count)" -ForegroundColor Green
}
