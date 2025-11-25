# Parse controls list CSV and extract control IDs
$csvPath = Join-Path (Split-Path $PSScriptRoot) "windows_CIS-Hardening_lIST.csv"
$controlIds = @()

if (Test-Path $csvPath) {
    $content = Get-Content $csvPath -Raw
    $lines = $content -split "`r?`n"
    
    foreach ($line in $lines) {
        if ($line -match '^(\d+\.\d+\.?\d*\.?\d*):') {
            $controlIds += $Matches[1]
        }
    }
}

Write-Host "Found $($controlIds.Count) controls in CSV"
$controlIds | ForEach-Object { Write-Host $_ }
