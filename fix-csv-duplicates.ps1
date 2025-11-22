# Fix CSV duplicates and "No One" control bugs
param(
    [Parameter(Mandatory=$true)]
    [string]$CSVPath
)

# Read CSV
$data = Import-Csv -Path $CSVPath -Encoding UTF8

# Group by control ID and take last occurrence (most recent)
$deduped = $data | Group-Object -Property Id | ForEach-Object {
    $_.Group | Select-Object -Last 1
}

# Fix "No One" controls - if ExpectedPrincipals is empty and ActualValue is "Not configured", it should be PASS
$fixed = $deduped | ForEach-Object {
    $row = $_
    
    # List of "No One" control IDs
    $noOneControls = @('2.2.1', '2.2.4', '2.2.15', '2.2.17', '2.2.27', '2.2.29', '2.2.36', '2.2.40', '2.2.48')
    
    if ($noOneControls -contains $row.Id -and $row.ActualValue -like "*Not configured*" -and $row.Status -eq 'FAIL') {
        $row.Status = 'PASS'
        $row.ActualValue = 'No One (Not configured - compliant)'
    }
    
    $row
}

# Export fixed CSV
$fixed | Export-Csv -Path $CSVPath -NoTypeInformation -Encoding UTF8

Write-Host "Fixed: $CSVPath" -ForegroundColor Green
