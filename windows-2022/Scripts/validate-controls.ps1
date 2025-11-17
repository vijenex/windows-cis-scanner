# Windows Server 2022 CIS Controls Validation Script
# Validates control counts, detects duplicates, and verifies Section 17 controls

param(
    [string]$MilestonesPath = "$PSScriptRoot\..\milestones"
)

Write-Host "`n=== Windows Server 2022 CIS Controls Validation ===" -ForegroundColor Cyan
Write-Host "Validating milestones in: $MilestonesPath`n" -ForegroundColor Gray

# Initialize
$Global:Rules = @()
$allControlIds = @()
$duplicates = @()
$section17Controls = @()

# Load all milestone files
$milestoneFiles = Get-ChildItem -Path $MilestonesPath -Filter "milestone-*.ps1" | Sort-Object Name

Write-Host "Loading milestone files..." -ForegroundColor Yellow
foreach ($file in $milestoneFiles) {
    Write-Host "  - $($file.Name)" -ForegroundColor Gray
    try {
        . $file.FullName
    } catch {
        Write-Host "    ERROR loading $($file.Name): $_" -ForegroundColor Red
    }
}

Write-Host "`nTotal controls loaded: $($Global:Rules.Count)" -ForegroundColor Green

# Extract control IDs and check for duplicates
Write-Host "`nChecking for duplicate control IDs..." -ForegroundColor Yellow
$controlGroups = $Global:Rules | Group-Object -Property Id
foreach ($group in $controlGroups) {
    $allControlIds += $group.Name
    if ($group.Count -gt 1) {
        $duplicates += [PSCustomObject]@{
            ControlId = $group.Name
            Count = $group.Count
        }
    }
}

if ($duplicates.Count -gt 0) {
    Write-Host "  ❌ DUPLICATES FOUND:" -ForegroundColor Red
    $duplicates | ForEach-Object {
        Write-Host "    - $($_.ControlId) appears $($_.Count) times" -ForegroundColor Red
    }
} else {
    Write-Host "  ✅ No duplicates found" -ForegroundColor Green
}

# Validate Section 17 controls
Write-Host "`nValidating Section 17 (Advanced Audit Policy)..." -ForegroundColor Yellow
$section17Controls = $Global:Rules | Where-Object { $_.Id -match '^17\.' } | Sort-Object Id
$section17Count = $section17Controls.Count

Write-Host "  Section 17 controls found: $section17Count" -ForegroundColor $(if ($section17Count -eq 34) { 'Green' } else { 'Red' })

if ($section17Count -eq 34) {
    Write-Host "  ✅ Correct count (expected 34 for CIS 2022)" -ForegroundColor Green
} else {
    Write-Host "  ❌ Incorrect count (expected 34, found $section17Count)" -ForegroundColor Red
}

# List Section 17 controls
Write-Host "`n  Section 17 control IDs:" -ForegroundColor Gray
$section17Controls | ForEach-Object {
    $dcOnly = if ($_.AppliesTo -eq 'DC') { " (DC only)" } else { "" }
    Write-Host "    - $($_.Id): $($_.Title.Substring(0, [Math]::Min(60, $_.Title.Length)))...$dcOnly" -ForegroundColor Gray
}

# Count controls by section
Write-Host "`nControls by section:" -ForegroundColor Yellow
$sections = $Global:Rules | Group-Object { $_.Id -replace '(\d+\.\d+).*', '$1' } | Sort-Object Name
foreach ($section in $sections) {
    $sectionNum = $section.Name
    $count = $section.Count
    Write-Host "  Section $sectionNum : $count controls" -ForegroundColor Gray
}

# Validate new 2022 controls
Write-Host "`nValidating new Windows 2022 controls..." -ForegroundColor Yellow
$new2022Controls = @('18.6.7.1', '18.6.8.2', '18.9.26.1', '18.9.39.1', '18.10.13.3', '18.10.57.3.3.5', '18.10.57.3.3.6', '18.10.57.3.3.7', '18.10.82.2')
$foundNew2022 = @()
$missingNew2022 = @()

foreach ($controlId in $new2022Controls) {
    if ($allControlIds -contains $controlId) {
        $foundNew2022 += $controlId
    } else {
        $missingNew2022 += $controlId
    }
}

Write-Host "  Found: $($foundNew2022.Count)/9" -ForegroundColor $(if ($foundNew2022.Count -eq 9) { 'Green' } else { 'Red' })
if ($missingNew2022.Count -gt 0) {
    Write-Host "  ❌ Missing new 2022 controls:" -ForegroundColor Red
    $missingNew2022 | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
} else {
    Write-Host "  ✅ All new 2022 controls present" -ForegroundColor Green
}

# Summary
Write-Host "`n=== VALIDATION SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total controls: $($Global:Rules.Count)" -ForegroundColor White
Write-Host "Unique control IDs: $($allControlIds.Count)" -ForegroundColor White
Write-Host "Duplicates: $($duplicates.Count)" -ForegroundColor $(if ($duplicates.Count -eq 0) { 'Green' } else { 'Red' })
Write-Host "Section 17 controls: $section17Count (expected 34)" -ForegroundColor $(if ($section17Count -eq 34) { 'Green' } else { 'Red' })
Write-Host "New 2022 controls: $($foundNew2022.Count)/9" -ForegroundColor $(if ($foundNew2022.Count -eq 9) { 'Green' } else { 'Red' })

# Final status
$allGood = ($duplicates.Count -eq 0) -and ($section17Count -eq 34) -and ($foundNew2022.Count -eq 9)
if ($allGood) {
    Write-Host "`n✅ VALIDATION PASSED - Scanner is ready for testing!" -ForegroundColor Green
} else {
    Write-Host "`n❌ VALIDATION FAILED - Issues need to be resolved" -ForegroundColor Red
}

Write-Host ""
