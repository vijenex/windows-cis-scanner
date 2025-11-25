# Add AppliesTo tags to all milestone files based on CSV list
$csvPath = Join-Path (Split-Path $PSScriptRoot) "windows_CIS-Hardening_lIST.csv"
$milestonesPath = Join-Path (Split-Path $PSScriptRoot) "milestones"

# Load CSV controls
$applicableControls = @()
if (Test-Path $csvPath) {
    $content = Get-Content $csvPath -Raw
    $lines = $content -split "`r?`n"
    foreach ($line in $lines) {
        if ($line -match '^(\d+\.\d+\.?\d*\.?\d*):') {
            $applicableControls += $Matches[1]
        }
    }
}

Write-Host "Loaded $($applicableControls.Count) applicable controls from CSV" -ForegroundColor Green

# Process each milestone file
$milestoneFiles = Get-ChildItem -Path $milestonesPath -Filter "milestone-*.ps1" | Where-Object { $_.Name -notmatch '\.backup$' }

foreach ($file in $milestoneFiles) {
    Write-Host "`nProcessing $($file.Name)..." -ForegroundColor Cyan
    
    $content = Get-Content $file.FullPath -Raw
    $updated = $false
    
    # Find all rule definitions
    $pattern = '(\$Global:Rules\s*\+=\s*@\{[^}]+Id\s*=\s*[''"](\d+\.\d+\.?\d*\.?\d*)[''"][^}]+\})'
    
    $newContent = [regex]::Replace($content, $pattern, {
        param($match)
        $fullRule = $match.Groups[1].Value
        $controlId = $match.Groups[2].Value
        
        # Check if AppliesTo already exists
        if ($fullRule -match 'AppliesTo\s*=') {
            return $fullRule
        }
        
        # Determine AppliesTo value
        $appliesTo = if ($applicableControls -contains $controlId) {
            # Check if it's Section 2.3.x (DefaultEnabled)
            if ($controlId -match '^2\.3\.') {
                "'DefaultEnabled'"
            } else {
                "'Applicable'"
            }
        } else {
            "'NotApplicable'"
        }
        
        # Insert AppliesTo before closing brace
        $fullRule -replace '\}$', "; AppliesTo = $appliesTo }"
    })
    
    if ($newContent -ne $content) {
        Set-Content -Path $file.FullPath -Value $newContent -NoNewline
        Write-Host "  ✓ Updated $($file.Name)" -ForegroundColor Green
        $updated = $true
    } else {
        Write-Host "  - No changes needed" -ForegroundColor Gray
    }
}

Write-Host "`n✅ AppliesTo tags added to all milestone files!" -ForegroundColor Green
