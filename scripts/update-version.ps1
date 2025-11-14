# Version Update Script for Vijenex Windows CIS Scanner
# Usage: .\scripts\update-version.ps1 -Version "v1.0.2"

param(
    [Parameter(Mandatory=$true)]
    [string]$Version
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Validate version format
if ($Version -notmatch '^v\d+\.\d+\.\d+$') {
    Write-Error "Version must be in format vX.Y.Z (e.g., v1.0.2)"
    exit 1
}

Write-Host "🔄 Updating version to $Version..." -ForegroundColor Cyan

# Update README.md
Write-Host "📝 Updating README.md..." -ForegroundColor Yellow

$readmePath = "README.md"
if (-not (Test-Path $readmePath)) {
    Write-Error "README.md not found in current directory"
    exit 1
}

$content = Get-Content $readmePath -Raw

# Update version references
$content = $content -replace 'archive/refs/tags/v\d+\.\d+\.\d+\.zip', "archive/refs/tags/$Version.zip"
$content = $content -replace 'windows-cis-scanner-\d+\.\d+\.\d+', "windows-cis-scanner-$($Version.Substring(1))"
$content = $content -replace '--branch v\d+\.\d+\.\d+', "--branch $Version"
$content = $content -replace '\*\*Current Version\*\*: v\d+\.\d+\.\d+', "**Current Version**: $Version"
$content = $content -replace '- \*\*v\d+\.\d+\.\d+\*\*', "- **$Version**"

Set-Content -Path $readmePath -Value $content -Encoding UTF8

Write-Host "✅ Version updated to $Version" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Next steps:" -ForegroundColor Cyan
Write-Host "1. Review changes: git diff" -ForegroundColor White
Write-Host "2. Commit changes: git add . && git commit -m 'Update version to $Version'" -ForegroundColor White
Write-Host "3. Create tag: git tag -a $Version -m 'Release $Version'" -ForegroundColor White
Write-Host "4. Push: git push origin main && git push origin $Version" -ForegroundColor White