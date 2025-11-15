# Compare Inspector passing controls with scanner results
# Inspector passing controls that scanner is failing

$inspectorPassing = @(
    '2.2.22', '2.2.23', '2.2.24', '2.2.25', '2.2.27',
    '2.3.1.3', '2.3.1.4', '2.3.7.4', '2.3.7.5',
    '2.3.10.8', '2.3.10.9'
)

Write-Host "Controls that Inspector shows PASSING but scanner shows FAILING:" -ForegroundColor Yellow
Write-Host ""

foreach ($id in $inspectorPassing) {
    Write-Host "Control $id - Check milestone configuration" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "These controls are likely:" -ForegroundColor Green
Write-Host "1. Manual checks (2.3.1.3, 2.3.1.4, 2.3.7.4, 2.3.7.5, 2.3.10.8, 2.3.10.9)" -ForegroundColor White
Write-Host "2. Deny rights that need DefaultValue support (2.2.22-2.2.27)" -ForegroundColor White
Write-Host ""
Write-Host "Solution: Add DefaultValue to these controls in milestone files" -ForegroundColor Green
