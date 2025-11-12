<#
  Windows Server 2025 CIS-style Scanner (Audit-only)
  - Loads all *.ps1 rule packs from ../milestones (unless -Milestones passed)
  - Reads live settings via `secedit` and `auditpol`
  - Writes HTML + CSV to -OutputDir (defaults ../reports)
  - No remediation; audit-only
#>

param(
  [string]$OutputDir = (Join-Path $PSScriptRoot "reports"),
  [string]$Profile = "Level1",
  [string[]]$Milestones,
  [string[]]$Include,
  [string[]]$Exclude
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Global:Rules = @()

# ===== ALL FUNCTIONS DEFINED FIRST =====
function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $pr = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
  }
}

function New-Dir([string]$Path){ 
  if (-not (Test-Path $Path)) { [void](New-Item -ItemType Directory -Path $Path) } 
}

function Get-OSInfo { 
  $os=Get-CimInstance Win32_OperatingSystem
  [pscustomobject]@{Caption=$os.Caption;Version=$os.Version;BuildNumber=[int]$os.BuildNumber} 
}

function Export-SecEdit { 
  $tmp=Join-Path $env:TEMP ("secpol-"+[guid]::NewGuid().Guid+".inf")
  secedit /export /cfg $tmp 2>$null | Out-Null
  $tmp 
}

function Parse-InfFile([string]$Path){
  $map=@{}
  if (-not (Test-Path $Path)) { return $map }
  $section=''
  foreach($line in Get-Content -LiteralPath $Path){
    $t=$line.Trim()
    if (-not $t -or $t.StartsWith(';')){continue}
    if ($t.StartsWith('[')){
      $section=$t.Trim('[',']')
      if (-not $map.ContainsKey($section)){$map[$section]=@{}}
      continue
    }
    $kv=$t -split '=',2
    if ($kv.Count -eq 2){ 
      $map[$section][$kv[0].Trim()] = $kv[1].Trim() 
    }
  }
  $map
}

# ===== Helpers for User Rights (Privilege Rights) =====
function Split-PrivilegeValue {
  param([string]$Raw)
  if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
  $parts = $Raw -split '\s*,\s*' | Where-Object { $_ -and $_.Trim() -ne '' }
  return $parts | ForEach-Object { $_.Trim() }
}

function Resolve-Principal {
  param([string]$Tok)
  try {
    $t = $Tok.Trim().TrimStart('*')
    if ($t -match '^S-\d-\d+-.+$') {
      $sid = New-Object System.Security.Principal.SecurityIdentifier($t)
      $acc = $sid.Translate([System.Security.Principal.NTAccount])
      return ($acc.Value.ToUpperInvariant())
    } else {
      return ($t.ToUpperInvariant())
    }
  } catch {
    return ($Tok.Trim().TrimStart('*').ToUpperInvariant())
  }
}

function Normalize-PrincipalSet {
  param([string[]]$Tokens)
  $hs = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($x in ($Tokens | Where-Object { $_ })) {
    [void]$hs.Add( (Resolve-Principal $x) )
  }
  return $hs
}

function Compare-StringSets {
  param([System.Collections.Generic.HashSet[string]]$Current,
        [System.Collections.Generic.HashSet[string]]$Expected,
        [ValidateSet('Exact','Superset')] [string]$Mode = 'Exact')
  switch ($Mode) {
    'Exact' {
      if ($Current.Count -ne $Expected.Count) { return $false }
      foreach ($e in $Expected) { if (-not $Current.Contains($e)) { return $false } }
      return $true
    }
    'Superset' {
      foreach ($e in $Expected) { if (-not $Current.Contains($e)) { return $false } }
      return $true
    }
  }
}

function Get-PrivilegeRaw {
  param([hashtable]$SecEditMap, [string]$Key)
  if ($SecEditMap.ContainsKey('Privilege Rights') -and $SecEditMap['Privilege Rights'].ContainsKey($Key)) {
    return $SecEditMap['Privilege Rights'][$Key]
  }
  return $null
}

function Get-AuditPolicies {
  $map = @{}
  try {
    $raw = & auditpol.exe /get /subcategory:* 2>&1
    if ($LASTEXITCODE -ne 0) { return $map }
    
    foreach ($ln in $raw) {
      if (-not $ln) { continue }
      $t = "$ln".Trim()
      
      # Skip headers and category lines
      if ($t -match '^\s*(System audit policy|Category|Subcategory|Machine Name|Policy Target|---|^\s*$)') { continue }
      if ($t -match '^\s*\w+/\w+\s*$') { continue }
      
      # Match: name + 2+ spaces + setting
      if ($t -match '^\s*(.+?)\s{2,}([^\s].+?)\s*$') {
        $name = $matches[1].Trim()
        $val = $matches[2].Trim()
        
        # Normalize values
        switch -Regex ($val) {
          '^(Success\s*and\s*Failure)$' { $val = 'Success and Failure' }
          '^(Success)$' { $val = 'Success' }
          '^(Failure)$' { $val = 'Failure' }
          '^(No Auditing|None)$' { $val = 'No Auditing' }
        }
        
        if ($name) { $map[$name] = $val }
      }
    }
  } catch { }
  return $map
}

function Test-Compare {
  param([Parameter(Mandatory)]$Current,[Parameter(Mandatory)]$Expected,[ValidateSet('Equals','NotEquals','GreaterOrEqual','LessOrEqual')]$Operator)
  
  if ($null -eq $Current) { return $false }
  
  switch ($Operator) {
    'Equals' { $Current -eq $Expected }
    'NotEquals' { $Current -ne $Expected }
    'GreaterOrEqual' { 
      try { [double]$Current -ge [double]$Expected } 
      catch { $false }
    }
    'LessOrEqual' { 
      try { [double]$Current -le [double]$Expected } 
      catch { $false }
    }
  }
}

function Evaluate-Rule([hashtable]$Rule,[hashtable]$Context){
  $result=[pscustomobject]@{
    Id=$Rule.Id
    Title=$Rule.Title
    Section=$Rule.Section
    Profile=$Rule.Profile

    Type=$Rule.Type
    Expected=''
    Current=''
    Passed=$false
    Evidence=''
    Remediation=$Rule.Remediation
    Description=if($Rule.ContainsKey('Description')){$Rule.Description}else{$null}
    Impact=if($Rule.ContainsKey('Impact')){$Rule.Impact}else{$null}
  }
  
  try{
    switch ($Rule.Type){
      'SecEdit' {
        $secpol=$Context.SecEdit
        $section=$Rule.SectionName
        $key=$Rule.Key
        $val = if ($secpol.ContainsKey($section) -and $secpol[$section].ContainsKey($key)){ 
          $secpol[$section][$key] 
        } else { 
          $null 
        }
        
        $result.Current = if ($null -eq $val){'<unset>'} else { $val }
        $result.Expected = "$($Rule.Operator) $($Rule.Expected)"
        $result.Passed = Test-Compare -Current $val -Expected $Rule.Expected -Operator $Rule.Operator
        $result.Evidence = "[$section] $key"
      }
      
      'AuditPolicy' {
        $ap=$Context.AuditPolicies
        $sub=$Rule.Subcategory
        $val = if ($ap.ContainsKey($sub)) { $ap[$sub] } else { $null }
        
        $result.Current = if ($null -eq $val){'<unset>'} else { $val }
        $result.Expected = $Rule.Expected
        $result.Passed = ($val -ieq $Rule.Expected)
        $result.Evidence = "auditpol:$sub"
      }
      
      'Composite' {
        $parts=@()
        $ev=@()
        $ok=$true
        $secpol=$Context.SecEdit
        
        foreach($sub in $Rule.AllOf){
          $section=$sub.SectionName
          $key=$sub.Key
          $val = if ($secpol.ContainsKey($section) -and $secpol[$section].ContainsKey($key)){ 
            $secpol[$section][$key] 
          } else { 
            $null 
          }
          
          $pass = Test-Compare -Current $val -Expected $sub.Expected -Operator $sub.Operator
          $ok = $ok -and $pass
          $parts += "$key $($sub.Operator) $($sub.Expected) => current:$val => $([string]$pass)"
          $ev += "[$section] $key"
        }
        
        $result.Passed=$ok
        $result.Expected=($parts -join '; ')
        $result.Current=''
        $result.Evidence=($ev|Select-Object -Unique) -join ', '
      }
      
      'PrivRight' {
        $raw = Get-PrivilegeRaw -SecEditMap $Context.SecEdit -Key $Rule.Key
        $curTokens = Split-PrivilegeValue -Raw $raw
        $curSet = Normalize-PrincipalSet -Tokens $curTokens
        $expSet = Normalize-PrincipalSet -Tokens $Rule.ExpectedPrincipals
        $mode = if ($Rule.SetMode) { $Rule.SetMode } else { 'Exact' }

        $result.Current = if ($curTokens.Count -gt 0) { ($curTokens -join ', ') } else { '<none>' }
        $result.Expected = ($Rule.ExpectedPrincipals -join ', ')
        $result.Passed = Compare-StringSets -Current $curSet -Expected $expSet -Mode $mode
        $result.Evidence = "[Privilege Rights] $($Rule.Key)"
      }
      
      'Registry' {
        try {
          $regPath = $Rule.Key
          $valueName = $Rule.ValueName
          $expectedValue = $Rule.Expected
          
          if (Test-Path $regPath) {
            $currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $valueName -ErrorAction SilentlyContinue
            if ($null -ne $currentValue) {
              $result.Current = $currentValue
              $result.Passed = ($currentValue -eq $expectedValue)
            } else {
              $result.Current = '<not set>'
              $result.Passed = $false
            }
          } else {
            $result.Current = '<key not found>'
            $result.Passed = $false
          }
          
          $result.Expected = $expectedValue
          $result.Evidence = "$regPath\$valueName"
        } catch {
          $result.Current = "<error: $($_.Exception.Message)>"
          $result.Passed = $false
          $result.Evidence = 'registry-error'
        }
      }
      
      'Manual' { 
        $result.Current='<manual-review>'
        $result.Expected=$Rule.Expected
        $result.Passed=$false
        $result.Evidence=$Rule.Evidence 
      }
      
      default { 
        $result.Current='<unsupported>'
        $result.Passed=$false 
      }
    }
  } catch { 
    $result.Current="<error: $($_.Exception.Message)>"
    $result.Passed=$false
    $result.Evidence='exception' 
  }
  
  $result
}

function Write-Reports([System.Collections.Generic.List[object]]$Results,[string]$OutDir){
  New-Dir $OutDir
  $csv = Join-Path $OutDir 'cis-results.csv'
  $html = Join-Path $OutDir 'cis-report.html'
  
  # Copy CIS documentation if available
  $docFolder = Join-Path (Split-Path $PSScriptRoot) "documentation"
  if (Test-Path $docFolder) {
    $cisDoc = Get-ChildItem -Path $docFolder -Filter "*.pdf" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cisDoc) {
      $destDoc = Join-Path $OutDir $cisDoc.Name
      Copy-Item -Path $cisDoc.FullName -Destination $destDoc -Force -ErrorAction SilentlyContinue
      Write-Host "CIS Documentation: $destDoc" -ForegroundColor Green
    }
  }
  
  $Results | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
  
  $total=$Results.Count
  $passed=@($Results|Where-Object{$_.Passed}).Count
  $failed=$total-$passed
  
  $rows = $Results | ForEach-Object {
    $status = if($_.Passed){'✓ Pass'}else{'✗ Fail'}
    $cls = if($_.Passed){'pass-row'}else{'fail-row'}
    $desc = if($_.PSObject.Properties['Description'] -and $_.Description){$_.Description}elseif($_.Type -eq 'PrivRight'){"Expected: $($_.Expected) | Current: $($_.Current)"}else{'N/A'}
    $impact = if($_.PSObject.Properties['Impact'] -and $_.Impact){$_.Impact}elseif($_.Type -eq 'PrivRight'){'User Rights Assignment compliance check'}else{'N/A'}
    "<tr class='$cls'><td><code>$($_.Id)</code></td><td>$($_.Title)</td><td>$($_.Section)</td><td><b>$status</b></td><td class='desc'>$desc</td><td class='impact'>$impact</td><td>$($_.Remediation)</td></tr>"
  }
  
  $htmlContent = @"
<!doctype html>
<html><head><meta charset="utf-8"/><title>CIS Scan Report - Windows Server 2025</title>
<style>body{font-family:Arial,sans-serif;margin:20px}h1{margin-bottom:0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px;text-align:left;font-size:12px}th{background:#f0f0f0}tr.fail-row{background:#ffe6e6}tr.pass-row{background:#e6ffe6}.desc,.impact{max-width:300px;word-wrap:break-word}</style>
</head><body>
<h1>CIS Scan</h1>
<div class="meta">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Host: $env:COMPUTERNAME</div>
<div class="summary"><div>Total checks: <b>$total</b></div><div>Passed: <span class="pass">$passed</span> | Failed: <span class="fail">$failed</span></div></div>
<table><thead><tr><th>ID</th><th>Control</th><th>Section</th><th>Status</th><th>Description</th><th>Impact</th><th>Remediation</th></tr></thead><tbody>
$($rows -join "`n")
</tbody></table>
<p style='margin-top:24px;color:#666;font-size:12px;'>Audit-only; no changes made.</p></body></html>
"@
  
  Set-Content -Path $html -Value $htmlContent -Encoding UTF8
  [pscustomobject]@{Csv=$csv; Html=$html}
}

# ===== MAIN EXECUTION =====
Assert-Admin
New-Dir $OutputDir

# Display Verityx CLI signature
Write-Host "`n" -ForegroundColor White
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "                        VERITYX                              " -ForegroundColor Cyan
Write-Host "      Windows Server 2025 CIS Compliance Scanner           " -ForegroundColor White
Write-Host "                 (Standalone/Workgroup)                     " -ForegroundColor White
Write-Host "           Powered by Verityx Security Platform             " -ForegroundColor Yellow
Write-Host "     https://github.com/satishk8s/Windows-Server-CIS-Audit  " -ForegroundColor Gray
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "`n" -ForegroundColor White

$os=Get-OSInfo
Write-Host "Scanning host: $($os.Caption) ($($os.Version) build $($os.BuildNumber))" -ForegroundColor Cyan

# Load milestones (all if not specified)
$milestoneFolder = Join-Path (Split-Path $PSScriptRoot) "milestones"
if (-not $Milestones -or $Milestones.Count -eq 0) {
  $Milestones = Get-ChildItem -Path $milestoneFolder -Filter *.ps1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
}

foreach ($m in $Milestones) {
  $p = Join-Path $milestoneFolder $m
  if (Test-Path $p) { 
    Write-Host "Loading $m ..." -ForegroundColor Cyan
    . $p 
  } else { 
    Write-Warning "Milestone not found: $m" 
  }
}

Write-Host "Loaded rules: $($Global:Rules.Count)" -ForegroundColor Yellow

# Get system data
$seceditPath = Export-SecEdit
$secMap = Parse-InfFile -Path $seceditPath
$auditMap = Get-AuditPolicies
$ctx = @{ SecEdit=$secMap; AuditPolicies=$auditMap }

# Filter rules
$rules = $Global:Rules
if ($Profile){ 
  $rules = $rules | Where-Object { $_.Profile -eq $Profile } 
}
if ($Include){ 
  $hi=[System.Collections.Generic.HashSet[string]]::new($Include,[System.StringComparer]::OrdinalIgnoreCase)
  $rules = $rules | Where-Object { $hi.Contains($_.Id) } 
}
if ($Exclude){ 
  $hx=[System.Collections.Generic.HashSet[string]]::new($Exclude,[System.StringComparer]::OrdinalIgnoreCase)
  $rules = $rules | Where-Object { -not $hx.Contains($_.Id) } 
}
$rules = @($rules)

Write-Host "Evaluating $($rules.Count) rules..." -ForegroundColor Cyan

# Evaluate rules
$results = New-Object System.Collections.Generic.List[object]
foreach($rule in $rules){ 
  $result = Evaluate-Rule -Rule $rule -Context $ctx
  $results.Add($result)
}

# Generate reports
$paths = Write-Reports -Results $results -OutDir $OutputDir
Write-Host "CSV:  $($paths.Csv)" -ForegroundColor Green
Write-Host "HTML: $($paths.Html)" -ForegroundColor Green

# Cleanup
if (Test-Path $seceditPath) { Remove-Item $seceditPath -Force -ErrorAction SilentlyContinue }

exit (@($results | Where-Object { -not $_.Passed }).Count)
