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
  [string[]]$Exclude,
  [ValidateSet('All','HTML','CSV','PDF','Word')][string[]]$OutputFormat = @('HTML','CSV')
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
  $cs=Get-CimInstance Win32_ComputerSystem
  $net=Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true} | Select-Object -First 1
  
  # Determine if system is domain-joined or standalone
  $domainRole = $cs.DomainRole
  $osType = switch ($domainRole) {
    0 { "$($os.Caption) (Standalone Workstation)" }
    1 { "$($os.Caption) (Member Workstation)" }
    2 { "$($os.Caption) (Standalone Server)" }
    3 { "$($os.Caption) (Member Server)" }
    4 { "$($os.Caption) (Backup Domain Controller)" }
    5 { "$($os.Caption) (Primary Domain Controller)" }
    default { "$($os.Caption) (Unknown Role)" }
  }
  
  [pscustomobject]@{
    Caption=$osType
    Version=$os.Version
    BuildNumber=[int]$os.BuildNumber
    ComputerName=$env:COMPUTERNAME
    MachineID=$cs.Name
    IPAddress=if($net.IPAddress){$net.IPAddress[0]}else{'N/A'}
    ScanDate=Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  } 
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

function Write-Reports([System.Collections.Generic.List[object]]$Results,[string]$OutDir,[object]$SystemInfo,[string[]]$Formats){
  New-Dir $OutDir
  $csv = Join-Path $OutDir 'cis-results.csv'
  $html = Join-Path $OutDir 'cis-report.html'
  $pdf = Join-Path $OutDir 'cis-report-pdf.html'
  $word = Join-Path $OutDir 'cis-report.rtf'
  $outputs = @{}
  
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
  
  # Generate CSV if requested
  if ($Formats -contains 'All' -or $Formats -contains 'CSV') {
    # Generate CSV with required columns including Passed status
  $csvData = $Results | Select-Object Id, Title, Section, @{Name='Status';Expression={if($_.Passed){'Pass'}else{'Fail'}}}, Passed, Description, Impact, Remediation
  $csvData | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    $outputs['CSV'] = $csv
    Write-Host "CSV:  $csv" -ForegroundColor Green
  }
  
  $total=$Results.Count
  $passed=@($Results|Where-Object{$_.Passed}).Count
  $failed=$total-$passed
  
  $rows = $Results | ForEach-Object {
    $status = if($_.Passed){'&#x2713; Pass'}else{'&#x2717; Fail'}
    $cls = if($_.Passed){'pass-row'}else{'fail-row'}
    $desc = if($_.PSObject.Properties['Description'] -and $_.Description){$_.Description}elseif($_.Type -eq 'PrivRight'){"Expected: $($_.Expected) | Current: $($_.Current)"}else{'N/A'}
    $impact = if($_.PSObject.Properties['Impact'] -and $_.Impact){$_.Impact}elseif($_.Type -eq 'PrivRight'){'User Rights Assignment compliance check'}else{'N/A'}
    "<tr class='$cls'><td><code>$($_.Id)</code></td><td>$($_.Title)</td><td>$($_.Section)</td><td><b>$status</b></td><td class='desc'>$desc</td><td class='impact'>$impact</td><td>$($_.Remediation)</td></tr>"
  }
  
  # Generate HTML if requested
  if ($Formats -contains 'All' -or $Formats -contains 'HTML') {
    $htmlContent = @"
<!doctype html>
<html><head><meta charset="utf-8"/><title>CIS Scan Report - $($SystemInfo.Caption)</title>
<style>body{font-family:Arial,sans-serif;margin:20px}h1{margin-bottom:0}.system-info{background:#f8f9fa;padding:15px;border-radius:5px;margin:15px 0}.system-info h3{margin-top:0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px;text-align:left;font-size:12px}th{background:#f0f0f0}tr.fail-row{background:#ffe6e6}tr.pass-row{background:#e6ffe6}.desc,.impact{max-width:300px;word-wrap:break-word}</style>
</head><body>
<h1>CIS Compliance Audit Report</h1>
<div class="system-info">
<h3>System Information</h3>
<p><strong>Operating System:</strong> $($SystemInfo.Caption)</p>
<p><strong>Version:</strong> $($SystemInfo.Version) (Build $($SystemInfo.BuildNumber))</p>
<p><strong>Computer Name:</strong> $($SystemInfo.ComputerName)</p>
<p><strong>Machine ID:</strong> $($SystemInfo.MachineID)</p>
<p><strong>IP Address:</strong> $($SystemInfo.IPAddress)</p>
<p><strong>Scan Date:</strong> $($SystemInfo.ScanDate)</p>
</div>
<div class="summary"><div>Total checks: <b>$total</b></div><div>Passed: <span class="pass">$passed</span> | Failed: <span class="fail">$failed</span></div></div>
<table><thead><tr><th>ID</th><th>Control</th><th>Section</th><th>Status</th><th>Description</th><th>Impact</th><th>Remediation</th></tr></thead><tbody>
$($rows -join "`n")
</tbody></table>
<p style='margin-top:24px;color:#666;font-size:12px;'>Audit-only; no changes made. Generated by Vijenex Security Platform.</p></body></html>
"@
    Set-Content -Path $html -Value $htmlContent -Encoding UTF8
    $outputs['HTML'] = $html
    Write-Host "HTML: $html" -ForegroundColor Green
  }
  
  # Generate PDF-ready HTML if requested
  if ($Formats -contains 'All' -or $Formats -contains 'PDF') {
    $pdfHtml = @"
<!doctype html>
<html><head><meta charset="utf-8"/><title>CIS Scan Report - $($SystemInfo.Caption)</title>
<style>
@media print {
  body { margin: 0; }
  .no-print { display: none; }
}
body{font-family:Arial,sans-serif;margin:20px;font-size:12px;line-height:1.4}
h1{margin-bottom:10px;color:#333}
.system-info{background:#f8f9fa;padding:15px;border:1px solid #ddd;margin:15px 0;border-radius:5px}
.system-info h3{margin-top:0;font-size:14px;color:#333}
.system-info p{margin:5px 0}
table{border-collapse:collapse;width:100%;margin-top:20px;font-size:11px}
th,td{border:1px solid #333;padding:8px;text-align:left;vertical-align:top}
th{background:#f0f0f0;font-weight:bold}
tr.fail-row{background:#ffe6e6}
tr.pass-row{background:#e6ffe6}
.desc,.impact{max-width:250px;word-wrap:break-word}
.summary{margin:20px 0;padding:15px;background:#f8f9fa;border-radius:5px}
.print-btn{margin:20px 0;padding:10px 20px;background:#007bff;color:white;border:none;border-radius:5px;cursor:pointer;font-size:14px}
.print-btn:hover{background:#0056b3}
</style>
<script>
function printToPDF() {
  window.print();
}
</script>
</head><body>
<div class="no-print">
<button class="print-btn" onclick="printToPDF()">&#x1F5A8; Print to PDF (Ctrl+P)</button>
<p><strong>Instructions:</strong> Click the button above or press Ctrl+P, then select "Save as PDF" as your printer.</p>
</div>
<h1>CIS Compliance Audit Report</h1>
<div class="system-info">
<h3>System Information</h3>
<p><strong>Operating System:</strong> $($SystemInfo.Caption)</p>
<p><strong>Version:</strong> $($SystemInfo.Version) (Build $($SystemInfo.BuildNumber))</p>
<p><strong>Computer Name:</strong> $($SystemInfo.ComputerName)</p>
<p><strong>Machine ID:</strong> $($SystemInfo.MachineID)</p>
<p><strong>IP Address:</strong> $($SystemInfo.IPAddress)</p>
<p><strong>Scan Date:</strong> $($SystemInfo.ScanDate)</p>
</div>
<div class="summary">
<h3>Summary</h3>
<p><strong>Total Checks:</strong> $total</p>
<p><strong>Passed:</strong> $passed</p>
<p><strong>Failed:</strong> $failed</p>
<p><strong>Success Rate:</strong> $([math]::Round(($passed/$total)*100,1))%</p>
</div>
<h3>Detailed Results</h3>
<table>
<thead><tr><th>ID</th><th>Control</th><th>Section</th><th>Status</th><th>Description</th><th>Impact</th><th>Remediation</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody></table>
<div style="margin-top:30px;color:#666;font-size:10px;text-align:center;">
<p>Audit-only scan; no changes made. Generated by Vijenex Security Platform.</p>
<p>Report generated on $($SystemInfo.ScanDate) for $($SystemInfo.ComputerName)</p>
</div>
</body></html>
"@
    Set-Content -Path $pdf -Value $pdfHtml -Encoding UTF8
    $outputs['PDF'] = $pdf
    Write-Host "PDF:  $pdf (Open in browser, click Print to PDF button)" -ForegroundColor Green
  }
  
  # Generate Word-compatible RTF document if requested
  if ($Formats -contains 'All' -or $Formats -contains 'Word') {
    try {
      # Generate RTF (Rich Text Format) - opens in Word without requiring Office
      $rtfContent = @"
{\rtf1\ansi\deff0 {\fonttbl {\f0 Times New Roman;}{\f1 Arial;}}
{\colortbl;\red0\green0\blue0;\red255\green0\blue0;\red0\green128\blue0;}
\f1\fs24\b CIS Compliance Audit Report\b0\par
\par
\fs20\b System Information\b0\par
\fs18 Operating System: $($SystemInfo.Caption)\par
Version: $($SystemInfo.Version) (Build $($SystemInfo.BuildNumber))\par
Computer Name: $($SystemInfo.ComputerName)\par
Machine ID: $($SystemInfo.MachineID)\par
IP Address: $($SystemInfo.IPAddress)\par
Scan Date: $($SystemInfo.ScanDate)\par
\par
\fs20\b Summary\b0\par
\fs18 Total Checks: $total\par
Passed: \cf3 $passed\cf1\par
Failed: \cf2 $failed\cf1\par
Success Rate: $([math]::Round(($passed/$total)*100,1))%\par
\par
\fs20\b Detailed Results\b0\par
\fs16
{\trowd\trgaph108\trleft-108
\cellx1440\cellx3600\cellx4680\cellx5760\cellx8640\cellx11520\cellx14400
\b ID\cell Control\cell Section\cell Status\cell Description\cell Impact\cell Remediation\cell\row}
"@
      
      # Add data rows
      foreach ($result in $Results) {
        $status = if($result.Passed){"Pass"}{"Fail"}
        $desc = if($result.Description){($result.Description -replace '\\','\\\\' -replace '{','\{' -replace '}','\}').Substring(0, [Math]::Min(100, $result.Description.Length)) + "..."}else{"N/A"}
        $impact = if($result.Impact){($result.Impact -replace '\\','\\\\' -replace '{','\{' -replace '}','\}').Substring(0, [Math]::Min(100, $result.Impact.Length)) + "..."}else{"N/A"}
        $remediation = ($result.Remediation -replace '\\','\\\\' -replace '{','\{' -replace '}','\}').Substring(0, [Math]::Min(150, $result.Remediation.Length)) + "..."
        
        $rtfContent += "$($result.Id)\t$($result.Title)\t$($result.Section)\t$status\t$desc\t$impact\t$remediation\par`n"
      }
      
      $rtfContent += @"
\par
\par
\fs14\i Audit-only scan; no changes made. Generated by Vijenex Security Platform.\par
Report generated on $($SystemInfo.ScanDate) for $($SystemInfo.ComputerName)\i0
}
"@
      
      Set-Content -Path $word -Value $rtfContent -Encoding ASCII
      $outputs['Word'] = $word
      Write-Host "Word: $word (RTF format - opens in Word/LibreOffice)" -ForegroundColor Green
    } catch {
      Write-Warning "Word document generation failed: $($_.Exception.Message)"
    }
  }
  
  return $outputs
}

# ===== MAIN EXECUTION =====
Assert-Admin
New-Dir $OutputDir

# Display Verityx CLI signature
Write-Host "`n" -ForegroundColor White
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "                        VIJENEX                              " -ForegroundColor Cyan
Write-Host "      Windows Server 2025 CIS Compliance Scanner           " -ForegroundColor White
Write-Host "                 (Standalone/Workgroup)                     " -ForegroundColor White
Write-Host "           Powered by Vijenex Security Platform             " -ForegroundColor Yellow
Write-Host "        https://github.com/vijenex/windows-cis-scanner       " -ForegroundColor Gray
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "`n" -ForegroundColor White

$systemInfo=Get-OSInfo
Write-Host "Scanning host: $($systemInfo.Caption) ($($systemInfo.Version) build $($systemInfo.BuildNumber))" -ForegroundColor Cyan
Write-Host "Machine: $($systemInfo.ComputerName) | IP: $($systemInfo.IPAddress) | Date: $($systemInfo.ScanDate)" -ForegroundColor Gray

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

# Handle output format parameter
if ($OutputFormat -contains 'All') {
  $formats = @('HTML','CSV','PDF','Word')
} else {
  $formats = $OutputFormat
}

# Generate reports
$paths = Write-Reports -Results $results -OutDir $OutputDir -SystemInfo $systemInfo -Formats $formats

# Cleanup
if (Test-Path $seceditPath) { Remove-Item $seceditPath -Force -ErrorAction SilentlyContinue }

exit (@($results | Where-Object { -not $_.Passed }).Count)
