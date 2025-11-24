<#
  Windows Server 2019 CIS-style Scanner (Audit-only)
  - Loads all *.ps1 rule packs from ../milestones (unless -Milestones passed)
  - Reads live settings via `secedit` and `auditpol`
  - Writes HTML + CSV to -OutputDir (defaults ../reports)
  - No remediation; audit-only
#>

param(
  [string]$OutputDir,
  [string]$Profile = "Level1",
  [string[]]$Milestones,
  [string[]]$Include,
  [string[]]$Exclude,
  [ValidateSet('All','HTML','CSV','PDF','Word')][string[]]$OutputFormat = @('HTML','CSV')
)

# Set default output directory to reports folder in parent directory
if (-not $OutputDir) {
  $OutputDir = Join-Path (Split-Path $PSScriptRoot) "reports"
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Global:Rules = @()

# Import effective policy module
$effectivePolicyModule = Join-Path $PSScriptRoot "Get-EffectivePolicy.ps1"
if (Test-Path $effectivePolicyModule) {
  . $effectivePolicyModule
  Write-Verbose "Loaded effective policy module"
}

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
  try {
    $tmp = Join-Path $env:TEMP ("secpol-" + [guid]::NewGuid().Guid + ".inf")
    
    # Validate temp path to prevent path traversal
    $resolvedPath = [System.IO.Path]::GetFullPath($tmp)
    if (-not $resolvedPath.StartsWith([System.IO.Path]::GetTempPath())) {
      throw "Invalid temp path detected"
    }
    
    $errFile = Join-Path $env:TEMP ("secpol-err-" + [guid]::NewGuid().Guid + ".txt")
    $result = Start-Process -FilePath "secedit.exe" -ArgumentList "/export", "/cfg", "`"$tmp`"" -Wait -PassThru -NoNewWindow -RedirectStandardError $errFile
    
    if ($result.ExitCode -ne 0) {
      $errContent = if (Test-Path $errFile) { Get-Content $errFile -Raw } else { "Unknown error" }
      Remove-Item $errFile -Force -ErrorAction SilentlyContinue
      throw "secedit export failed with exit code $($result.ExitCode): $errContent"
    }
    
    Remove-Item $errFile -Force -ErrorAction SilentlyContinue
    
    if (-not (Test-Path $tmp)) {
      throw "secedit export did not create expected file"
    }
    
    return $tmp
  } catch {
    Write-Warning "Failed to export security policy: $($_.Exception.Message)"
    return $null
  }
}

function Parse-InfFile([string]$Path){
  $map=@{}
  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path $Path)) { return $map }
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
  if ($parts) {
    return @($parts | ForEach-Object { $_.Trim() })
  }
  return @()
}

function Resolve-Principal {
  param([string]$Tok)
  try {
    $t = $Tok.Trim().TrimStart('*')
    $wellKnown = @{
      'S-1-5-32-544'='BUILTIN\Administrators';'S-1-5-32-545'='BUILTIN\Users'
      'S-1-5-32-546'='BUILTIN\Guests';'S-1-5-19'='NT AUTHORITY\LOCAL SERVICE'
      'S-1-5-20'='NT AUTHORITY\NETWORK SERVICE';'S-1-5-6'='NT AUTHORITY\SERVICE'
      'S-1-5-11'='NT AUTHORITY\Authenticated Users';'S-1-5-83-0'='NT VIRTUAL MACHINE\Virtual Machines'
      'S-1-5-90-0'='Window Manager\Window Manager Group'
    }
    if($wellKnown.ContainsKey($t)){return $wellKnown[$t].ToUpperInvariant()}
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
  if ($Tokens) {
    foreach ($x in ($Tokens | Where-Object { $_ })) {
      [void]$hs.Add( (Resolve-Principal $x) )
    }
  }
  return $hs
}

function Compare-StringSets {
  param([System.Collections.Generic.HashSet[string]]$Current,
        [System.Collections.Generic.HashSet[string]]$Expected,
        [ValidateSet('Exact','Superset')] [string]$Mode = 'Exact')
  if ($null -eq $Current -or $null -eq $Expected) { return $false }
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
    # Use auditpol /get /category:* to get all policies at once (more reliable)
    $auditOutput = auditpol /get /category:* 2>$null | Out-String
    
    # Parse line by line to extract subcategory and setting
    $lines = $auditOutput -split "`n"
    foreach ($line in $lines) {
      # Match lines with subcategory name followed by setting (2+ spaces separator)
      # Example: "  Credential Validation                    Success and Failure"
      if ($line -match '^\s+(.+?)\s{2,}(.+)$') {
        $subcatName = $Matches[1].Trim()
        $setting = $Matches[2].Trim()
        
        # Only add if setting is valid (not empty and not a category header)
        if ($setting -and $setting -notmatch '^(Security|Account|Detailed|DS|Logon|Object|Policy|Privilege|System)') {
          $map[$subcatName] = $setting
        }
      }
    }
  } catch {
    Write-Warning "Failed to get audit policies: $($_.Exception.Message)"
  }
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
    Status=''
    Profile=$Rule.Profile
    Type=$Rule.Type
    Passed=$false
    CISReference=if($Rule.ContainsKey('CISReference')){$Rule.CISReference}else{'Refer to CIS Benchmark documentation'}
    Remediation=''
    Description=''
    EvidenceCommand=''
    ActualValue=''
  }
  
  try{
    switch ($Rule.Type){
      'SecEdit' {
        # Try to get effective value from registry first (more accurate)
        $val = $null
        $fromRegistry = $false
        
        # Map common SecEdit settings to registry paths
        $registryMap = @{
          'LimitBlankPasswordUse' = @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='LimitBlankPasswordUse'}
          'ForceLogoffWhenHourExpire' = @{Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name='EnableForcedLogoff'}
          'ClearTextPassword' = @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='ClearTextPassword'}
          'NoLMHash' = @{Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='NoLMHash'}
        }
        
        if ($registryMap.ContainsKey($Rule.Key) -and (Get-Command Get-EffectiveSecurityOption -ErrorAction SilentlyContinue)) {
          $regInfo = $registryMap[$Rule.Key]
          $val = Get-EffectiveSecurityOption -Path $regInfo.Path -Name $regInfo.Name
          if ($null -ne $val) {
            $fromRegistry = $true
          }
        }
        
        # Fallback to secedit if registry not available
        if (-not $fromRegistry) {
          $secpol=$Context.SecEdit
          $section=$Rule.SectionName
          $key=$Rule.Key
          if ($secpol.ContainsKey($section) -and $secpol[$section].ContainsKey($key)) {
            $rawVal = $secpol[$section][$key]
            # Handle empty strings and whitespace - treat as null
            if ([string]::IsNullOrWhiteSpace($rawVal) -or $rawVal -eq '') {
              $val = $null
            } else {
              $val = $rawVal.Trim()
            }
          } else {
            $val = $null
          }
        }
        
        $defaultValue = if ($Rule.ContainsKey('DefaultValue')) { $Rule.DefaultValue } else { $null }
        
        # Use default value if actual value is null
        $compareValue = if ($null -eq $val -and $null -ne $defaultValue) { $defaultValue } else { $val }
        
        # Perform comparison
        if ($null -ne $compareValue) {
          $result.Passed = Test-Compare -Current $compareValue -Expected $Rule.Expected -Operator $Rule.Operator
        } else {
          $result.Passed = $false
        }
        
        # Format ActualValue with human-readable explanation
        if ($null -ne $val) {
          if ($val -match '^\d+$' -and ([int]$val -eq 0 -or [int]$val -eq 1)) {
            $result.ActualValue = "$val (" + $(if([int]$val -eq 1){"Enabled"}else{"Disabled"}) + ")"
          } else {
            $result.ActualValue = $val
          }
        } elseif ($null -ne $defaultValue) {
          $result.ActualValue = "Not configured (using default: $defaultValue)"
        } else {
          $result.ActualValue = "Not configured (policy not set)"
        }
        
        $result.EvidenceCommand = "secedit /export /cfg temp.cfg"
        $result.Remediation = if ($Rule.Remediation) { $Rule.Remediation } else { 'Configure via Local Security Policy or Group Policy' }
        $result.Description = "Security policy setting verified via secedit export. Value shown is the effective policy."
      }
      
      'AuditPolicy' {
        $ap=$Context.AuditPolicies
        $sub=$Rule.Subcategory
        $val = if ($ap.ContainsKey($sub)) { $ap[$sub] } else { 'No Auditing' }
        
        # Handle 'include' syntax (e.g., "include Success" means Success OR Success and Failure)
        $includeMatch = $Rule.Expected -match '^include\s+(.+)$'
        if ($includeMatch) {
          $requiredSetting = $Matches[1].Trim()
          if ($val -ieq 'Success and Failure') {
            $result.Passed = $true
          } elseif ($val -ieq $requiredSetting) {
            $result.Passed = $true
          } else {
            $result.Passed = $false
          }
        } else {
          # Exact match or "Success and Failure" satisfies Success/Failure requirement
          if ($val -ieq $Rule.Expected) {
            $result.Passed = $true
          } elseif ($val -ieq 'Success and Failure') {
            $result.Passed = ($Rule.Expected -ieq 'Success' -or $Rule.Expected -ieq 'Failure')
          } else {
            $result.Passed = $false
          }
        }
        
        $result.ActualValue = $val
        $result.EvidenceCommand = "auditpol /get /subcategory:`"$sub`""
        $result.Remediation = if ($Rule.Remediation) { $Rule.Remediation } else { "Configure via Advanced Audit Policy Configuration" }
        $result.Description = "⚠️ IMPORTANT NOTE: This scanner uses 'auditpol' command to read the EFFECTIVE audit policy (Advanced Audit Policy). " +
          "If you check through Local Security Policy GUI (secpol.msc → Local Policies → Audit Policy), it may show 'Not Configured' or different values. " +
          "This is NORMAL because Windows has TWO audit systems: Legacy (shown in GUI) and Advanced (effective policy). " +
          "When Advanced Audit Policy is configured (via GPO or auditpol command), it OVERRIDES the Legacy policy shown in GUI. " +
          "Always verify using 'auditpol /get /category:*' command to see what's actually enforced. " +
          "The scanner reports the ACTUAL effective policy, not the GUI display."
      }
      
      'Composite' {
        $parts=@()
        $ev=@()
        $ok=$true
        $secpol=$Context.SecEdit
        $defaultValue = if ($Rule.ContainsKey('DefaultValue')) { $Rule.DefaultValue } else { $null }
        
        foreach($sub in $Rule.AllOf){
          $section=$sub.SectionName
          $key=$sub.Key
          $subDefault = if ($sub.ContainsKey('DefaultValue')) { $sub.DefaultValue } else { $defaultValue }
          $val = if ($secpol.ContainsKey($section) -and $secpol[$section].ContainsKey($key)){ 
            $secpol[$section][$key] 
          } else { 
            $null 
          }
          if ($null -eq $val -and $null -ne $subDefault) { $val = $subDefault }
          
          $pass = Test-Compare -Current $val -Expected $sub.Expected -Operator $sub.Operator
          $ok = $ok -and $pass
          $parts += "$key $($sub.Operator) $($sub.Expected) => current:$val => $([string]$pass)"
          $ev += "[$section] $key"
        }
        
        $result.Passed=$ok
        $result.Remediation = if ($Rule.Remediation) { $Rule.Remediation } else { 'Configure multiple related settings' }
        $result.Description = "Composite check verifying multiple related security settings."
      }
      
      'PrivRight' {
        try {
          $raw = Get-PrivilegeRaw -SecEditMap $Context.SecEdit -Key $Rule.Key
          $defaultValue = if ($Rule.ContainsKey('DefaultValue')) { $Rule.DefaultValue } else { $null }
          
          # Get current tokens from secedit
          $curTokens = @()
          if ($raw) {
            $curTokens = @(Split-PrivilegeValue -Raw $raw)
          } elseif ($null -ne $defaultValue) {
            # If privilege doesn't exist and DefaultValue is defined, use DefaultValue
            $curTokens = @($defaultValue)
          }
          
          # Normalize both current and expected principals to resolved names
          $curSet = Normalize-PrincipalSet -Tokens $curTokens
          $expSet = Normalize-PrincipalSet -Tokens $Rule.ExpectedPrincipals
          $mode = if ($Rule.SetMode) { $Rule.SetMode } else { 'Exact' }
          
          # Special case: If expected is empty (No One) and current is empty, that's a PASS
          $curSetArray = @($curSet)
          $expSetArray = @($expSet)
          if ($curSetArray.Count -eq 0 -and $expSetArray.Count -eq 0) {
            $result.Passed = $true
          } else {
            # Use the Compare-StringSets function which properly handles HashSet comparison
            $result.Passed = Compare-StringSets -Current $curSet -Expected $expSet -Mode $mode
          }
          
          # Show resolved names in ActualValue for better readability
          $curSetArray = @($curSet)
          if ($curSetArray.Count -gt 0) {
            $resolvedNames = @($curSetArray | Sort-Object)
            $result.ActualValue = $resolvedNames -join ', '
          } else {
            $result.ActualValue = "Not configured (No principals assigned)"
          }
          
          $result.EvidenceCommand = "secedit /export /cfg temp.cfg"
          $result.Remediation = if ($Rule.Remediation) { $Rule.Remediation } else { 
            "Navigate to: Local Security Policy → Local Policies → User Rights Assignment → $($Rule.Key)" 
          }
          $result.Description = "User rights assignment verified via secedit export. Principals are resolved to account names for accurate comparison."
        } catch {
          $result.Passed = $false
          $result.ActualValue = "Error: $($_.Exception.Message)"
          $result.EvidenceCommand = "secedit /export /cfg temp.cfg"
          $result.Remediation = if ($Rule.Remediation) { $Rule.Remediation } else { 'Error reading privilege' }
          $result.Description = "Error occurred while checking user rights assignment: $($_.Exception.Message)"
        }
      }
      
      'Firewall' {
        try {
          $profileName = $Rule.ProfileName  # Domain, Private, or Public
          $propertyName = $Rule.PropertyName
          $expectedValue = $Rule.Expected
          $operator = if ($Rule.ContainsKey('Operator')) { $Rule.Operator } else { 'Equals' }
          
          $fw = Get-NetFirewallProfile -Name $profileName -ErrorAction Stop
          $currentValue = $fw.$propertyName
          
          $result.Passed = Test-Compare -Current $currentValue -Expected $expectedValue -Operator $operator
          
          # Format ActualValue
          if ($null -ne $currentValue) {
            if ($currentValue -is [bool]) {
              $result.ActualValue = "$currentValue (" + $(if($currentValue){"Enabled"}else{"Disabled"}) + ")"
            } else {
              $result.ActualValue = $currentValue.ToString()
            }
          } else {
            $result.ActualValue = "Not configured"
          }
          
          $result.EvidenceCommand = "Get-NetFirewallProfile -Name $profileName | Select-Object $propertyName"
          $result.Remediation = if ($Rule.Remediation) { $Rule.Remediation } else { 
            "Set-NetFirewallProfile -Name $profileName -$propertyName $expectedValue" 
          }
          $result.Description = "Firewall profile setting verified via Get-NetFirewallProfile cmdlet."
        } catch {
          $result.Passed = $false
          $result.ActualValue = "Error: $($_.Exception.Message)"
          $result.EvidenceCommand = "Get-NetFirewallProfile -Name $($Rule.ProfileName)"
          $result.Remediation = if ($Rule.Remediation) { $Rule.Remediation } else { 'Error reading firewall profile' }
          $result.Description = "Error occurred while reading firewall profile: $($_.Exception.Message)"
        }
      }
      
      'Registry' {
        try {
          $regPath = $Rule.Key
          $valueName = $Rule.ValueName
          $expectedValue = $Rule.Expected
          $operator = if ($Rule.ContainsKey('Operator')) { $Rule.Operator } else { 'Equals' }
          $defaultValue = if ($Rule.ContainsKey('DefaultValue')) { $Rule.DefaultValue } else { $null }
          $currentValue = $null
          
          if (Test-Path $regPath) {
            $regItem = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            if ($regItem -and $regItem.PSObject.Properties.Name -contains $valueName) {
              $currentValue = $regItem.$valueName
            }
          }
          
          # Use default if current is null
          $compareValue = if ($null -eq $currentValue -and $null -ne $defaultValue) { $defaultValue } else { $currentValue }
          
          if ($null -ne $compareValue) {
            $result.Passed = Test-Compare -Current $compareValue -Expected $expectedValue -Operator $operator
          } else {
            $result.Passed = $false
          }
          
          # Format ActualValue with human-readable explanation
          if ($null -ne $currentValue) {
            if ($currentValue -is [int] -and ($currentValue -eq 0 -or $currentValue -eq 1)) {
              $result.ActualValue = "$currentValue (" + $(if($currentValue -eq 1){"Enabled"}else{"Disabled"}) + ")"
            } else {
              $result.ActualValue = $currentValue.ToString()
            }
          } elseif ($null -ne $defaultValue) {
            $result.ActualValue = "Not configured (using default: $defaultValue)"
          } else {
            $result.ActualValue = "Not configured (registry key or value does not exist)"
          }
          
          $result.EvidenceCommand = "Get-ItemProperty -Path '$regPath' -Name '$valueName'"
          $result.Remediation = if ($Rule.Remediation) { $Rule.Remediation } else { 
            "Set registry value: $regPath\$valueName = $expectedValue" 
          }
          $result.Description = "Registry setting verified directly. Value shown is the current registry value."
        } catch {
          $result.Passed = $false
          $result.ActualValue = "Error: $($_.Exception.Message)"
          $result.EvidenceCommand = "Get-ItemProperty -Path '$($Rule.Key)' -Name '$($Rule.ValueName)'"
          $result.Remediation = if ($Rule.Remediation) { $Rule.Remediation } else { 'Error reading registry' }
          $result.Description = "Error occurred while reading registry value: $($_.Exception.Message)"
        }
      }
      
      'Manual' { 
        $result.Passed=$false
        $result.Remediation = if ($Rule.Remediation) { $Rule.Remediation } else { 'Manual review required - see CIS Benchmark' }
        $result.Description = "This control requires manual verification and cannot be automated."
      }
      
      default { 
        $result.Passed=$false
        $result.Remediation = 'Unsupported control type'
        $result.Description = 'This control type is not supported by the scanner.'
      }
    }
  } catch { 
    $result.Passed=$false
    $result.Remediation = 'Error occurred during evaluation'
    $result.Description = "Exception: $($_.Exception.Message)"
  }
  
  # Set Status field based on Passed
  $result.Status = if ($result.Passed) { 'PASS' } else { 'FAIL' }
  
  $result
}

function Write-Reports([System.Collections.Generic.List[object]]$Results,[string]$OutDir,[object]$SystemInfo,[string[]]$Formats){
  New-Dir $OutDir
  $csv = Join-Path $OutDir 'vijenex-cis-results.csv'
  $html = Join-Path $OutDir 'vijenex-cis-report.html'
  $pdf = Join-Path $OutDir 'vijenex-cis-report-pdf.html'
  $word = Join-Path $OutDir 'vijenex-cis-report.docx'
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
    # Generate CSV with evidence columns
    $csvData = $Results | Select-Object Id, Title, Section, Status, ActualValue, EvidenceCommand, CISReference, Remediation, Description
    $csvData | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    $outputs['CSV'] = $csv
    Write-Host "CSV:  $csv" -ForegroundColor Green
  }
  
  $total=$Results.Count
  $passed=@($Results|Where-Object{$_.Passed}).Count
  $failed=$total-$passed
  
  $rows = $Results | ForEach-Object {
    $status = if($_.Passed){'[PASS]'}else{'[FAIL]'}
    $cls = if($_.Passed){'pass-row'}else{'fail-row'}
    $cisLink = if($_.CISReference){"<a href='$($_.CISReference)' target='_blank'>CIS Benchmark</a>"}else{'N/A'}
    $actualVal = if($_.ActualValue){$_.ActualValue}else{'N/A'}
    $evidCmd = if($_.EvidenceCommand){"<code style='font-size:10px'>$($_.EvidenceCommand)</code>"}else{'N/A'}
    "<tr class='$cls'><td><code>$($_.Id)</code></td><td>$($_.Title)</td><td>$($_.Section)</td><td><b>$status</b></td><td>$actualVal</td><td>$evidCmd</td><td>$cisLink</td></tr>"
  }
  
  # Generate HTML if requested
  if ($Formats -contains 'All' -or $Formats -contains 'HTML') {
    $htmlContent = @"
<!doctype html>
<html><head><meta charset="utf-8"/><title>CIS Scan Report - $($SystemInfo.Caption)</title>
<style>body{font-family:Arial,sans-serif;margin:20px}h1{margin-bottom:0}.system-info{background:#f8f9fa;padding:15px;border-radius:5px;margin:15px 0}.system-info h3{margin-top:0}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px;text-align:left;font-size:12px}th{background:#f0f0f0}tr.fail-row{background:#ffe6e6}tr.pass-row{background:#e6ffe6}.desc{max-width:300px;word-wrap:break-word}</style>
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
<table><thead><tr><th>ID</th><th>Control</th><th>Section</th><th>Status</th><th>Actual Value</th><th>Evidence Command</th><th>CIS Reference</th></tr></thead><tbody>
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
h2{color:#2E75B6;margin-top:25px;font-size:16px}
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
.note-box{background:#fff3cd;border-left:4px solid #ffc107;padding:15px;margin:20px 0;page-break-inside:avoid}
.code-box{background:#f4f4f4;border:1px solid #ddd;padding:10px;font-family:Consolas,monospace;margin:10px 0}
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
<h2>About This Report</h2>
<p><strong>Scanning Methodology:</strong> This system was scanned using the Vijenex CIS Scanner, which is based on official CIS Benchmark documentation. The scanner performs 100% read-only audits without making any system changes.</p>
<p><strong>CIS Benchmark Reference:</strong> This audit follows the official CIS Microsoft Windows Server 2019 Benchmark. Download the official documentation at: <a href="https://www.cisecurity.org/cis-benchmarks" target="_blank">https://www.cisecurity.org/cis-benchmarks</a></p>
<div class="note-box">
<p><strong>⚠️ IMPORTANT: Remediation Best Practices</strong></p>
<ol>
<li><strong>Test First:</strong> Always perform remediation on Non-Production systems first</li>
<li><strong>Validate:</strong> Ensure all applications and services work correctly after remediation</li>
<li><strong>Production Rollout:</strong> Only apply changes to Production after successful Non-Prod validation</li>
<li><strong>Golden Image:</strong> Once remediation is complete and validated, create a hardened golden image for future deployments to save time and ensure consistency</li>
<li><strong>Documentation:</strong> Document all changes and maintain an audit trail</li>
</ol>
</div>
<div class="note-box">
<p><strong>⚠️ IMPORTANT: Audit Policy Verification</strong></p>
<p><strong>Why GUI Shows Different Results:</strong><br>
Windows has TWO separate audit policy systems:</p>
<ol>
<li>Legacy Audit Policy (9 categories) - Shown in Local Security Policy GUI</li>
<li>Advanced Audit Policy (53 subcategories) - The EFFECTIVE policy</li>
</ol>
<p><strong>When both are configured, Advanced Audit Policy OVERRIDES Legacy.</strong></p>
<p><strong>What This Means:</strong></p>
<ul>
<li>Scanner reads: auditpol command (Advanced Audit Policy - EFFECTIVE)</li>
<li>GUI shows: Legacy Audit Policy (may show "Not Configured")</li>
<li>Result: Scanner shows FAIL, but GUI shows "Not Configured" - THIS IS NORMAL</li>
</ul>
<p><strong>How to Verify Scanner Results:</strong><br>
Run this command in PowerShell (as Administrator):</p>
<div class="code-box">auditpol /get /category:*</div>
<p>This shows the ACTUAL enforced policy (what the scanner reads).</p>
</div>
<h2>System Information</h2>
<div class="system-info">
<p><strong>Operating System:</strong> $($SystemInfo.Caption)</p>
<p><strong>Version:</strong> $($SystemInfo.Version) (Build $($SystemInfo.BuildNumber))</p>
<p><strong>Computer Name:</strong> $($SystemInfo.ComputerName)</p>
<p><strong>Machine ID:</strong> $($SystemInfo.MachineID)</p>
<p><strong>IP Address:</strong> $($SystemInfo.IPAddress)</p>
<p><strong>Scan Date:</strong> $($SystemInfo.ScanDate)</p>
</div>
<h2>Summary</h2>
<div class="summary">
<p><strong>Total Checks:</strong> $total</p>
<p><strong>Passed:</strong> $passed</p>
<p><strong>Failed:</strong> $failed</p>
<p><strong>Success Rate:</strong> $([math]::Round(($passed/$total)*100,1))%</p>
</div>
<h2>Detailed Results</h2>
<table>
<thead><tr><th>ID</th><th>Control</th><th>Section</th><th>Status</th><th>Actual Value</th><th>Evidence Command</th><th>Remediation</th></tr></thead>
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
  
  # Generate Word DOCX document if requested
  if ($Formats -contains 'All' -or $Formats -contains 'Word') {
    # Generate Word-compatible HTML (skip COM to avoid hanging)
      $wordHtml = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"/><title>CIS Compliance Audit Report</title>
<style>body{font-family:Calibri,Arial,sans-serif;margin:40px;line-height:1.4}h1{color:#2E75B6;border-bottom:2px solid #2E75B6;padding-bottom:10px}h2{color:#2E75B6;margin-top:30px}.info-table{border-collapse:collapse;margin:20px 0}.info-table td{padding:8px;border:1px solid #ddd}.info-table td:first-child{background:#f0f0f0;font-weight:bold;width:150px}table{border-collapse:collapse;width:100%;margin-top:20px;font-size:11px}th,td{border:1px solid #333;padding:6px;text-align:left;vertical-align:top}th{background:#2E75B6;color:white;font-weight:bold}.pass{background:#d4edda;color:#155724}.fail{background:#f8d7da;color:#721c24}.note-box{background:#fff3cd;border-left:4px solid #ffc107;padding:15px;margin:20px 0}.code-box{background:#f4f4f4;border:1px solid #ddd;padding:10px;font-family:Consolas,monospace;margin:10px 0}</style>
</head><body>
<h1>CIS Compliance Audit Report</h1>
<h2>About This Report</h2>
<p><strong>Scanning Methodology:</strong> This system was scanned using the Vijenex CIS Scanner, which is based on official CIS Benchmark documentation. The scanner performs 100% read-only audits without making any system changes.</p>
<p><strong>CIS Benchmark Reference:</strong> This audit follows the official CIS Microsoft Windows Server 2019 Benchmark. Download the official documentation at: <a href="https://www.cisecurity.org/cis-benchmarks" target="_blank">https://www.cisecurity.org/cis-benchmarks</a></p>
<div class="note-box">
<p><strong>⚠️ IMPORTANT: Remediation Best Practices</strong></p>
<ol>
<li><strong>Test First:</strong> Always perform remediation on Non-Production systems first</li>
<li><strong>Validate:</strong> Ensure all applications and services work correctly after remediation</li>
<li><strong>Production Rollout:</strong> Only apply changes to Production after successful Non-Prod validation</li>
<li><strong>Golden Image:</strong> Once remediation is complete and validated, create a hardened golden image for future deployments to save time and ensure consistency</li>
<li><strong>Documentation:</strong> Document all changes and maintain an audit trail</li>
</ol>
</div>
<div class="note-box">
<p><strong>⚠️ IMPORTANT: Audit Policy Verification</strong></p>
<p><strong>Why GUI Shows Different Results:</strong><br>
Windows has TWO separate audit policy systems:</p>
<ol>
<li>Legacy Audit Policy (9 categories) - Shown in Local Security Policy GUI</li>
<li>Advanced Audit Policy (53 subcategories) - The EFFECTIVE policy</li>
</ol>
<p><strong>When both are configured, Advanced Audit Policy OVERRIDES Legacy.</strong></p>
<p><strong>What This Means:</strong></p>
<ul>
<li>Scanner reads: auditpol command (Advanced Audit Policy - EFFECTIVE)</li>
<li>GUI shows: Legacy Audit Policy (may show "Not Configured")</li>
<li>Result: Scanner shows FAIL, but GUI shows "Not Configured" - THIS IS NORMAL</li>
</ul>
<p><strong>How to Verify Scanner Results:</strong><br>
Run this command in PowerShell (as Administrator):</p>
<div class="code-box">auditpol /get /category:*</div>
<p>This shows the ACTUAL enforced policy (what the scanner reads).</p>
</div>
<h2>System Information</h2>
<table class="info-table">
<tr><td>Operating System</td><td>$($SystemInfo.Caption)</td></tr>
<tr><td>Version</td><td>$($SystemInfo.Version) (Build $($SystemInfo.BuildNumber))</td></tr>
<tr><td>Computer Name</td><td>$($SystemInfo.ComputerName)</td></tr>
<tr><td>Machine ID</td><td>$($SystemInfo.MachineID)</td></tr>
<tr><td>IP Address</td><td>$($SystemInfo.IPAddress)</td></tr>
<tr><td>Scan Date</td><td>$($SystemInfo.ScanDate)</td></tr>
</table>
<h2>Summary</h2>
<table class="info-table">
<tr><td>Total Checks</td><td>$total</td></tr>
<tr><td>Passed</td><td class="pass">$passed</td></tr>
<tr><td>Failed</td><td class="fail">$failed</td></tr>
<tr><td>Success Rate</td><td>$([math]::Round(($passed/$total)*100,1))%</td></tr>
</table>
<h2>Detailed Results</h2>
<table>
<thead><tr><th>ID</th><th>Control</th><th>Section</th><th>Status</th><th>Actual Value</th><th>Evidence Command</th><th>Remediation</th></tr></thead>
<tbody>
"@
      
      foreach ($result in $Results) {
        $statusClass = if($result.Passed){"pass"}else{"fail"}
        $status = if($result.Passed){"Pass"}else{"Fail"}
        $actualVal = if($result.ActualValue){$result.ActualValue}else{'N/A'}
        $evidCmd = if($result.EvidenceCommand){$result.EvidenceCommand}else{'N/A'}
        $wordHtml += "<tr class='$statusClass'><td>$($result.Id)</td><td>$($result.Title)</td><td>$($result.Section)</td><td>$status</td><td>$actualVal</td><td style='font-size:10px'>$evidCmd</td><td>$($result.Remediation)</td></tr>`n"
      }
      
      $wordHtml += @"
</tbody></table>
<p style="margin-top:30px;color:#666;font-size:12px;text-align:center;">
Audit-only scan; no changes made. Generated by Vijenex Security Platform.<br>
Report generated on $($SystemInfo.ScanDate) for $($SystemInfo.ComputerName)
</p>
<p style="color:#666;font-size:10px;text-align:center;">Note: Open this file in Microsoft Word and save as DOCX for native Word format.</p>
</body></html>
"@
    
    Set-Content -Path $word -Value $wordHtml -Encoding UTF8
    $outputs['Word'] = $word
    Write-Host "Word: $word (HTML format - open in Word to save as DOCX)" -ForegroundColor Yellow
  }
  
  return $outputs
}

# ===== MAIN EXECUTION =====
Assert-Admin
New-Dir $OutputDir

# Display Vijenex CLI signature
Write-Host "`n" -ForegroundColor White
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "                        VIJENEX                              " -ForegroundColor Cyan
Write-Host "      Windows Server 2019 CIS Compliance Scanner           " -ForegroundColor White
Write-Host "                 (Standalone/Workgroup)                     " -ForegroundColor White
Write-Host "           Powered by Vijenex Security Platform             " -ForegroundColor Yellow
Write-Host "        https://github.com/vijenex/windows-cis-scanner       " -ForegroundColor Gray
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "`n" -ForegroundColor White

$systemInfo=Get-OSInfo

# Detect if this is a Domain Controller
$cs=Get-CimInstance Win32_ComputerSystem
$isDomainController = $cs.DomainRole -in @(4,5)
# 4 = Backup Domain Controller, 5 = Primary Domain Controller

if ($isDomainController) {
  Write-Host "⚠️  DETECTED: Domain Controller" -ForegroundColor Yellow
  Write-Host "    DC-only controls will be evaluated" -ForegroundColor Gray
} else {
  Write-Host "✓  DETECTED: Member Server" -ForegroundColor Green
  Write-Host "    DC-only controls will be skipped (marked as N/A)" -ForegroundColor Gray
}
Write-Host ""

# Validate Windows version
$expectedBuild = 17763  # Windows Server 2019
if ($systemInfo.BuildNumber -lt ($expectedBuild - 1000) -or $systemInfo.BuildNumber -gt ($expectedBuild + 1000)) {
  Write-Host "`n" -ForegroundColor Red
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "                VERSION MISMATCH WARNING                     " -ForegroundColor Yellow
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "Expected: Windows Server 2019 (Build ~$expectedBuild)" -ForegroundColor Yellow
  Write-Host "Detected: Build $($systemInfo.BuildNumber)" -ForegroundColor Yellow
  Write-Host "`nYou may be running the wrong scanner version!" -ForegroundColor Red
  Write-Host "Please use the correct folder for your Windows version." -ForegroundColor Yellow
  Write-Host "=============================================================" -ForegroundColor Red
  Write-Host "`n" -ForegroundColor White
  
  $response = Read-Host "Continue anyway? (yes/no)"
  if ($response -ne 'yes') {
    throw "Scan cancelled due to version mismatch"
  }
}

Write-Host "Scanning host: $($systemInfo.Caption) ($($systemInfo.Version) Build: $($systemInfo.BuildNumber))" -ForegroundColor Cyan
Write-Host "Machine: $($systemInfo.ComputerName) | IP: $($systemInfo.IPAddress) | Date: $($systemInfo.ScanDate)" -ForegroundColor Gray

# Load milestones (all if not specified)
$milestoneFolder = Join-Path (Split-Path $PSScriptRoot) "milestones"

# Validate milestone folder exists
if (-not (Test-Path $milestoneFolder)) {
  throw "Milestones folder not found: $milestoneFolder"
}

if (-not $Milestones -or $Milestones.Count -eq 0) {
  $Milestones = Get-ChildItem -Path $milestoneFolder -Filter *.ps1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
  # Ensure all milestone files are loaded in order
  $Milestones = $Milestones | Sort-Object { [int]($_ -replace '\D') }
}

foreach ($m in $Milestones) {
  # Validate milestone filename to prevent path traversal
  if ($m -match '[\\\/\.]\.' -or $m -notmatch '^[a-zA-Z0-9_-]+\.ps1$') {
    Write-Warning "Invalid milestone filename: $m"
    continue
  }
  
  $p = Join-Path $milestoneFolder $m
  
  # Ensure the resolved path is within the milestones folder
  $resolvedPath = [System.IO.Path]::GetFullPath($p)
  $resolvedMilestoneFolder = [System.IO.Path]::GetFullPath($milestoneFolder)
  
  if (-not $resolvedPath.StartsWith($resolvedMilestoneFolder)) {
    Write-Warning "Path traversal attempt detected: $m"
    continue
  }
  
  if (Test-Path $p) { 
    Write-Host "Loading $m ..." -ForegroundColor Cyan
    try {
      . $p 
    } catch {
      Write-Warning "Failed to load milestone $m : $($_.Exception.Message)"
    }
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

# Filter DC-only controls if this is a Member Server
if (-not $isDomainController) {
  $dcOnlyCount = @($rules | Where-Object { $_.Title -match '\(DC [Oo]nly\)' }).Count
  $rules = $rules | Where-Object { $_.Title -notmatch '\(DC [Oo]nly\)' }
  if ($dcOnlyCount -gt 0) {
    Write-Host "Filtered out $dcOnlyCount DC-only controls (not applicable to Member Server)" -ForegroundColor Yellow
  }
}

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
Write-Host ""

# Evaluate rules
$results = New-Object System.Collections.Generic.List[object]
foreach($rule in $rules){ 
  $result = Evaluate-Rule -Rule $rule -Context $ctx
  $results.Add($result)
  
  # Display real-time progress like Linux scanner
  $status = if($result.Passed){"[PASS]"}else{"[FAIL]"}
  $statusColor = if($result.Passed){"Green"}else{"Red"}
  $manualNote = if($result.Type -eq 'Manual'){" (Manual Review Required)"}else{""}
  
  Write-Host "[$($result.Id)] $($result.Title)$manualNote" -ForegroundColor White
  Write-Host "    Status: " -NoNewline -ForegroundColor Gray
  Write-Host $status -ForegroundColor $statusColor
  Write-Host ""
}

# Display summary like Linux scanner
$totalChecks = $results.Count
$passedChecks = @($results | Where-Object { $_.Passed }).Count
$failedChecks = $totalChecks - $passedChecks
$successRate = if ($totalChecks -gt 0) { [math]::Round(($passedChecks / $totalChecks) * 100, 1) } else { 0 }

Write-Host "`n" -ForegroundColor White
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "                    SCAN COMPLETED                           " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "Total Checks: $totalChecks" -ForegroundColor White
Write-Host "Passed: " -NoNewline -ForegroundColor White
Write-Host "$passedChecks" -ForegroundColor Green
Write-Host "Failed: " -NoNewline -ForegroundColor White
Write-Host "$failedChecks" -ForegroundColor Red
Write-Host "Success Rate: $successRate%" -ForegroundColor Yellow
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "`n" -ForegroundColor White

# Handle output format parameter
if ($OutputFormat -contains 'All') {
  $formats = @('HTML','CSV','PDF','Word')
} else {
  $formats = $OutputFormat
}

# Generate reports
$paths = Write-Reports -Results $results -OutDir $OutputDir -SystemInfo $systemInfo -Formats $formats

# Cleanup
if ($seceditPath -and (Test-Path $seceditPath)) { 
  try {
    Remove-Item $seceditPath -Force -ErrorAction SilentlyContinue 
  } catch {
    Write-Warning "Failed to cleanup temporary file: $seceditPath"
  }
}

exit (@($results | Where-Object { -not $_.Passed }).Count)