[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\ListWindowsUsers-script.log",
  [string]$ARLog  = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference='Stop'
$HostName=$env:COMPUTERNAME
$LogMaxKB=100
$LogKeep=5
$runStart=Get-Date

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line="[$ts][$Level] $Message"
  switch($Level){
    'ERROR'{Write-Host $line -ForegroundColor Red}
    'WARN' {Write-Host $line -ForegroundColor Yellow}
    default{Write-Host $line}
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if(Test-Path $LogPath -PathType Leaf){
    if((Get-Item $LogPath).Length/1KB -gt $LogMaxKB){
      for($i=$LogKeep-1;$i -ge 0;$i--){
        $old="$LogPath.$i";$new="$LogPath."+($i+1)
        if(Test-Path $old){Rename-Item $old $new -Force}
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function NowZ { (Get-Date).ToString('yyyy-MM-dd HH:mm:sszzz') }

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

Rotate-Log
Write-Log "=== SCRIPT START : List Windows Users ==="

$ts = NowZ
$lines = @()

try {
  $allGroups = Get-LocalGroup -ErrorAction SilentlyContinue
  $groupMembers = @{}
  foreach($g in $allGroups){
    try {
      $groupMembers[$g.Name] = (Get-LocalGroupMember -Group $g.Name -ErrorAction Stop).Name
    } catch {
      $groupMembers[$g.Name] = @()
    }
  }


  $users = Get-LocalUser -ErrorAction Stop | Where-Object { $_.Name -match '^\w' }

  foreach($u in $users){
    $uname = $u.Name.Trim()
    $uGroups = @()
    foreach($g in $groupMembers.Keys){
      if ($groupMembers[$g] -contains $uname) { $uGroups += $g }
    }

    $lines += ([pscustomobject]@{
      timestamp           = $ts
      host                = $HostName
      action              = 'list_windows_users'
      copilot_action      = $true
      type                = 'user'
      username            = $uname
      fullname            = $u.FullName
      enabled             = [bool]$u.Enabled
      description         = $u.Description
      password_required   = [bool]$u.PasswordRequired
      password_changeable = [bool]$u.PasswordChangeable
      password_expired    = [bool]$u.PasswordExpired
      user_may_change_pw  = [bool]$u.UserMayChangePassword
      lastlogon           = if($u.LastLogon){ $u.LastLogon.ToString('o') } else { $null }
      account_expires     = if($u.AccountExpires){ $u.AccountExpires.ToString('o') } else { $null }
      groups              = ($uGroups | Sort-Object -Unique)
    } | ConvertTo-Json -Compress -Depth 6)
  }

  $lines += ([pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'list_windows_users'
    copilot_action = $true
    type           = 'verify_source'
    source_users   = 'Get-LocalUser'
    source_groups  = 'Get-LocalGroup/Get-LocalGroupMember'
    users_count    = $users.Count
    groups_count   = $allGroups.Count
  } | ConvertTo-Json -Compress -Depth 5)

  $summary = [pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'list_windows_users'
    copilot_action = $true
    type           = 'summary'
    total_users    = $users.Count
    duration_s     = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  }
  $lines = @(( $summary | ConvertTo-Json -Compress -Depth 5 )) + $lines

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0} ({1} lines)" -f $ARLog,$lines.Count) 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $err = [pscustomobject]@{
    timestamp      = NowZ
    host           = $HostName
    action         = 'list_windows_users'
    copilot_action = $true
    type           = 'error'
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @(($err | ConvertTo-Json -Compress -Depth 5)) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally {
  $dur=[int]((Get-Date)-$runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
