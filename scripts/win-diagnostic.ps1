# ============================================================
# KakaoChat Viewer - Windows Diagnostic & Key Solver (v1.0)
#
# Purpose:
#   1. Dump KakaoTalk registry DeviceInfo (all subkeys/values)
#   2. List EDB files under %LocalAppData%\Kakao\KakaoTalk\users
#   3. Recover userId candidates (file scan + process memory dump)
#   4. Try full parameter solve: materials x 15 built-in keys x
#      userId candidates -> decrypt first block -> match SQLite header
#
# Run (PowerShell):
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\win-diagnostic.ps1
#
# Output:
#   Console + %USERPROFILE%\Desktop\kkv-diagnostic-result.txt
#   Send the result file back for analysis.
#
# For personal device backup / forensics / migration only.
# ============================================================

$ErrorActionPreference = 'Continue'
$enc1 = [System.Text.Encoding]::GetEncoding(28591)   # latin1
$OUT  = New-Object System.Collections.Generic.List[string]

function Out-Line([string]$s) {
  $OUT.Add($s) | Out-Null
  Write-Host $s
}

# ---------- 15 built-in candidate keys (public research, kdevil2k/Kakaotalk_decDB) ----------
$KEYS = @(
  '1070fe58019a4d488a6ce02d9286aabb',
  '4a8c14e149954920b2ca88ea23f6f029',
  '60f533f580aa4a668f8a4a03fbaab3a5',
  '80714702d5cc49deb65ff5ff0ab048ac',
  '97b83a40292f4f54a2204b5cec7da166',
  'aa85c9df01f34ad6a909a6870ab80312',
  'b04f14d2ae334dcba785d40b51f70cf7',
  'b9c307637fbd4fd78e81aaa5e90e4fd6',
  'bf60d3f1089c4c6f829076e4c68617de',
  'c37150d489e147889dd2caa2dacde7c7',
  'c4def0e5d3ee4e8aadf9df1ba48a4f5a',
  'ce35ab8752b811eaa0ef806e6f6e6963',
  'd82c75b5c999406fa2235103ab900a07',
  'dec8c9b560b7474fb4f00ea7f7737764',
  'e15caf15e5c94e538804c755151840bc'
)

# ---------- crypto helpers (mirror decDB.py exactly) ----------
function Get-Pragma([string]$material, [byte[]]$key) {
  # pragma = Base64( SHA512( AES-128-CBC( utf8(material) padded PKCS7, key, zero IV ) ) )
  $aes = [System.Security.Cryptography.Aes]::Create()
  $aes.Mode = 'CBC'; $aes.Padding = 'None'
  $aes.KeySize = 128; $aes.Key = $key; $aes.IV = (New-Object byte[] 16)
  $src = [System.Text.Encoding]::UTF8.GetBytes($material)
  $padLen = 16 - ($src.Length % 16)
  $buf = New-Object byte[] ($src.Length + $padLen)
  [Array]::Copy($src, $buf, $src.Length)
  for ($i = $src.Length; $i -lt $buf.Length; $i++) { $buf[$i] = [byte]$padLen }
  $enc = $aes.CreateEncryptor().TransformFinalBlock($buf, 0, $buf.Length)
  $aes.Dispose()
  $sha = [System.Security.Cryptography.SHA512]::Create()
  $h = $sha.ComputeHash($enc); $sha.Dispose()
  return [Convert]::ToBase64String($h)
}

function Get-KeyIv([string]$pragma, [string]$uid) {
  # keyStr = (pragma + uid) self-repeat to 512 chars; key = MD5(keyStr); iv = MD5(base64(key))
  $ks = $pragma + $uid
  while ($ks.Length -lt 512) { $ks += $ks }
  if ($ks.Length -gt 512) { $ks = $ks.Substring(0, 512) }
  $md5 = [System.Security.Cryptography.MD5]::Create()
  $key = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ks))
  $iv  = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes([Convert]::ToBase64String($key)))
  return ,@($key, $iv)
}

function Test-SqliteHead([byte[]]$edb, [byte[]]$key, [byte[]]$iv) {
  try {
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = 'CBC'; $aes.Padding = 'None'; $aes.KeySize = 128
    $aes.Key = $key; $aes.IV = $iv
    $dec = $aes.CreateDecryptor().TransformFinalBlock($edb, 0, 16)
    $aes.Dispose()
    return ($enc1.GetString($dec) -eq ('SQLite format 3' + [char]0))
  } catch { return $false }
}

# ================= [1] Registry =================
Out-Line '===== [1] Registry: HKCU\Software\Kakao\KakaoTalk\DeviceInfo ====='
$regRaw = ''
try { $regRaw = (reg query 'HKCU\Software\Kakao\KakaoTalk\DeviceInfo' /s 2>&1 | Out-String) } catch { $regRaw = ('reg query failed: ' + $_.Exception.Message) }
Out-Line $regRaw.TrimEnd()

# parse subkeys and values
$devMap = @{}
$curKey = $null
foreach ($line in ($regRaw -split "`r?`n")) {
  if ($line -match '^HKEY_CURRENT_USER\\Software\\Kakao\\KakaoTalk\\DeviceInfo\\?(.*)$') {
    $curKey = $Matches[1]
    if (-not $devMap.ContainsKey($curKey)) { $devMap[$curKey] = @{} }
  } elseif ($null -ne $curKey -and $line -match '^\s+(\S+)\s+REG_(?:SZ|EXPAND_SZ|BINARY|DWORD|QWORD|MULTI_SZ)\s+(.*)$') {
    $devMap[$curKey][$Matches[1]] = $Matches[2].Trim()
  }
}

$fieldUuids = @(); $fieldModels = @(); $fieldSerials = @(); $devIds = @()
foreach ($k in $devMap.Keys) {
  foreach ($vn in @($devMap[$k].Keys)) {
    $v = [string]$devMap[$k][$vn]
    if (-not $v) { continue }
    if ($vn -match 'dev_id')  { $devIds      += $v }
    if ($vn -match 'uuid')    { $fieldUuids += $v }
    if ($vn -match 'model')   { $fieldModels += $v }
    if ($vn -match 'serial')  { $fieldSerials += $v }
  }
}

# ================= [2] Build material variants =================
Out-Line '===== [2] Material variants ====='
$materials = New-Object System.Collections.Generic.List[string]
$AddMat = { param($s) if ($s -and -not $materials.Contains($s)) { $materials.Add($s); Out-Line ('  [' + $materials.Count + '] ' + $s) } }

foreach ($d in $devIds) {
  & $AddMat $d.Trim()
  if ($d -match '\|') {
    $p = $d -split '\|'
    if ($p.Count -ge 3) { & $AddMat (($p[0] + '|' + $p[1] + '|' + $p[2]).Trim()) }
  }
}
foreach ($u in $fieldUuids) {
  & $AddMat $u.Trim()
  foreach ($m in $fieldModels) {
    foreach ($s in $fieldSerials) {
      & $AddMat (($u + '|' + $m + '|' + $s).Trim())
      & $AddMat (($u + '|' + $m + '|' + ($s -replace '\.$','')).Trim())
    }
  }
}
Out-Line ('Total material variants: ' + $materials.Count)

# ================= [3] EDB files =================
Out-Line '===== [3] EDB files ====='
$usersDir = Join-Path $env:LOCALAPPDATA 'Kakao\KakaoTalk\users'
if (-not (Test-Path $usersDir)) {
  Out-Line ('NOT FOUND: ' + $usersDir)
} else {
  Out-Line ('users dir: ' + $usersDir)
}
$edbs = @()
if (Test-Path $usersDir) {
  $edbs = @(Get-ChildItem -Path $usersDir -Recurse -Filter *.edb -ErrorAction SilentlyContinue | Sort-Object Length)
}
if ($edbs.Count -eq 0) {
  Out-Line 'No .edb files found!'
} else {
  Out-Line ('EDB count: ' + $edbs.Count)
  foreach ($e in ($edbs | Select-Object -First 25)) { Out-Line ('  {0,10} bytes  {1}' -f $e.Length, $e.FullName) }
  if ($edbs.Count -gt 25) { Out-Line ('  ... and ' + ($edbs.Count - 25) + ' more') }
}

# ================= [4] userId candidates: file scan =================
$scores = @{}
function Add-Uid([string]$num, [double]$w) {
  if ($num -and $num -ne '0') {
    if (-not $scores.ContainsKey($num)) { $scores[$num] = 0.0 }
    $scores[$num] = $scores[$num] + $w
  }
}
$patterns = @(
  @{ re = '"from":"(\d{5,10})"';    w = 0.9  },
  @{ re = '"user_id":(\d{5,10})"';  w = 0.6  },
  @{ re = '(?i)\bnt\s+(\d{5,10})';  w = 0.15 },
  @{ re = '==(\d{5,10})';           w = 0.1  }
)

Out-Line '===== [4] userId candidates (file scan) ====='
$base = Join-Path $env:LOCALAPPDATA 'Kakao\KakaoTalk'
try {
  Get-ChildItem -Path $base -Recurse -Depth 2 -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -notin @('.edb', '.db') -and $_.Length -gt 0 -and $_.Length -lt 8MB } |
    ForEach-Object {
      try {
        $text = $enc1.GetString([System.IO.File]::ReadAllBytes($_.FullName))
        foreach ($p in $patterns) {
          foreach ($mm in [System.Text.RegularExpressions.Regex]::Matches($text, $p.re)) { Add-Uid $mm.Groups[1].Value $p.w }
        }
      } catch {}
    }
} catch {}
Out-Line ('File-scan candidates: ' + (($scores.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object { $_.Key }) -join ', '))

# ================= [5] userId candidates: memory dump =================
Out-Line '===== [5] userId candidates (process memory dump) ====='
$procs = @(Get-Process KakaoTalk -ErrorAction SilentlyContinue)
if ($procs.Count -eq 0) {
  Out-Line 'KakaoTalk.exe is NOT running - skip memory dump (run again while KakaoTalk is open for more candidates)'
} else {
  $sig = @'
using System;
using System.Runtime.InteropServices;
public class KkvMem {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out int read);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MEMORY_BASIC_INFORMATION info, int len);
  [StructLayout(LayoutKind.Sequential)]
  public struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public IntPtr RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
  }
}
'@
  try { Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue } catch {}
  foreach ($proc in $procs) {
    $dumpPath = Join-Path $env:TEMP ('kkv-mem-' + $proc.Id + '.dmp')
    Out-Line ('Dumping PID ' + $proc.Id + ' ...')
    $h = [KkvMem]::OpenProcess(0x0410, $false, $proc.Id)
    if ($h -eq [IntPtr]::Zero) { Out-Line ('  OpenProcess failed (try running this script as the same user that runs KakaoTalk)'); continue }
    $fs = [System.IO.File]::Create($dumpPath)
    $addr = [IntPtr]::Zero
    $buf = New-Object byte[] 16777216
    $read = 0
    $total = [long]0
    while ($true) {
      $mbi = New-Object KkvMem+MEMORY_BASIC_INFORMATION
      $ret = [KkvMem]::VirtualQueryEx($h, $addr, [ref]$mbi, [System.Runtime.InteropServices.Marshal]::SizeOf($mbi))
      if ($ret -eq [IntPtr]::Zero) { break }
      $region = [int64]$mbi.RegionSize
      if ($mbi.State -eq 0x1000 -and $region -gt 0 -and $region -le 268435456) {
        $remain = $region
        $cur = [int64]$mbi.BaseAddress
        while ($remain -gt 0) {
          $take = [int][Math]::Min($remain, $buf.Length)
          $ok = [KkvMem]::ReadProcessMemory($h, [IntPtr]$cur, $buf, $take, [ref]$read)
          if ($ok -and $read -gt 0) { $fs.Write($buf, 0, $read); $total += $read }
          $cur += $take
          $remain -= $take
        }
      }
      $addr = [IntPtr]([int64]$mbi.BaseAddress + $region)
      if ([int64]$addr -le 0) { break }
      if ($total -gt 3GB) { Out-Line '  dump size cap reached'; break }
    }
    $fs.Close()
    Out-Line ('  dumped ' + $total + ' bytes')
    try {
      $text = $enc1.GetString([System.IO.File]::ReadAllBytes($dumpPath))
      foreach ($p in $patterns) {
        foreach ($mm in [System.Text.RegularExpressions.Regex]::Matches($text, $p.re)) { Add-Uid $mm.Groups[1].Value $p.w }
      }
    } catch { Out-Line ('  scan failed: ' + $_.Exception.Message) }
    Remove-Item -Path $dumpPath -Force -ErrorAction SilentlyContinue
  }
}
$uids = @($scores.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 12 | ForEach-Object { $_.Key })
Out-Line ('All userId candidates (top): ' + ($uids -join ', '))

# ================= [6] Solve =================
Out-Line '===== [6] Parameter solve ====='
if ($edbs.Count -eq 0) {
  Out-Line 'No EDB to solve. Send this output back.'
} elseif ($materials.Count -eq 0) {
  Out-Line 'No material variants. Send this output back (registry section above is critical).'
} else {
  $probe = $edbs | Where-Object { $_.Name -match '^chatLogs' } | Select-Object -First 1
  if (-not $probe) { $probe = $edbs | Select-Object -First 1 }
  $edbBytes = [System.IO.File]::ReadAllBytes($probe.FullName)
  Out-Line ('Probe: ' + $probe.Name + ' (' + $probe.Length + ' bytes)')
  Out-Line ('First 16 bytes: ' + (($edbBytes[0..15] | ForEach-Object { $_.ToString('x2') }) -join ' '))
  Out-Line ('Solving: ' + $materials.Count + ' materials x 15 keys x ' + $uids.Count + ' userIds ...')

  $found = $null
  :outer
  foreach ($mat in $materials) {
    for ($ki = 0; $ki -lt $KEYS.Count; $ki++) {
      $keyHex = $KEYS[$ki]
      $key = New-Object byte[] 16
      for ($i = 0; $i -lt 16; $i++) { $key[$i] = [Convert]::ToByte($keyHex.Substring($i * 2, 2), 16) }
      $pragma = Get-Pragma $mat $key
      foreach ($uid in $uids) {
        $ki2 = Get-KeyIv $pragma $uid
        if (Test-SqliteHead $edbBytes $ki2[0] $ki2[1]) {
          $found = @{ mat = $mat; keyIdx = ($ki + 1); keyHex = $keyHex; uid = $uid; pragma = $pragma }
          break :outer
        }
      }
    }
  }

  if ($found) {
    Out-Line ''
    Out-Line '################ FOUND ################'
    Out-Line ('Material (copy this into manual mode): ' + $found.mat)
    Out-Line ('Key index: ' + $found.keyIdx + '  (' + $found.keyHex + ')')
    Out-Line ('userId: ' + $found.uid)
    Out-Line ('pragma: ' + $found.pragma)
    Out-Line '#######################################'
    Out-Line ''
    Out-Line 'Next: update the app, or use manual mode with the material string above as the device input and the userId above.'
  } else {
    Out-Line 'NOT FOUND with any combination. Send this whole output back - the registry section and first-16-bytes are the key clues.'
  }
}

# ---------- save ----------
$outPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'kkv-diagnostic-result.txt'
[System.IO.File]::WriteAllLines($outPath, $OUT, (New-Object System.Text.UTF8Encoding($false)))
Out-Line ''
Out-Line ('Result saved to: ' + $outPath)
Out-Line 'Please send this file back.'
