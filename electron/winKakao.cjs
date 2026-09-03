'use strict';
/**
 * Windows 版 KakaoTalk EDB 自动发现与解密（main 进程专用）
 *
 * 算法依据公开研究（kdevil2k/Kakaotalk_decDB、system32.kr 博客与相关论文）：
 *   1. 材料：注册表 HKCU\Software\Kakao\KakaoTalk\DeviceInfo\<子键>\dev_id（即 "uuid|model|serial" 组合串）
 *   2. pragma = Base64(SHA512(AES-128-CBC(材料, 内置候选key×15, 全零IV)))，PKCS7 填充
 *   3. PK = pragma + userId；keyStr = PK 自我重复至 512 字节截断
 *   4. key = MD5(keyStr)；iv = MD5(Base64(key))
 *   5. EDB 按 4096 字节/页，每页独立 AES-128-CBC 解密（无填充），产物为标准 SQLite
 *
 * 仅限本人设备/合法授权场景使用（备份、取证、迁移）。
 */

const { execFile, spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

/** KakaoTalk.exe 内置的 15 个候选 AES key（hex，公开研究整理） */
const CANDIDATE_KEYS = [
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
  'e15caf15e5c94e538804c755151840bc',
];

const SQLITE_HEAD = 'SQLite format 3\x00';

/* ============ 注册表：设备材料 ============ */

/** 读取 HKCU\Software\Kakao\KakaoTalk\DeviceInfo 全部子键的全部值（dev_id/uuid/model/serial…） */
function readDeviceInfo() {
  return new Promise((resolve) => {
    execFile(
      'reg',
      ['query', 'HKCU\\Software\\Kakao\\KakaoTalk\\DeviceInfo', '/s'],
      { encoding: 'utf8', timeout: 15000, maxBuffer: 8 * 1024 * 1024, windowsHide: true },
      (err, stdout) => {
        if (err) return resolve({ ok: false, reason: err.message, devIds: [], fields: [], materials: [] });
        const devIds = [];
        const fields = []; // { key: 子键, name: 值名, value: 值 }
        let curKey = '';
        for (const line of String(stdout).split(/\r?\n/)) {
          const km = line.match(/^HKEY_CURRENT_USER\\Software\\Kakao\\KakaoTalk\\DeviceInfo(.*)$/i);
          if (km) { curKey = km[1].replace(/^\\/, ''); continue; }
          // 形如：    值名    REG_SZ    值
          const m = line.match(/^\s+(\S+)\s+REG_[A-Z]+\s+(.*)$/);
          if (m) {
            const name = m[1];
            const value = m[2].trim();
            fields.push({ key: curKey, name, value });
            if (/^dev_id$/i.test(name)) devIds.push(value);
          }
        }
        resolve({ ok: fields.length > 0, devIds, fields, materials: buildMaterials(devIds, fields) });
      }
    );
  });
}

/**
 * 由注册表字段生成材料变体：
 *   1. dev_id 原串 / 三段重组
 *   2. uuid|model|serial 独立值组合（kdevil2k generate_pragma 的标准材料），含 serial 尾点去留两变体
 *   3. uuid 单串兜底
 */
function buildMaterials(devIds, fields = []) {
  const materials = [];
  const push = (input, label) => {
    if (input && !materials.some((m) => m.input === input)) materials.push({ input, label });
  };
  for (const d of devIds) {
    const raw = String(d).trim();
    push(raw, 'dev_id 原串');
    if (raw.includes('|')) {
      const parts = raw.split('|').map((s) => s.trim());
      if (parts.length >= 3) push(`${parts[0]}|${parts[1]}|${parts[2]}`, 'dev_id 三段重组');
    }
  }
  const val = (re) => fields.filter((f) => re.test(f.name) && f.value).map((f) => f.value.trim());
  const uuids = val(/uuid/i);
  const models = val(/model/i);
  const serials = val(/serial/i);
  for (const u of uuids) {
    push(u, '注册表 uuid 单串');
    const uLower = u.toLowerCase();
    const uUpper = u.toUpperCase();
    if (uLower !== u) push(uLower, '注册表 uuid 单串（小写）');
    if (uUpper !== u) push(uUpper, '注册表 uuid 单串（大写）');
    for (const mo of models) {
      for (const s of serials) {
        push(`${u}|${mo}|${s}`, '注册表 uuid|model|serial');
        const s2 = s.replace(/\.$/, '');
        if (s2 !== s) push(`${u}|${mo}|${s2}`, '注册表 uuid|model|serial（serial 去尾点）');
        if (uLower !== u) push(`${uLower}|${mo}|${s2}`, 'uuid 小写|model|serial（serial 去尾点）');
        if (uUpper !== u) push(`${uUpper}|${mo}|${s}`, 'uuid 大写|model|serial');
      }
    }
  }
  return materials;
}

/* ============ 密钥派生 ============ */

function pkcs7Pad(buf, block) {
  const n = block - (buf.length % block);
  return Buffer.concat([buf, Buffer.alloc(n, n)]);
}

/** pragma = Base64(SHA512(AES-128-CBC(材料, key, 零IV))) —— 只依赖材料与候选 key */
function computePragma(materialInput, keyHex) {
  const c = crypto.createCipheriv('aes-128-cbc', Buffer.from(keyHex, 'hex'), Buffer.alloc(16));
  c.setAutoPadding(false);
  const enc = Buffer.concat([c.update(pkcs7Pad(Buffer.from(materialInput, 'utf8'), 16)), c.final()]);
  return crypto.createHash('sha512').update(enc).digest('base64');
}

/** 由 pragma + userId 派生 EDB 的 key/iv（16 字节 raw × 2） */
function deriveKeyIv(pragma, userIdStr) {
  let keyStr = pragma + userIdStr;
  while (keyStr.length < 512) keyStr += keyStr;
  keyStr = keyStr.slice(0, 512);
  const key = crypto.createHash('md5').update(keyStr, 'utf8').digest();
  const iv = crypto.createHash('md5').update(Buffer.from(key.toString('base64'), 'utf8')).digest();
  return { key, iv };
}

/* ============ EDB 解密 ============ */

/** 按页（4096 字节）独立 AES-128-CBC 解密；产物为标准 SQLite 字节 */
function decryptEdb(buf, key, iv) {
  const out = Buffer.alloc(buf.length);
  for (let off = 0; off < buf.length; off += 4096) {
    let chunk = buf.subarray(off, Math.min(off + 4096, buf.length));
    if (chunk.length % 16 !== 0) chunk = chunk.subarray(0, chunk.length - (chunk.length % 16));
    const d = crypto.createDecipheriv('aes-128-cbc', key, iv);
    d.setAutoPadding(false);
    const dec = Buffer.concat([d.update(chunk), d.final()]);
    dec.copy(out, off);
  }
  return out;
}

/** 用首块密文快速验证参数（CBC 首块明文只依赖 IV 与首块密文） */
function firstBlockMatches(buf, key, iv) {
  const d = crypto.createDecipheriv('aes-128-cbc', key, iv);
  d.setAutoPadding(false);
  const head = d.update(buf.subarray(0, 16));
  return head.toString('latin1') === SQLITE_HEAD;
}

/**
 * 在 (材料 × 15候选key × userId候选) 空间中求解可解密参数
 * @param {Buffer} edbBuf 加密 EDB 数据（至少 16 字节）
 * @param {Array} materials buildMaterials 的产物
 * @param {Array<number|string>} userIds userId 候选
 */
function solveEdbParams(edbBuf, materials, userIds) {
  for (const mat of materials) {
    for (const keyHex of CANDIDATE_KEYS) {
      const pragma = computePragma(mat.input, keyHex); // pragma 与 userId 无关，外层预计算
      for (const uid of userIds) {
        const { key, iv } = deriveKeyIv(pragma, String(uid));
        if (firstBlockMatches(edbBuf, key, iv)) {
          return { material: mat, keyHex, userId: String(uid), pragma };
        }
      }
    }
  }
  return null;
}

/* ============ users 目录与 EDB 清单 ============ */

/** KakaoTalk 数据根目录（%LocalAppData%\Kakao\KakaoTalk） */
function kakaoBaseDir() {
  const local = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
  return path.join(local, 'Kakao', 'KakaoTalk');
}

/** 递归收集 users 目录下全部 .edb 文件 */
function listEdbFiles(maxDepth = 4) {
  const base = kakaoBaseDir();
  const usersDir = path.join(base, 'users');
  const out = [];
  if (!fs.existsSync(usersDir)) return { ok: false, base, usersDir, edbs: [] };
  const walk = (dir, depth) => {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full, depth + 1);
      else if (/\.edb$/i.test(e.name)) {
        let size = 0;
        try { size = fs.statSync(full).size; } catch { /* 忽略 */ }
        const cm = e.name.match(/chatLogs[_-](\d+)\.edb$/i);
        out.push({ path: full, name: e.name, size, userDir: path.basename(dir), chatId: cm ? cm[1] : null });
      }
    }
  };
  walk(usersDir, 0);
  out.sort((a, b) => b.size - a.size);
  return { ok: out.length > 0, base, usersDir, edbs: out };
}

/** KakaoTalk.exe 是否在运行；运行则返回进程列表 */
function isKakaoTalkRunning() {
  return new Promise((resolve) => {
    execFile(
      'tasklist',
      ['/FI', 'IMAGENAME eq KakaoTalk.exe', '/NH', '/FO', 'CSV'],
      { encoding: 'utf8', timeout: 10000, windowsHide: true },
      (err, stdout) => {
        if (err) return resolve({ running: false, pids: [] });
        const pids = [];
        for (const line of String(stdout).split(/\r?\n/)) {
          const m = line.match(/^"KakaoTalk\.exe","(\d+)"/i);
          if (m) pids.push(Number(m[1]));
        }
        resolve({ running: pids.length > 0, pids });
      }
    );
  });
}

/* ============ userId 还原：文件扫描 ============ */

/** 识别模式与权重（对齐 kdevil2k FindUSERID.py 的正则） */
const UID_PATTERNS = {
  from: /"from":"(\d{5,10})"/g,
  user_id: /"user_id":(\d{5,10})"/g,
  nt: /\bnt\s+(\d{5,10})/g,
  equal: /==(\d{5,10})/g,
};

/** 从 KakaoTalk 目录浅层文件（config/缓存等）提取 userId 候选 */
function extractUserIdFromFiles() {
  const base = kakaoBaseDir();
  const counts = { from: new Map(), user_id: new Map(), nt: new Map(), equal: new Map() };
  const scan = (dir, depth) => {
    if (depth > 2) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { scan(full, depth + 1); continue; }
      if (/\.(edb|db)$/i.test(e.name)) continue;
      let size = 0;
      try { size = fs.statSync(full).size; } catch { continue; }
      if (size > 8 * 1024 * 1024) continue;
      try {
        const text = fs.readFileSync(full, 'latin1');
        for (const [key, re] of Object.entries(UID_PATTERNS)) {
          for (const m of text.matchAll(re)) {
            const n = m[1];
            if (n !== '0') counts[key].set(n, (counts[key].get(n) || 0) + 1);
          }
        }
      } catch { /* 忽略不可读文件 */ }
    }
  };
  scan(base, 0);
  return { base, counts, candidates: weightedUserId(counts) };
}

/** 按 kdevil2k 权重（from 0.9 / user_id 0.6 / nt 0.15 / equal 0.1）加权排序 */
function weightedUserId(counts) {
  const weight = { from: 0.9, user_id: 0.6, nt: 0.15, equal: 0.1 };
  const combined = new Map();
  for (const [key, map] of Object.entries(counts)) {
    for (const [num, cnt] of map) {
      combined.set(num, (combined.get(num) || 0) + cnt * weight[key]);
    }
  }
  return [...combined.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([num, score]) => ({ num, score: Math.round(score * 100) / 100 }));
}

/* ============ userId 还原：内存 dump（PowerShell） ============ */

/** 写出内存 dump 用的 PowerShell 脚本（P/Invoke ReadProcessMemory，仅同用户权限） */
function writeMemoryDumpScript(tmpDir) {
  const ps1 = path.join(tmpDir, 'kkv-dump.ps1');
  const script = String.raw`
param([int]$TargetPid, [string]$OutFile, [switch]$PrivateOnly)
$sig = @"
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
"@
Add-Type -TypeDefinition $sig
$h = [KkvMem]::OpenProcess(0x0410, $false, $TargetPid)
if ($h -eq [IntPtr]::Zero) { Write-Error 'OpenProcess failed'; exit 1 }
$buf = New-Object byte[] 16777216
$read = 0
# 阶段1：枚举所有 region
$regions = New-Object System.Collections.Generic.List[object]
$addr = [IntPtr]::Zero
$commitCount = 0
while ($true) {
  $mbi = New-Object KkvMem+MEMORY_BASIC_INFORMATION
  $ret = [KkvMem]::VirtualQueryEx($h, $addr, [ref]$mbi, [Runtime.InteropServices.Marshal]::SizeOf($mbi))
  if ($ret -eq [IntPtr]::Zero) { break }
  $region = [int64]$mbi.RegionSize
  if ($mbi.State -eq 0x1000 -and $region -gt 0 -and $region -le 268435456) {
    $commitCount++
    # 可读保护位（0x02/0x04/0x08/0x20/0x40/0x80），排除 PAGE_GUARD(0x100)；PrivateOnly 时仅 MEM_PRIVATE(0x20000) 堆内存
    $protOk = (($mbi.Protect -band 0xEE) -ne 0) -and (($mbi.Protect -band 0x100) -eq 0)
    $typeOk = (-not $PrivateOnly) -or ($mbi.Type -eq 0x20000)
    if ($protOk -and $typeOk) {
      $regions.Add([pscustomobject]@{ Base = [int64]$mbi.BaseAddress; Size = $region })
    }
  }
  $addr = [IntPtr]([int64]$mbi.BaseAddress + $region)
  if ([int64]$addr -le 0) { break }
}
$matchedCount = $regions.Count
# 阶段2：按 size 降序排序（kakaocli-win 实测：KakaoTalk 的 SQLCipher raw key 多驻留在大私有堆 ≥800KB，让大 region 优先被 Node 扫描到）
$sorted = $regions | Sort-Object -Property Size -Descending
# 阶段3：按顺序读取并写入 dump
$fs = [System.IO.File]::Create($OutFile)
$totalBytes = [long]0
foreach ($r in $sorted) {
  $remain = $r.Size
  $cur = $r.Base
  while ($remain -gt 0) {
    $take = [int][Math]::Min($remain, $buf.Length)
    $ok = [KkvMem]::ReadProcessMemory($h, [IntPtr]$cur, $buf, $take, [ref]$read)
    if ($ok -and $read -gt 0) { $fs.Write($buf, 0, $read); $totalBytes += $read }
    $cur += $take
    $remain -= $take
  }
}
$fs.Close()
Write-Output ("DUMPSTATS commit=$commitCount matched=$matchedCount bytes=$totalBytes regions=$($sorted.Count)")
`;
  fs.writeFileSync(ps1, script, 'utf8');
  return ps1;
}

/**
 * dump 指定进程内存到临时文件（P/Invoke，仅同用户权限）；调用方负责删除 dump 文件
 * privateOnly=true 时仅导出 MEM_PRIVATE 堆内存（体积小，SQLCipher 密钥扫描用）
 * @returns {Promise<{ok:boolean, dumpPath?:string, reason?:string}>}
 */
function dumpProcessMemory(pid, timeoutMs = 300000, { privateOnly = false } = {}) {
  return new Promise((resolve) => {
    const dumpPath = path.join(os.tmpdir(), `kkv-mem-${pid}${privateOnly ? '-p' : ''}.dmp`);
    const ps1 = writeMemoryDumpScript(os.tmpdir());
    const args = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ps1, '-TargetPid', String(pid), '-OutFile', dumpPath];
    if (privateOnly) args.push('-PrivateOnly');
    const child = spawn('powershell.exe', args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    let stdout = '';
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    const timer = setTimeout(() => { try { child.kill(); } catch { /* 忽略 */ } }, timeoutMs);
    child.on('close', (code) => {
      clearTimeout(timer);
      const m = stdout.match(/DUMPSTATS commit=(\d+) matched=(\d+) bytes=(\d+)(?: regions=(\d+))?/);
      const dumpStats = m
        ? { commit: Number(m[1]), matched: Number(m[2]), bytes: Number(m[3]), regions: m[4] ? Number(m[4]) : null }
        : null;
      let size = 0;
      try { size = fs.statSync(dumpPath).size; } catch { /* 文件不存在 */ }
      if (code !== 0 || !fs.existsSync(dumpPath)) {
        return resolve({ ok: false, reason: '内存导出失败：' + (stderr.trim() || `exit ${code}`), dumpStats, size });
      }
      resolve({ ok: true, dumpPath, dumpStats, size });
    });
  });
}

/**
 * dump KakaoTalk 进程内存并提取 userId 候选（加权统计）
 * @returns {Promise<{ok:boolean, candidates:Array, reason?:string, dumpPath?:string}>}
 */
async function extractUserIdFromMemory(timeoutMs = 300000) {
  const { running, pids } = await isKakaoTalkRunning();
  if (!running) return { ok: false, candidates: [], reason: 'KakaoTalk 未在运行，无法扫描内存' };
  const dump = await dumpProcessMemory(pids[0], timeoutMs);
  if (!dump.ok) return { ok: false, candidates: [], reason: dump.reason };
  try {
    const candidates = scanDumpForUserId(dump.dumpPath);
    return { ok: candidates.length > 0, candidates, dumpPath: dump.dumpPath };
  } catch (e) {
    return { ok: false, candidates: [], reason: '内存分析失败：' + e.message };
  }
}

/** 流式扫描 dump 文件，跑四种 userId 正则并加权 */
function scanDumpForUserId(dumpPath) {
  const counts = { from: new Map(), user_id: new Map(), nt: new Map(), equal: new Map() };
  const fd = fs.openSync(dumpPath, 'r');
  const size = fs.fstatSync(fd).size;
  const CHUNK = 8 * 1024 * 1024;
  const OVERLAP = 64; // 正则跨界重叠
  const buf = Buffer.alloc(CHUNK + OVERLAP);
  let tail = Buffer.alloc(0);
  for (let off = 0; off < size; off += CHUNK) {
    const got = fs.readSync(fd, buf, 0, CHUNK + OVERLAP, off);
    if (got <= 0) break;
    const text = Buffer.concat([tail, buf.subarray(0, got)]).toString('latin1');
    tail = Buffer.from(text.slice(text.length - OVERLAP), 'latin1');
    for (const [key, re] of Object.entries(UID_PATTERNS)) {
      re.lastIndex = 0;
      for (const m of text.matchAll(re)) {
        const n = m[1];
        if (n !== '0') counts[key].set(n, (counts[key].get(n) || 0) + 1);
      }
    }
  }
  fs.closeSync(fd);
  try { fs.unlinkSync(dumpPath); } catch { /* 清理失败不阻塞 */ }
  return weightedUserId(counts);
}

/* ============ SQLCipher 4：内存 raw key 恢复（新版 KakaoTalk EDB）============ */

const SQLITE_HEAD_BUF = Buffer.from(SQLITE_HEAD, 'latin1');

/**
 * 流式扫描 dump 提取 SQLCipher raw key 候选（64 位 hex）。
 * 优先 x'…' 包装形式（SQLCipher PRAGMA key 原始格式）；includeBare=true 时扩大到裸 64hex。
 */
function scanDumpForRawKeys(dumpPath, { includeBare = false, maxKeys = 200000 } = {}) {
  const wrapped = new Set();
  const bare = new Set();
  const WRAP_RE = /x'([0-9a-fA-F]{64})'/g;
  const BARE_RE = /\b[0-9a-fA-F]{64}\b/g;
  const fd = fs.openSync(dumpPath, 'r');
  const size = fs.fstatSync(fd).size;
  const CHUNK = 8 * 1024 * 1024;
  const OVERLAP = 128; // 正则跨界重叠
  const buf = Buffer.alloc(CHUNK + OVERLAP);
  let tail = Buffer.alloc(0);
  for (let off = 0; off < size; off += CHUNK) {
    const got = fs.readSync(fd, buf, 0, CHUNK + OVERLAP, off);
    if (got <= 0) break;
    const text = Buffer.concat([tail, buf.subarray(0, got)]).toString('latin1');
    tail = Buffer.from(text.slice(text.length - OVERLAP), 'latin1');
    for (const m of text.matchAll(WRAP_RE)) wrapped.add(m[1].toLowerCase());
    if (includeBare) {
      for (const m of text.matchAll(BARE_RE)) {
        const v = m[0].toLowerCase();
        if (!wrapped.has(v)) bare.add(v);
      }
    }
    if (wrapped.size + bare.size > maxKeys) break;
  }
  fs.closeSync(fd);
  return { keys: [...wrapped, ...bare], wrappedCount: wrapped.size };
}

/** 用页1验证 SQLCipher raw key；命中返回页参数。
 * 加密库页1前 16 字节是随机盐（覆盖了 SQLite 文件头），解密数据从 header offset16 开始：
 * 验证 page_size 大端值、恒定魔数 0x40 0x20 0x20、reserved == 16+hmacSize（自动区分变体） */
function trySqlCipherParams(edbBuf, keyBytes) {
  if (!Buffer.isBuffer(keyBytes) || keyBytes.length !== 32) return null;
  if (!Buffer.isBuffer(edbBuf) || edbBuf.length < 1024) return null;
  for (const pageSize of [4096, 1024]) {
    if (edbBuf.length < pageSize) continue;
    for (const hmacSize of [64, 32, 0]) {
      const ivOff = pageSize - hmacSize - 16;
      if (ivOff <= 16) continue;
      let d;
      try {
        d = crypto.createDecipheriv('aes-256-cbc', keyBytes, edbBuf.subarray(ivOff, ivOff + 16));
      } catch {
        return null; // key/iv 非法
      }
      d.setAutoPadding(false);
      const dec = d.update(edbBuf.subarray(16, 16 + 32)); // 页1密文头（盐后 32 字节）
      if (
        dec[0] === (pageSize >> 8) && dec[1] === (pageSize & 0xff) &&
        dec[4] === 16 + hmacSize &&
        dec[5] === 0x40 && dec[6] === 0x20 && dec[7] === 0x20
      ) return { pageSize, hmacSize };
    }
  }
  return null;
}

/**
 * SQLCipher 页级解密：每页 [密文 data][IV][HMAC] → 明文页尾补零（保留区），
 * 页1 前部 16 字节盐明文还原为 SQLite 头。产物可被标准 SQLite/SQLCipher 打开。
 */
function decryptSqlCipherEdb(buf, keyBytes, pageSize, hmacSize) {
  const dataLen = pageSize - 16 - hmacSize;
  const pages = Math.floor(buf.length / pageSize);
  const out = Buffer.alloc(pages * pageSize);
  SQLITE_HEAD_BUF.copy(out, 0);
  for (let p = 0; p < pages; p++) {
    const base = p * pageSize;
    const start = p === 0 ? 16 : base; // 页1 跳过明文盐
    const len = p === 0 ? dataLen - 16 : dataLen;
    const ivOff = base + pageSize - hmacSize - 16;
    const d = crypto.createDecipheriv('aes-256-cbc', keyBytes, buf.subarray(ivOff, ivOff + 16));
    d.setAutoPadding(false);
    const dec = Buffer.concat([d.update(buf.subarray(start, start + len)), d.final()]);
    dec.copy(out, base + (p === 0 ? 16 : 0));
    if (p === 0) out[20] = 0; // 关键：清零 SQLite header byte 20（reserved space），SQLCipher 把它当 codec 保留（=80），plain SQLite 必须为 0
  }
  return out;
}

const PGNO1_LE = Buffer.from([1, 0, 0, 0]);

/**
 * SQLCipher 4 页1 HMAC 精验（对照官方源码 sqlcipher.c，已经 vendor wasm 真库验证）：
 *   hmac_key = PBKDF2-HMAC-SHA512(cipher_key, 页1盐 ^ 0x3a, iter=2, 32B)
 *   页1 HMAC = HMAC(hmac_key, page[16 .. pageSize-hmacSize] || pgno_LE(1))（跳过 16 字节盐）
 * hmacSize=64→SHA512，32→SHA256；0（无 HMAC 变体）不支持精验，返回 false。
 */
function verifySqlCipherHmac(edbBuf, keyBytes, pageSize = 4096, hmacSize = 64) {
  if (hmacSize !== 64 && hmacSize !== 32) return false;
  if (!Buffer.isBuffer(edbBuf) || edbBuf.length < pageSize) return false;
  if (!Buffer.isBuffer(keyBytes) || keyBytes.length !== 32) return false;
  const saltXor = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) saltXor[i] = edbBuf[i] ^ 0x3a;
  const hmacKey = crypto.pbkdf2Sync(keyBytes, saltXor, 2, 32, 'sha512');
  const h = crypto.createHmac(hmacSize === 64 ? 'sha512' : 'sha256', hmacKey);
  h.update(edbBuf.subarray(16, pageSize - hmacSize));
  h.update(PGNO1_LE);
  return h.digest().equals(edbBuf.subarray(pageSize - hmacSize, pageSize));
}

/** 只读 EDB 头部若干字节（探针用，避免整读大文件） */
function readEdbHead(edb, bytes) {
  if (edb.data instanceof ArrayBuffer) return Buffer.from(edb.data).subarray(0, bytes);
  if (ArrayBuffer.isView(edb.data)) {
    return Buffer.from(edb.data.buffer, edb.data.byteOffset, edb.data.byteLength).subarray(0, bytes);
  }
  const fd = fs.openSync(edb.path, 'r');
  try {
    const buf = Buffer.alloc(bytes);
    const got = fs.readSync(fd, buf, 0, bytes, 0);
    return got > 0 ? buf.subarray(0, got) : buf.subarray(0, 0);
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * SQLCipher 探针选择：优先登录后必然被加载的库（其 key 大概率在内存中）。
 * 入参按 size 降序；返回最多 max 个。
 */
function pickSqlCipherProbes(edbsDesc, max = 3) {
  const out = [];
  const push = (e) => { if (e && !out.includes(e)) out.push(e); };
  const find = (re) => edbsDesc.find((e) => re.test(e.name));
  push(find(/^TalkUserDB\.edb$/i)); // 登录后常驻
  push(find(/^chatListInfo\.edb$/i)); // 聊天列表
  push(find(/^chatLogs[_-]\d+\.edb$/i)); // 降序下第一个 = 最大 chatLogs（最可能被打开过）
  push(edbsDesc[edbsDesc.length - 1]); // 最小文件兜底
  return out.slice(0, max).filter((e) => (e.size == null ? true : e.size >= 4096));
}

/**
 * 二进制窗口扫描：对 dump 以 32 字节/step 步进窗口做快速过滤
 *  1. 向量化预过滤（kakaocli-win 同款）：32 字节窗口内 0x00 字节数 ≤ 4 且可打印 ASCII 字符数 ≤ 27
 *  2. 多样性检查：32 字节内不同字节数 ≥ 18
 *  3. AES 解密探针页1首块检查 SQLite 头特征
 * 命中窗口收为候选，由调用方 HMAC 精验。
 * @param {string} dumpPath 内存 dump 文件
 * @param {Array<{name:string,buf:Buffer}>} probes 探针页1头部（≥ pageSize）
 * @returns {{candidates:Array<{keyHex:string,probe:string,pageSize:number,hmacSize:number}>, scanned:number, filtered:number}}
 */
function scanDumpForBinaryKeys(dumpPath, probes, { step = 4, variants = [[4096, 64]], maxCandidates = 50000, onProgress } = {}) {
  const checks = [];
  for (const p of probes) {
    for (const [pageSize, hmacSize] of variants) {
      const ivOff = pageSize - hmacSize - 16;
      if (!p.buf || p.buf.length < pageSize || ivOff <= 16) continue;
      checks.push({
        name: p.name, pageSize, hmacSize,
        ct: p.buf.subarray(16, 32), // 页1密文首块（盐后 16 字节）
        iv: p.buf.subarray(ivOff, ivOff + 16),
        pgHi: pageSize >> 8, pgLo: pageSize & 0xff, reserved: 16 + hmacSize,
      });
    }
  }
  if (!checks.length) return { candidates: [], scanned: 0, filtered: 0 };
  const candidates = [];
  const seen = new Set();
  const fd = fs.openSync(dumpPath, 'r');
  const size = fs.fstatSync(fd).size;
  const CHUNK = 16 * 1024 * 1024;
  const OVERLAP = 32 + step; // 覆盖跨块窗口
  const buf = Buffer.alloc(CHUNK + OVERLAP);
  let scanned = 0;
  let filtered = 0; // 向量化过滤掉的窗口数
  let lastReport = 0;
  let done = false;
  for (let off = 0; off < size && !done; off += CHUNK) {
    const got = fs.readSync(fd, buf, 0, CHUNK + OVERLAP, off);
    if (got <= 32) break;
    const limit = Math.min(CHUNK - step, got - 32); // 与下一块无缝衔接（CHUNK 是 step 的倍数）
    // 向量化预过滤：单次 O(n) 扫描算 zero/printable 累加和，内层只查表 O(1)
    const usableLen = limit + step; // 最远需要读到 limit+32-1
    const zeroPrefix = new Int32Array(usableLen + 1);
    const printablePrefix = new Int32Array(usableLen + 1);
    for (let i = 0; i < usableLen; i++) {
      const b = buf[i];
      zeroPrefix[i + 1] = zeroPrefix[i] + (b === 0 ? 1 : 0);
      printablePrefix[i + 1] = printablePrefix[i] + ((b >= 0x20 && b <= 0x7E) ? 1 : 0);
    }
    // 收集通过快速过滤的窗口起点
    const offsets = [];
    for (let i = 0; i <= limit; i += step) {
      const zeros = zeroPrefix[i + 32] - zeroPrefix[i];
      const printable = printablePrefix[i + 32] - printablePrefix[i];
      if (zeros <= 4 && printable <= 27) offsets.push(i);
      else filtered++;
    }
    scanned += offsets.length;
    for (const i of offsets) {
      const keyBytes = buf.subarray(i, i + 32);
      // 多样性检查：32 字节内不同字节数 ≥ 18（kakaocli-win 经验：堆元数据/指针域通不过此阈）
      const uniq = new Uint8Array(256);
      let uniqCount = 0;
      for (let j = 0; j < 32; j++) {
        if (!uniq[keyBytes[j]]) { uniq[keyBytes[j]] = 1; uniqCount++; }
        if (uniqCount + (32 - j - 1) < 18) break; // 提前退出：剩余字节即使全不同也凑不到 18
      }
      if (uniqCount < 18) continue;
      for (const c of checks) {
        const d = crypto.createDecipheriv('aes-256-cbc', keyBytes, c.iv);
        d.setAutoPadding(false);
        const dec = d.update(c.ct);
        if (
          dec[0] === c.pgHi && dec[1] === c.pgLo && dec[4] === c.reserved &&
          dec[5] === 0x40 && dec[6] === 0x20 && dec[7] === 0x20
        ) {
          const keyHex = keyBytes.toString('hex');
          if (!seen.has(keyHex)) {
            seen.add(keyHex);
            candidates.push({ keyHex, probe: c.name, pageSize: c.pageSize, hmacSize: c.hmacSize });
            if (candidates.length >= maxCandidates) { done = true; break; }
          }
        }
      }
    }
    if (onProgress && off - lastReport >= 64 * 1024 * 1024) {
      lastReport = off;
      onProgress(scanned, Math.min(off + CHUNK, size), size);
    }
  }
  fs.closeSync(fd);
  return { candidates, scanned, filtered };
}

/** hex 候选密钥在探针上验证（解密头特征），返回全部命中 [{keyHex,pageSize,hmacSize,probe}] */
function verifyHexKeys(keys, probeHeads, report, label) {
  const hits = [];
  let tried = 0;
  for (const hex of keys) {
    tried++;
    if (tried % 5000 === 0) report('solve', `${label}：已验证 ${tried}/${keys.length} 个密钥候选…`);
    const keyBytes = Buffer.from(hex, 'hex');
    for (const p of probeHeads) {
      const params = trySqlCipherParams(p.buf, keyBytes);
      if (params) {
        hits.push({ keyHex: hex, ...params, probe: p.name });
        break; // 同一 key 只记一次
      }
    }
  }
  return hits;
}

/** SQLCipher 全部支持的 (pageSize, hmacSize) 变体（kakaocli-win 实机验证：KakaoTalk 可能使用非默认组合） */
const SQLCIPHER_VARIANTS = [[4096, 64], [4096, 32], [4096, 0], [1024, 64], [1024, 32], [1024, 0]];

/**
 * 二进制扫描多轮策略：
 *  A = step4 × 全部 6 种参数变体 × 全部探针（≈每百 MB 1-2 分钟）
 *  B = step1 × 全部变体 × 首探针（兜底：key 未对齐）
 * 每轮候选先 HMAC 精验再解密特征确认，双保险排除误报；
 * 返回该轮全部真 key（不同 EDB 可能用不同 key，需全部收集）。
 */
function runBinaryRounds(dumpPath, probeHeads, report, stats) {
  const rounds = [
    { label: '二进制扫描（步进4，SQLCipher 4 全部 6 种参数变体）', step: 4, probes: probeHeads },
    { label: '二进制扫描（步进1，6 种参数变体，首探针）', step: 1, probes: probeHeads.slice(0, 1) },
  ];
  for (const r of rounds) {
    report('solve', `${r.label}…`);
    const { candidates, scanned } = scanDumpForBinaryKeys(dumpPath, r.probes, {
      step: r.step,
      variants: SQLCIPHER_VARIANTS,
      onProgress: (n, doneBytes, total) => {
        report('solve', `${r.label}：${(doneBytes / 1048576).toFixed(0)}/${(total / 1048576).toFixed(0)} MB，累计窗口 ${n}…`);
      },
    });
    stats.binScanned += scanned;
    stats.binCandidates += candidates.length;
    stats.rounds.push(`${r.label}:窗口${scanned}/候选${candidates.length}`);
    const hits = [];
    for (const c of candidates) {
      const keyBytes = Buffer.from(c.keyHex, 'hex');
      const p = probeHeads.find((x) => x.name === c.probe) || probeHeads[0];
      const okHmac = verifySqlCipherHmac(p.buf, keyBytes, c.pageSize, c.hmacSize);
      const params = trySqlCipherParams(p.buf, keyBytes);
      if (okHmac && params) hits.push({ keyHex: c.keyHex, ...params, probe: c.probe });
    }
    if (hits.length) return hits;
    if (candidates.length) report('solve', `${r.label}：${candidates.length} 个过滤候选均未通过 HMAC 精验`);
  }
  return [];
}

/** 命中密钥集解密全部 EDB（各库可能 key/页参数不同，逐库在密钥集上自适应验证） */
function decryptWithSqlCipherKeys(hits, usable, report) {
  report('found', `SQLCipher 密钥命中 ${hits.length} 把：${hits.map((h) => `${h.keyHex.slice(0, 12)}…(${h.probe})`).join('、')}`);
  const files = [];
  let skipped = 0;
  const usedKeys = new Set();
  for (let i = 0; i < usable.length; i++) {
    const edb = usable[i];
    report('decrypt', `解密 ${edb.name}（${i + 1}/${usable.length}）…`);
    try {
      const buf = readEdbBuffer(edb);
      let plain = null;
      for (const hit of hits) {
        const keyBytes = Buffer.from(hit.keyHex, 'hex');
        // 每个 EDB 可能用不同 key/参数：先自身页1解密特征验证，再 HMAC 精验兜底
        const params = trySqlCipherParams(buf, keyBytes) ||
          (verifySqlCipherHmac(buf, keyBytes, hit.pageSize, hit.hmacSize) ? { pageSize: hit.pageSize, hmacSize: hit.hmacSize } : null);
        if (!params) continue;
        const out = decryptSqlCipherEdb(buf, keyBytes, params.pageSize, params.hmacSize);
        if (out.subarray(0, 16).equals(SQLITE_HEAD_BUF)) {
          plain = out;
          usedKeys.add(hit.keyHex);
          break;
        }
      }
      if (plain) {
        files.push({ name: edb.name, path: edb.path, chatId: edb.chatId, size: edb.size, data: new Uint8Array(plain) });
      } else {
        skipped++;
      }
    } catch (e) {
      report('warn', `${edb.name} 解密失败：${e.message}`);
    }
  }
  if (!files.length) return { ok: false, reason: '密钥命中探针但没有任何 EDB 解密成功' };
  if (skipped) report('warn', `${skipped} 个 EDB 使用不同密钥或数据异常，已跳过（在 KakaoTalk 中打开对应聊天后重试可补全）`);
  const first = hits.find((h) => usedKeys.has(h.keyHex)) || hits[0];
  return {
    ok: true,
    params: { kind: 'sqlcipher', keyHex: first.keyHex, keyCount: hits.length, userId: null, pragma: null },
    files,
  };
}

/**
 * SQLCipher 内存密钥恢复路线：dump KakaoTalk 进程私有内存 → hex 文本扫描 +
 * 二进制窗口扫描（AES 过滤 + HMAC 精验）→ 命中后解密全部（不依赖设备材料与 userId）。
 * 探针优先 TalkUserDB/chatListInfo/最大 chatLogs（登录后必然被加载，key 在内存概率最高）。
 */
async function trySqlCipherFromMemory(edbs, onProgress) {
  const report = onProgress || (() => {});
  const { running, pids } = await isKakaoTalkRunning();
  if (!running) return { ok: false, reason: '内存密钥恢复需要 KakaoTalk 正在运行（请先启动并登录 KakaoTalk）' };
  const usable = edbs.filter((e) => (e.size == null ? true : e.size >= 4096)); // SQLCipher 验证至少需要一整页
  if (!usable.length) return { ok: false, reason: '没有足够大（≥4KB）的 EDB 文件可用于 SQLCipher 密钥验证' };
  const desc = [...usable].sort((a, b) => (b.size || 0) - (a.size || 0));
  const probes = pickSqlCipherProbes(desc, 3);
  const probeInfo = [];
  const probeHeads = probes.map((p) => {
    let buf = Buffer.alloc(0);
    try {
      buf = readEdbHead(p, 8192);
    } catch (e) {
      probeInfo.push(`${p.name}:读取失败(${e.code || e.message})`);
      return { name: p.name, buf };
    }
    if (buf.length >= 4096) probeInfo.push(`${p.name}:${buf.length}B`);
    else probeInfo.push(`${p.name}:仅${buf.length}B(不足一页,可能被占用)`);
    return { name: p.name, buf };
  });
  report('solve', `SQLCipher 探针：${probeInfo.join('、')}`);

  const stats = { pidsFound: pids.length, pids: [], dumpMB: 0, dumpStats: null, probeInfo, hexWrapped: 0, hexBare: 0, binScanned: 0, binCandidates: 0, rounds: [] };
  for (const pid of pids.slice(0, 3)) {
    report('solve', `导出 KakaoTalk 进程内存（PID ${pid}，仅私有内存）…`);
    let dump = await dumpProcessMemory(pid, 300000, { privateOnly: true });
    if (dump.ok && (dump.size || 0) < 1024 * 1024) {
      // 私有内存过滤在本机可能过严（不同 KakaoTalk 版本内存布局差异）：回退导出全部可读内存
      report('warn', `PID ${pid} 私有内存仅 ${((dump.size || 0) / 1048576).toFixed(1)}MB，回退导出全部可读内存…`);
      const full = await dumpProcessMemory(pid, 300000, { privateOnly: false });
      if (full.ok && (full.size || 0) > (dump.size || 0)) {
        try { fs.unlinkSync(dump.dumpPath); } catch { /* 忽略 */ }
        dump = full;
      } else if (full.ok) {
        try { fs.unlinkSync(full.dumpPath); } catch { /* 忽略 */ }
      }
    }
    if (!dump.ok) {
      report('warn', `PID ${pid} 内存导出失败：${dump.reason}`);
      continue;
    }
    stats.pids.push(pid);
    const dumpSize = dump.size || 0;
    stats.dumpMB = Math.max(stats.dumpMB, Math.round((dumpSize / 1048576) * 10) / 10);
    if (dump.dumpStats) stats.dumpStats = dump.dumpStats;
    report('solve', `内存导出完成（${(dumpSize / 1048576).toFixed(0)} MB），开始扫描密钥…`);
    try {
      // 轮1：hex 文本形态密钥（x'' 包装优先，再裸 64hex），秒级
      let scan = scanDumpForRawKeys(dump.dumpPath, { includeBare: false });
      stats.hexWrapped = scan.keys.length;
      let hits = verifyHexKeys(scan.keys, probeHeads, report, '包装密钥');
      if (!hits.length) {
        scan = scanDumpForRawKeys(dump.dumpPath, { includeBare: true });
        stats.hexBare = scan.keys.length;
        hits = verifyHexKeys(scan.keys, probeHeads, report, '全量 hex 候选');
      }
      // 轮2：二进制窗口扫描（key 不以文本形态存在时）
      if (!hits.length) {
        report('solve', '内存中未发现文本形态密钥，开始二进制窗口扫描（约 2-6 分钟，请耐心等待）…');
        hits = runBinaryRounds(dump.dumpPath, probeHeads, report, stats);
      }
      if (hits.length) {
        const dec = decryptWithSqlCipherKeys(hits, usable, report);
        if (dec.ok) return dec;
        report('warn', `${dec.reason}，继续扫描其它进程/轮次…`);
      }
    } finally {
      try { fs.unlinkSync(dump.dumpPath); } catch { /* 清理失败不阻塞 */ }
    }
  }
  const dstat = stats.dumpStats
    ? `，提交区 ${stats.dumpStats.commit}/命中 ${stats.dumpStats.matched}${stats.dumpStats.regions != null ? `/region ${stats.dumpStats.regions}` : ''}`
    : '';
  return {
    ok: false,
    reason: `内存中未找到有效 SQLCipher 密钥（发现进程 ${stats.pidsFound} 个/成功导出 [${stats.pids.join(',') || '无'}]，导出内存 ${stats.dumpMB}MB${dstat}，探针[${stats.probeInfo.join(' ')}]，hex候选=${stats.hexWrapped}+${stats.hexBare}，二进制扫描窗口=${stats.binScanned}，过滤候选=${stats.binCandidates}，轮次=[${stats.rounds.join(' | ') || '无'}]）。请确认 KakaoTalk 已登录并打开过聊天列表/聊天窗口`,
  };
}

/* ============ 汇总：Windows 自动发现 ============ */

/**
 * Windows 自动发现入口：注册表材料 + users 目录 + EDB 清单 + userId 候选
 */
async function discoverWindows() {
  const [dev, edbInfo, procInfo, fileUid] = await Promise.all([
    readDeviceInfo(),
    Promise.resolve(listEdbFiles()),
    isKakaoTalkRunning(),
    Promise.resolve(extractUserIdFromFiles()),
  ]);
  return {
    platform: 'win32',
    devOk: dev.ok,
    devIds: dev.devIds,
    materials: dev.materials,
    baseDir: edbInfo.base,
    usersDir: edbInfo.usersDir,
    edbs: edbInfo.edbs,
    running: procInfo.running,
    pids: procInfo.pids,
    userIdCandidates: fileUid.candidates,
    fileUidSource: 'KakaoTalk 目录文件扫描',
    registryFields: dev.fields,
  };
}

/** 读取 EDB 数据：支持磁盘路径（自动模式）与直传字节（手动模式） */
function readEdbBuffer(edb) {
  if (edb.data instanceof ArrayBuffer) return Buffer.from(edb.data);
  if (ArrayBuffer.isView(edb.data)) return Buffer.from(edb.data.buffer, edb.data.byteOffset, edb.data.byteLength);
  return fs.readFileSync(edb.path);
}

/**
 * 解密全部 EDB：先在最小文件上求解参数，再批量解密
 * @param {Array<{path?:string,name:string,size?:number,chatId:?string,data?:Uint8Array|ArrayBuffer}>} edbs
 * @param {Array} materials 设备材料变体
 * @param {Array<number|string>} userIdCandidates userId 候选（可被调用方合并人工输入）
 * @param {(stage:string, detail:string)=>void} onProgress 进度回调
 * @returns {Promise<{ok:boolean, params?:object, files?:Array, reason?:string}>}
 */
async function decryptAllEdbs(edbs, materials, userIdCandidates, onProgress) {
  if (!edbs.length) return { ok: false, reason: '未找到 EDB 数据库文件' };
  const report = onProgress || (() => {});
  const sorted = [...edbs].filter((e) => (e.size == null ? true : e.size >= 16)).sort((a, b) => Math.max(a.size || 0, 1) - Math.max(b.size || 0, 1)); // 最小文件先试（求解最快）
  if (!sorted.length) return { ok: false, reason: 'EDB 文件均为空或过小' };
  if (!materials.length) {
    // 无设备材料时旧算法路线不可用，但新版 SQLCipher 内存密钥路线不依赖材料/userId
    report('solve', '注册表无设备材料，直接尝试 SQLCipher 内存密钥恢复…');
    const mem = await trySqlCipherFromMemory(sorted, report);
    if (mem.ok) return mem;
    return { ok: false, reason: `注册表中未找到设备材料（dev_id），且${mem.reason}` };
  }
  let params = null;
  let probeBuf = null;
  let probePath = null;
  for (const edb of sorted) {
    report('solve', `在 ${edb.name} 上求解解密参数…`);
    try {
      probeBuf = readEdbBuffer(edb);
      probePath = edb.path || edb.name;
    } catch (e) {
      return { ok: false, reason: `无法读取 ${edb.name}：${e.message}` };
    }
    params = solveEdbParams(probeBuf, materials, userIdCandidates);
    if (params) break;
  }
  if (!params) {
    report('solve', '设备材料派生路线未命中，尝试 SQLCipher 内存密钥恢复…');
    const mem = await trySqlCipherFromMemory(sorted, report);
    if (mem.ok) return mem;
    const labels = materials.map((m) => `${m.label}(${m.input.slice(0, 24)}${m.input.length > 24 ? '…' : ''})`).join('；');
    return {
      ok: false,
      reason: `未找到有效解密参数：${materials.length} 种材料 × ${CANDIDATE_KEYS.length} 个内置key × ${userIdCandidates.length} 个userId候选 全部不匹配；${mem.reason}。` +
        `材料列表=[${labels}]，userId候选=[${userIdCandidates.map((u) => u.num || u).join(', ') || '无'}]，探针首16字节=[${probeBuf ? probeBuf.subarray(0, 16).toString('hex') : '不可读'}]。` +
        `请保持 KakaoTalk 登录并打开过聊天列表后重试；仍失败请运行 Release 页的 win-diagnostic.ps1 并发回输出`,
    };
  }
  report('found', `参数命中：keyIdx=${CANDIDATE_KEYS.indexOf(params.keyHex) + 1}，userId=${params.userId}，材料=${params.material.label}`);
  const files = [];
  for (let i = 0; i < sorted.length; i++) {
    const edb = sorted[i];
    if (edb.size === 0) continue;
    report('decrypt', `解密 ${edb.name}（${i + 1}/${sorted.length}）…`);
    try {
      const buf = (edb.path || edb.name) === probePath ? probeBuf : readEdbBuffer(edb);
      const { key, iv } = deriveKeyIv(params.pragma, params.userId);
      const plain = decryptEdb(buf, key, iv);
      if (plain.subarray(0, 16).toString('latin1') === SQLITE_HEAD) {
        files.push({ name: edb.name, path: edb.path, chatId: edb.chatId, size: edb.size, data: new Uint8Array(plain) });
      } else {
        report('warn', `${edb.name} 解密后不是有效 SQLite（密钥类别可能不同），已跳过`);
      }
    } catch (e) {
      report('warn', `${edb.name} 解密失败：${e.message}`);
    }
  }
  if (!files.length) return { ok: false, reason: '没有任何 EDB 解密成功' };
  return { ok: true, params, files };
}

module.exports = {
  CANDIDATE_KEYS,
  readDeviceInfo,
  buildMaterials,
  computePragma,
  deriveKeyIv,
  decryptEdb,
  firstBlockMatches,
  solveEdbParams,
  listEdbFiles,
  isKakaoTalkRunning,
  extractUserIdFromFiles,
  extractUserIdFromMemory,
  discoverWindows,
  decryptAllEdbs,
  kakaoBaseDir,
  dumpProcessMemory,
  scanDumpForRawKeys,
  trySqlCipherParams,
  decryptSqlCipherEdb,
  verifySqlCipherHmac,
  readEdbHead,
  pickSqlCipherProbes,
  scanDumpForBinaryKeys,
  verifyHexKeys,
  runBinaryRounds,
  decryptWithSqlCipherKeys,
  trySqlCipherFromMemory,
};
