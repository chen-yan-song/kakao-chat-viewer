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

/** 读取 HKCU\Software\Kakao\KakaoTalk\DeviceInfo 全部子键的 dev_id */
function readDeviceInfo() {
  return new Promise((resolve) => {
    execFile(
      'reg',
      ['query', 'HKCU\\Software\\Kakao\\KakaoTalk\\DeviceInfo', '/s'],
      { encoding: 'utf8', timeout: 15000, maxBuffer: 8 * 1024 * 1024, windowsHide: true },
      (err, stdout) => {
        if (err) return resolve({ ok: false, reason: err.message, devIds: [], materials: [] });
        const devIds = [];
        for (const line of String(stdout).split(/\r?\n/)) {
          // 形如：    dev_id    REG_SZ    uuid|model|serial
          const m = line.match(/^\s+dev_id\s+REG_[A-Z]+\s+(.+)$/i);
          if (m) devIds.push(m[1].trim());
        }
        resolve({ ok: devIds.length > 0, devIds, materials: buildMaterials(devIds) });
      }
    );
  });
}

/** 由 dev_id 生成材料变体（原串优先，三段拆分重组兜底） */
function buildMaterials(devIds) {
  const materials = [];
  for (const d of devIds) {
    const raw = d.trim();
    if (raw) materials.push({ input: raw, label: 'dev_id 原串' });
    if (raw.includes('|')) {
      const parts = raw.split('|').map((s) => s.trim());
      if (parts.length >= 3) {
        materials.push({ input: `${parts[0]}|${parts[1]}|${parts[2]}`, label: 'dev_id 三段重组' });
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
param([int]$TargetPid, [string]$OutFile)
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
$fs = [System.IO.File]::Create($OutFile)
$addr = [IntPtr]::Zero
$buf = New-Object byte[] 16777216
$read = 0
while ($true) {
  $mbi = New-Object KkvMem+MEMORY_BASIC_INFORMATION
  $ret = [KkvMem]::VirtualQueryEx($h, $addr, [ref]$mbi, [Runtime.InteropServices.Marshal]::SizeOf($mbi))
  if ($ret -eq [IntPtr]::Zero) { break }
  $region = [int64]$mbi.RegionSize
  if ($mbi.State -eq 0x1000 -and $region -gt 0 -and $region -le 268435456) {
    $remain = $region
    $cur = [int64]$mbi.BaseAddress
    while ($remain -gt 0) {
      $take = [int][Math]::Min($remain, $buf.Length)
      $ok = [KkvMem]::ReadProcessMemory($h, [IntPtr]$cur, $buf, $take, [ref]$read)
      if ($ok -and $read -gt 0) { $fs.Write($buf, 0, $read) }
      $cur += $take
      $remain -= $take
    }
  }
  $addr = [IntPtr]([int64]$mbi.BaseAddress + $region)
  if ([int64]$addr -le 0) { break }
}
$fs.Close()
`;
  fs.writeFileSync(ps1, script, 'utf8');
  return ps1;
}

/**
 * dump KakaoTalk 进程内存并提取 userId 候选（加权统计）
 * @returns {Promise<{ok:boolean, candidates:Array, reason?:string, dumpPath?:string}>}
 */
function extractUserIdFromMemory(timeoutMs = 300000) {
  return new Promise(async (resolve) => {
    const { running, pids } = await isKakaoTalkRunning();
    if (!running) return resolve({ ok: false, candidates: [], reason: 'KakaoTalk 未在运行，无法扫描内存' });
    const dumpPath = path.join(os.tmpdir(), `kkv-mem-${pids[0]}.dmp`);
    const ps1 = writeMemoryDumpScript(os.tmpdir());
    const child = spawn(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ps1, '-TargetPid', String(pids[0]), '-OutFile', dumpPath],
      { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] }
    );
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    const timer = setTimeout(() => { try { child.kill(); } catch { /* 忽略 */ } }, timeoutMs);
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0 || !fs.existsSync(dumpPath)) {
        return resolve({ ok: false, candidates: [], reason: '内存导出失败：' + (stderr.trim() || `exit ${code}`) });
      }
      try {
        const candidates = scanDumpForUserId(dumpPath);
        resolve({ ok: candidates.length > 0, candidates, dumpPath });
      } catch (e) {
        resolve({ ok: false, candidates: [], reason: '内存分析失败：' + e.message });
      }
    });
  });
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
  if (!materials.length) return { ok: false, reason: '注册表中未找到设备材料（dev_id），请确认已在 Windows 登录过 KakaoTalk' };
  const report = onProgress || (() => {});
  const sorted = [...edbs].filter((e) => (e.size == null ? true : e.size >= 16)).sort((a, b) => Math.max(a.size || 0, 1) - Math.max(b.size || 0, 1)); // 最小文件先试（求解最快）
  if (!sorted.length) return { ok: false, reason: 'EDB 文件均为空或过小' };
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
    return { ok: false, reason: `在 ${materials.length} 种材料 × ${CANDIDATE_KEYS.length} 个内置key × userId 候选范围内未找到有效解密参数（可手动填写 userId 重试）` };
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
};
