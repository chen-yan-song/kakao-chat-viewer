/**
 * 自动流程控制器（Mac App 模式）
 *
 * 目标：用户双击打开 App 即可拿到聊天记录——
 *   获取设备 UUID → 读取 KakaoTalk 偏好设置 → 还原 userId → 定位加密数据库 → 自动解密。
 *
 * 依赖注入：app.js 调用 registerAuto({ setStep, applyDiscovery, tryOpenDatabase, onEnterViewer })
 * Electron 桥接 API 挂在 window.kakaoApp（preload.cjs）。
 * 手动模式失败时自动展开原手动配置界面作为兜底。
 */
import { parsePlist, extractUserIdInfo } from './plistParser.js';

/** 自动流程步骤定义（与 index.html 中 li[data-step] 对应） */
export const AUTO_STEPS = ['uuid', 'plist', 'uid', 'db', 'decrypt'];

let controls = null;

/** 由 app.js 注入共享控制函数 */
export function registerAuto(ctl) {
  controls = ctl;
}

function setStep(name, state, detail) {
  if (controls) controls.setStep(name, state, detail);
  const line = `[auto] ${name}: ${state} ${detail || ''}`;
  if (inElectron()) window.kakaoApp.log(line);
  else console.log(line);
}

/** 是否在 Electron App 内运行 */
export function inElectron() {
  return typeof window !== 'undefined' && !!window.kakaoApp;
}

/** 是否 macOS 环境（自动发现依赖 macOS 沙盒容器与 ioreg） */
function isMacPlatform() {
  return /Macintosh|Mac OS X/.test(navigator.userAgent);
}

/** 是否 Windows 环境 */
function isWindowsPlatform() {
  return /Windows/.test(navigator.userAgent);
}

/** 运行全自动流程，成功返回 true；失败返回 false（并已显示手动兜底入口） */
export async function runAutoFlow() {
  if (!controls) return false;

  if (!inElectron()) {
    setStep('uuid', 'fail', '当前不在 App 环境中（浏览器访问请使用下方手动模式）');
    return false;
  }

  if (!isMacPlatform()) {
    if (isWindowsPlatform()) return runAutoFlowWindows();
    setStep('uuid', 'fail', '自动发现仅支持 macOS / Windows 版本（Linux 请使用手动模式）');
    return false;
  }

  let disc = null;
  try {
    disc = await window.kakaoApp.discover();
  } catch (e) {
    setStep('uuid', 'fail', '自动发现失败：' + e.message);
    return false;
  }

  // ---- 步骤 1：设备 UUID ----
  if (!disc.uuid) {
    setStep('uuid', 'fail', '无法读取本机 IOPlatformUUID');
    return false;
  }
  setStep('uuid', 'ok', disc.uuid);

  // ---- 步骤 2：读取偏好设置 plist ----
  let userIdInfo = null;
  if (disc.plist && disc.plist.byteLength > 0) {
    try {
      const plist = parsePlist(disc.plist);
      if (plist) {
        userIdInfo = extractUserIdInfo(plist);
        setStep('plist', 'ok', '已读取 com.kakao.KakaoTalkMac.plist');
      } else {
        setStep('plist', 'warn', 'plist 解析失败，尝试其他途径还原用户 ID');
      }
    } catch (e) {
      setStep('plist', 'warn', 'plist 解析异常：' + e.message);
    }
  } else {
    setStep('plist', 'warn', '未找到 KakaoTalk 偏好设置文件（可能尚未登录过 KakaoTalk）');
  }

  // ---- 步骤 3：还原 userId ----
  setStep('uid', 'active', '正在定位用户 ID…');
  let userId = null;
  let uidDetail = '';

  if (userIdInfo && userIdInfo.direct) {
    userId = userIdInfo.direct;
    uidDetail = `用户 ID ${userId}（来自偏好设置键）`;
  } else if (userIdInfo && userIdInfo.hash) {
    // plist 只存了 SHA-512(userId)，启动多线程爆破
    setStep('uid', 'active', '偏好设置中仅有用户 ID 哈希，正在多线程爆破还原（最多 10 亿个候选）…');
    const result = await bruteUserId(disc, userIdInfo.hash);
    if (result === null) return false; // 被中止或失败，setStep 已处理
    userId = result;
    uidDetail = `用户 ID ${userId}（SHA-512 爆破还原）`;
  } else if (userIdInfo && userIdInfo.candidates.length > 0) {
    userId = userIdInfo.candidates[0];
    uidDetail = `用户 ID ${userId}（候选列表第一个，共 ${userIdInfo.candidates.length} 个候选）`;
  }

  if (userId === null) {
    setStep('uid', 'fail', '无法从本机信息还原 KakaoTalk 用户 ID，请使用手动模式填写');
    return false;
  }
  setStep('uid', 'ok', uidDetail);

  // ---- 步骤 4：定位加密数据库 ----
  const mains = (disc.dbFiles || []).filter((f) => !f.isSide && f.size > 0);
  if (mains.length === 0) {
    setStep('db', 'fail', `数据库目录中没有可用的主库文件（${disc.dbDir}）`);
    return false;
  }
  const sides = (disc.dbFiles || []).filter((f) => f.isSide);
  controls.applyDiscovery({ uuid: disc.uuid, userId, mains, sides });
  const mainName = controls.state.mainFile ? controls.state.mainFile.name : mains[0].name;
  const sideNote = sides.length ? `（含 ${sides.length} 个伴随文件）` : '';
  setStep('db', 'ok', `已选中主库 ${mainName.slice(0, 16)}…${sideNote}`);

  // KakaoTalk 运行中的提示（不阻塞流程）
  if (disc.running) {
    controls.autoMsg(`检测到 KakaoTalk 正在运行：最新消息可能仍在 -wal 缓存中，若记录不全请退出 KakaoTalk 后点「重新自动检测」。`);
  }

  // ---- 步骤 5：派生密钥并解密 ----
  setStep('decrypt', 'active', '派生密钥（PBKDF2 100,000 次）并解密…');
  const ok = await controls.tryOpenDatabase();
  if (!ok) return false; // 失败详情由 openDatabase 的错误显示逻辑呈现

  setStep('decrypt', 'ok', '解密成功，正在加载聊天记录…');
  if (inElectron()) window.kakaoApp.log('[auto] 全部步骤完成');
  return true;
}

/**
 * Windows 全自动流程：注册表设备材料 → EDB 清单 → userId 还原（文件扫描/内存提取）→
 * 参数求解 → 按页 AES 解密 → 汇总统一库
 */
async function runAutoFlowWindows() {
  const app = window.kakaoApp;

  // ---- 步骤 1：设备材料（注册表 dev_id）----
  setStep('uuid', 'active', '正在读取注册表设备信息（DeviceInfo → dev_id）…');
  let disc;
  try {
    disc = await app.winDiscover();
  } catch (e) {
    setStep('uuid', 'fail', 'Windows 自动发现失败：' + e.message);
    return false;
  }
  if (!disc.devOk) {
    setStep('uuid', 'fail', '注册表中未找到设备材料（dev_id）——请确认已在本机登录过 KakaoTalk PC 版');
    return false;
  }
  setStep('uuid', 'ok', `${disc.devIds.length} 组设备材料（${disc.materials.map((m) => m.label).join(' / ')}）`);

  // ---- 步骤 2：EDB 数据文件清单 ----
  if (!disc.edbs.length) {
    setStep('plist', 'fail', `未找到 EDB 数据文件（${disc.usersDir || disc.baseDir}）——请确认已在 KakaoTalk 中同步过聊天记录`);
    return false;
  }
  const totalMB = disc.edbs.reduce((s, f) => s + (f.size || 0), 0) / 1024 / 1024;
  setStep('plist', 'ok', `找到 ${disc.edbs.length} 个 EDB 文件（共 ${totalMB.toFixed(1)} MB）`);
  if (disc.running) {
    controls.autoMsg('检测到 KakaoTalk 正在运行：将同时从进程内存提取用户 ID（成功率更高）；若记录不全请退出 KakaoTalk 后重新检测。');
  }

  // ---- 步骤 3：userId 还原 ----
  setStep('uid', 'active', '正在还原用户 ID…');
  let candidates = (disc.userIdCandidates || []).map((c) => c.num);
  if (candidates.length) {
    setStep('uid', 'active', `文件扫描候选：${candidates.join(', ')}`);
  }
  if (disc.running) {
    setStep('uid', 'active', 'KakaoTalk 运行中：正在导出进程内存并提取用户 ID（可能需要 1-3 分钟）…');
    try {
      const mem = await app.winUserIdFromMemory();
      if (mem.ok) {
        const nums = mem.candidates.map((c) => c.num);
        candidates = [...new Set([...nums, ...candidates])];
        setStep('uid', 'active', `内存提取候选：${nums.join(', ')}（结合文件扫描共 ${candidates.length} 个）`);
      }
    } catch (e) {
      setStep('uid', 'active', `内存提取失败（${e.message}），继续用文件扫描候选…`);
    }
  }
  if (!candidates.length) {
    setStep('uid', 'fail', '无法自动还原用户 ID——请在手动模式中填写 userId（KakaoTalk PC 版数字 ID）与设备材料');
    return false;
  }

  // ---- 步骤 4：参数求解 + 解密 ----
  setStep('db', 'ok', `已定位 ${disc.edbs.length} 个 EDB 文件`);
  if (app.onWinProgress) {
    app.onWinProgress(({ detail }) => {
      setStep('decrypt', 'active', detail);
    });
  }
  setStep('decrypt', 'active', '求解解密参数并按页解密 EDB…');
  let dec;
  try {
    dec = await app.winDecrypt({
      materials: disc.materials,
      userIdCandidates: candidates,
      edbs: disc.edbs,
    });
  } catch (e) {
    setStep('decrypt', 'fail', '解密失败：' + e.message);
    return false;
  }
  if (!dec.ok) {
    setStep('decrypt', 'fail', dec.reason);
    return false;
  }
  const isSqlcipher = dec.params.kind === 'sqlcipher';
  if (isSqlcipher) {
    const kc = dec.params.keyCount > 1 ? `（共 ${dec.params.keyCount} 把密钥）` : '';
    setStep('uid', 'ok', `SQLCipher 密钥已从进程内存恢复${kc}（新版加密，无需 userId）`);
  } else {
    setStep('uid', 'ok', `用户 ID ${dec.params.userId}（已由参数求解验证）`);
  }
  setStep('decrypt', 'active', `解密成功 ${dec.files.length} 个 EDB，正在汇总为统一查询库…`);

  // SQLCipher 路线无 userId：用密钥哈希作派生种子（仅需自洽，统一库密钥与源库无关）
  const winUserId = dec.params.userId || `sqlcipher-${String(dec.params.keyHex || 'mem').slice(0, 16)}`;
  const ok = await controls.tryOpenWindows(dec.files, winUserId, disc);
  if (!ok) return false; // 错误详情由 openWindowsDatabase 呈现

  setStep('decrypt', 'ok', '汇总完成，正在加载聊天记录…');
  if (inElectron()) window.kakaoApp.log('[auto] Windows 全部步骤完成');
  return true;
}

/**
 * 多线程爆破 SHA-512 还原 userId
 * @returns {Promise<number|null>} 命中的 userId；中止/失败返回 null
 */
async function bruteUserId(disc, hash) {
  const app = window.kakaoApp;
  const bruteStartTs = Date.now();

  app.onBruteProgress(({ checked, total }) => {
    const pct = Math.min(99.9, (checked / total) * 100).toFixed(1);
    const speed = checked / Math.max(0.5, (Date.now() - bruteStartTs) / 1000);
    setStep('uid', 'active',
      `爆破中：${checked.toLocaleString()} / ${total.toLocaleString()}（${pct}%，${Math.round(speed).toLocaleString()} 次/秒）…`);
  });

  setStep('uid', 'active', '爆破中…');
  let result;
  try {
    // 范围 0 ~ 10 亿：覆盖 9 位以内的 KakaoTalk 用户 ID
    result = await app.bruteStart({ hash, start: 0, end: 1_000_000_000 });
  } catch (e) {
    setStep('uid', 'fail', '爆破任务异常：' + e.message);
    return null;
  }
  if (result.found !== null && result.found !== undefined) {
    return result.found;
  }
  if (result.aborted) {
    setStep('uid', 'fail', '爆破已手动停止');
    return null;
  }
  setStep('uid', 'fail',
    '在 0 ~ 10 亿范围内未还原出用户 ID（可在手动模式中扩大范围重试或直接填写）');
  return null;
}
