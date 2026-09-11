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
 * Windows 全自动流程：注册表设备材料 → EDB 清单 → 两步流编排 → 解密 → 汇总统一库
 *
 * 两步流背景（2026-09 实机验证）：新版 KakaoTalk 运行时把核心 EDB 锁死且磁盘全零，
 * 完全退出后才真实落盘；而解密密钥只在运行时驻留内存。因此必须分两步：
 *   退出态：复制 EDB 快照 + 缓存探针 → 运行态：内存取密钥 → 用快照解密。
 * 密钥缓存后，日常使用只需「退出 KakaoTalk」一次即可解密最新数据。
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
    // 新版 SQLCipher 路线不依赖设备材料：不中断，继续走解密（内部自动转 SQLCipher 内存密钥路线）
    setStep('uuid', 'active', '注册表未找到设备材料——不影响新版 SQLCipher 解密（无需设备材料），继续…');
  } else {
    setStep('uuid', 'ok', `${disc.devIds.length} 组设备材料（${disc.materials.map((m) => m.label).join(' / ')}）`);
  }

  // ---- 步骤 2：EDB 数据文件清单 ----
  if (!disc.edbs.length) {
    setStep('plist', 'fail', `未找到 EDB 数据文件（${disc.usersDir || disc.baseDir}）——请确认已在 KakaoTalk 中同步过聊天记录`);
    return false;
  }
  const totalMB = disc.edbs.reduce((s, f) => s + (f.size || 0), 0) / 1024 / 1024;
  setStep('plist', 'ok', `找到 ${disc.edbs.length} 个 EDB 文件（共 ${totalMB.toFixed(1)} MB）`);

  // ---- 步骤 3：userId 候选（仅文件扫描；SQLCipher 路线不需要 userId，跳过耗时的内存提取）----
  const candidates = (disc.userIdCandidates || []).map((c) => c.num);
  setStep('uid', 'active', '正在检测 KakaoTalk 数据保护状态…');

  // ---- 步骤 4/5：两步流状态机编排（最多 4 轮用户引导，防死循环）----
  if (app.onWinProgress) {
    app.onWinProgress(({ detail }) => {
      setStep('decrypt', 'active', detail);
    });
  }
  setStep('db', 'ok', `已定位 ${disc.edbs.length} 个 EDB 文件`);

  for (let round = 0; round < 4; round++) {
    let st;
    try {
      st = await app.winTwoStepStatus();
    } catch (e) {
      setStep('uid', 'warn', `状态检测失败（${e.message}），回退传统解密流程…`);
      return legacyWindowsDecrypt(disc, candidates);
    }
    const stDesc = `运行中=${st.running ? '是' : '否'}，可读库 ${st.readable}/${st.coreCount}，已存密钥 ${st.keyCount}，快照 ${st.snapshotCount}`;
    setStep('uid', 'active', `保护状态检测：${stDesc}`);

    // A. 文件可读且有密钥：直接解密最新落盘数据
    if (st.advice === 'decrypt-now') {
      setStep('uid', 'ok', `已缓存 ${st.keyCount} 把密钥，数据文件可读`);
      return legacyWindowsDecrypt(disc, candidates);
    }

    // B. 有密钥有快照：直接解密快照
    if (st.advice === 'decrypt-snapshot') {
      setStep('uid', 'ok', `已缓存 ${st.keyCount} 把密钥`);
      const ok = await decryptSnapshotAndOpen(st);
      if (ok) return true;
      // 快照解密失败（key 可能已轮换）：清一轮重试
      setStep('decrypt', 'warn', '快照解密失败，重新检测状态…');
      continue;
    }

    // C. 文件可读但无密钥：先快照，再引导启动 KakaoTalk 取密钥
    if (st.advice === 'snapshot') {
      setStep('db', 'active', '正在复制数据快照（KakaoTalk 退出态，仅一次机会窗口）…');
      const snap = await app.winSnapshot();
      if (!snap.ok) {
        setStep('db', 'fail', '快照复制失败：核心库均不可读');
        return false;
      }
      setStep('db', 'ok', `快照完成：${snap.count} 个核心库（含未落盘的 WAL 数据）`);
      await controls.waitConfirm(
        '数据快照已保存。现在请：\n① 启动 KakaoTalk 并完成登录\n② 点开左侧「聊天」列表\n③ 逐个进入你需要导出的聊天室（每个房间密钥独立，进入过才会驻留内存）\n完成后点击下方按钮。',
        '已完成，开始提取密钥');
      setStep('decrypt', 'active', '正在从 KakaoTalk 进程内存提取解密密钥（约 2-5 分钟）…');
      const ck = await app.winCollectKeys({ edbs: disc.edbs });
      if (!ck.ok) {
        setStep('decrypt', 'fail', ck.detail || ck.reason);
        return false;
      }
      setStep('uid', 'ok', `密钥提取完成（命中 ${ck.hits.length} 把，累计缓存 ${ck.keyCount} 把）`);
      const ok = await decryptSnapshotAndOpen(st);
      if (ok) return true;
      return false;
    }

    // D. 运行中、有探针缓存、无密钥：确认登录状态后直接取密钥
    if (st.advice === 'collect-keys') {
      if (!st.running) {
        await controls.waitConfirm(
          '请启动 KakaoTalk 并完成登录，点开「聊天」列表和需要导出的聊天室。完成后点击下方按钮。',
          '已启动并登录');
        continue;
      }
      await controls.waitConfirm(
        'KakaoTalk 运行中。请确认：已登录，且已点开「聊天」列表和需要导出的聊天室（密钥只在打开过的房间驻留内存）。',
        '已确认，开始提取密钥');
      setStep('decrypt', 'active', '正在从 KakaoTalk 进程内存提取解密密钥（约 2-5 分钟）…');
      const ck = await app.winCollectKeys({ edbs: disc.edbs });
      if (!ck.ok) {
        if (ck.reason === 'edb-protected') {
          // 探针缓存也失效：必须重新走退出态快照
          setStep('decrypt', 'warn', ck.detail);
          await controls.waitConfirm(
            '需要刷新数据探针。请完全退出 KakaoTalk（右键托盘图标 → 退出，不是关窗口）。',
            '已完全退出 KakaoTalk');
          continue;
        }
        setStep('decrypt', 'fail', ck.detail || ck.reason);
        return false;
      }
      setStep('uid', 'ok', `密钥提取完成（命中 ${ck.hits.length} 把，累计缓存 ${ck.keyCount} 把）`);
      // 有快照则直接解密；无快照引导退出落盘
      const st2 = await app.winTwoStepStatus();
      if (st2.hasSnapshot) {
        const ok = await decryptSnapshotAndOpen(st2);
        if (ok) return true;
        return false;
      }
      await controls.waitConfirm(
        '密钥已保存。现在请完全退出 KakaoTalk（右键托盘图标 → 退出），让聊天数据落盘。',
        '已完全退出 KakaoTalk');
      continue;
    }

    // E. 什么都没有/文件被保护：引导退出 KakaoTalk
    if (st.advice === 'exit-kakao') {
      await controls.waitConfirm(
        '新版 KakaoTalk 运行时会锁死并清空数据文件（反取证保护）。\n请完全退出 KakaoTalk：右键右下角托盘图标 → 「退出」（仅关窗口无效）。',
        '已完全退出 KakaoTalk');
      continue;
    }
  }
  setStep('decrypt', 'fail', '两步流编排超出最大轮次，请点击「重新自动检测」重试');
  return false;
}

/** 解密已有快照并打开统一库 */
async function decryptSnapshotAndOpen(st) {
  const app = window.kakaoApp;
  const snap = await app.winSnapshotEdbs();
  if (!snap.ok) {
    setStep('decrypt', 'fail', '快照为空，请重新检测');
    return false;
  }
  setStep('decrypt', 'active', `用已缓存密钥解密快照（${snap.edbs.length} 个库，快照时间 ${st.snapshotAt || '未知'}）…`);
  const dec = await app.winDecryptCached({ edbs: snap.edbs });
  if (!dec.ok) {
    setStep('decrypt', 'fail', dec.reason);
    return false;
  }
  setStep('decrypt', 'active', `解密成功 ${dec.files.length} 个 EDB，正在汇总为统一查询库…`);
  const winUserId = `sqlcipher-${String(dec.params.keyHex || 'cache').slice(0, 16)}`;
  // materials 存在即走「已解密文件」分支；devId 仅作统一库本地加密盐（自洽即可）
  const ok = await controls.tryOpenWindows(dec.files, winUserId, { materials: [], devId: 'win-snapshot' });
  if (!ok) {
    // openWindowsDatabase 把详细原因存在 __lastOpenError（手动区错误在自动面板不可见）
    const why = window.__lastOpenError || '未知原因';
    let logPath = '';
    try { logPath = await app.getLogPath(); } catch { /* 忽略 */ }
    setStep('decrypt', 'fail', `汇总失败：${why}${logPath ? `（日志文件：${logPath}）` : ''}`);
    return false;
  }
  setStep('decrypt', 'ok', `汇总完成（数据为 ${st.snapshotAt ? new Date(st.snapshotAt).toLocaleString() : '上次'} 的快照），正在加载聊天记录…`);
  if (inElectron()) window.kakaoApp.log('[auto] Windows 两步流完成');
  return true;
}

/** 传统路径：材料派生 → SQLCipher 内存恢复 → 解密（decryptAllEdbs 内部含缓存密钥快速通道） */
async function legacyWindowsDecrypt(disc, candidates) {
  const app = window.kakaoApp;
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
    setStep('decrypt', 'fail', dec.detail || dec.reason);
    return false;
  }
  const isSqlcipher = dec.params.kind === 'sqlcipher';
  if (isSqlcipher) {
    const kc = dec.params.keyCount > 1 ? `（共 ${dec.params.keyCount} 把密钥）` : '';
    setStep('uid', 'ok', `SQLCipher 密钥已恢复${kc}（新版加密，无需 userId）`);
  } else {
    setStep('uid', 'ok', `用户 ID ${dec.params.userId}（已由参数求解验证）`);
  }
  setStep('decrypt', 'active', `解密成功 ${dec.files.length} 个 EDB，正在汇总为统一查询库…`);

  // SQLCipher 路线无 userId：用密钥哈希作派生种子（仅需自洽，统一库密钥与源库无关）
  const winUserId = dec.params.userId || `sqlcipher-${String(dec.params.keyHex || 'mem').slice(0, 16)}`;
  const ok = await controls.tryOpenWindows(dec.files, winUserId, disc);
  if (!ok) {
    // 错误详情由 openWindowsDatabase 记录到 __lastOpenError（手动区错误在自动面板不可见）
    const why = window.__lastOpenError || '未知原因';
    setStep('decrypt', 'fail', `汇总失败：${why}`);
    return false;
  }

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
