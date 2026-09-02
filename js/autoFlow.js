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

/** 是否 macOS 环境（自动发现依赖 macOS 沙盒容器与 ioreg，Windows 版仅支持手动模式） */
function isMacPlatform() {
  return /Macintosh|Mac OS X/.test(navigator.userAgent);
}

/** 运行全自动流程，成功返回 true；失败返回 false（并已显示手动兜底入口） */
export async function runAutoFlow() {
  if (!controls) return false;

  if (!inElectron()) {
    setStep('uuid', 'fail', '当前不在 App 环境中（浏览器访问请使用下方手动模式）');
    return false;
  }

  if (!isMacPlatform()) {
    setStep('uuid', 'warn', '自动发现仅支持 macOS 版本（Windows 版 KakaoTalk 采用不同加密体系）');
    controls.autoMsg(
      '当前为 Windows 版：Windows 版 KakaoTalk 数据库加密体系不同，本工具仅作为聊天记录查看器使用——' +
      '请点下方「使用手动模式」，加载从 Mac 端导出的数据库文件查看。'
    );
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
