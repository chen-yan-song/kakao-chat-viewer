/**
 * 渲染进程：调用 Electron 解析媒体，并生成可展示的 object URL
 */
const mediaUrlCache = new Map(); // key → objectURL

function mediaCacheKey(m, idx = 0) {
  return `${m.chatId}:${m.logId}:${m.type}:${idx}`;
}

/** 是否值得尝试解析媒体 */
export function isMediaMessage(type) {
  const t = Number(type);
  return t === 2 || t === 3 || t === 4 || t === 18 || t === 27;
}

/**
 * 解析一条消息的媒体帧（仅 Electron App）
 * @returns {Promise<Array<{ok:boolean, tier:string, reason:string, objectUrl?:string, mime?:string, name?:string}>>}
 */
export async function loadMessageMedia(m, { allowCdn = true } = {}) {
  if (!window.kakaoApp || typeof window.kakaoApp.resolveMedia !== 'function') {
    return [{ ok: false, tier: 'stub', reason: '需要 Electron App' }];
  }
  if (!isMediaMessage(m.type)) {
    return [{ ok: false, tier: 'stub', reason: '非媒体类型' }];
  }

  const res = await window.kakaoApp.resolveMedia({
    chatId: m.chatId,
    logId: m.logId,
    type: m.type,
    attachment: m.attachment,
    allowCdn,
  });
  const frames = (res && res.frames) || [];
  return frames.map((f, idx) => {
    if (!f || !f.ok || !f.base64) {
      return {
        ok: false,
        tier: (f && f.tier) || 'stub',
        reason: (f && f.reason) || 'unavailable',
        name: f && f.name,
      };
    }
    const key = mediaCacheKey(m, idx);
    let objectUrl = mediaUrlCache.get(key);
    if (!objectUrl) {
      const bin = Uint8Array.from(atob(f.base64), (c) => c.charCodeAt(0));
      const blob = new Blob([bin], { type: f.mime || 'application/octet-stream' });
      objectUrl = URL.createObjectURL(blob);
      mediaUrlCache.set(key, objectUrl);
    }
    return {
      ok: true,
      tier: f.tier,
      reason: f.reason,
      mime: f.mime,
      name: f.name,
      objectUrl,
    };
  });
}

/** 人类可读的失败原因 */
export function mediaFailLabel(reason) {
  const r = String(reason || '');
  if (r.includes('cdn-expired')) return 'CDN 链接已过期（约发送后 3 天）';
  if (r.includes('not-cached')) return '本机未缓存（需在 KakaoTalk 里打开过图片）';
  if (r.includes('no-local-cache')) return '语音/文件无本地缓存，需有效 CDN';
  if (r.includes('cdn-disabled')) return '已关闭 CDN 拉取';
  if (r.includes('cdn-unverifiable')) return '缺少校验指纹，跳过 CDN';
  if (r.includes('cdn-checksum-mismatch')) return 'CDN 内容校验失败';
  if (r.includes('decrypt-failed')) return '本地缓存解密失败';
  if (r.includes('media-macos-only')) return '媒体解析仅支持 macOS App';
  if (r.includes('需要 Electron')) return '请用 npm start 打开 App';
  return r || '无法获取媒体';
}
