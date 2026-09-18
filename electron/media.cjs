/**
 * KakaoTalk macOS 媒体解析
 *
 * - 本地缓存：账号目录 / sha1(reverse(chatId)) / sha1(reverse(前缀+logId)).{img,thm,vid}
 * - 本地文件为 Pkv2（AES-256-CBC），密钥 = SHA256(reverse("#"+logId+"%"))
 * - CDN：attachment.url / imageUrls[i]，约 3 天有效；有 cs 才校验下载
 * - 语音/通用文件（type 4 / 18）通常无本地缓存，仅 CDN
 */
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const http = require('http');

const DB_DIR = path.join(
  os.homedir(),
  'Library',
  'Containers',
  'com.kakao.KakaoTalkMac',
  'Data',
  'Library',
  'Application Support',
  'com.kakao.KakaoTalkMac'
);

const PKV2_MAGIC = Buffer.from('Pkv2');
const PLAINTEXT_HEADER_LEN = 256;
const MAX_CDN_BYTES = 64 * 1024 * 1024;
const CDN_TIMEOUT_MS = 20000;

function sha1Hex(buf) {
  return crypto.createHash('sha1').update(buf).digest('hex');
}

function sha1Rev(input) {
  return sha1Hex(Buffer.from(String(input).split('').reverse().join(''), 'utf8'));
}

function chatDirName(chatId) {
  return sha1Rev(String(chatId));
}

function photoFullStem(logId) {
  return sha1Rev(`p${logId}`);
}
function photoThumbStem(logId) {
  return sha1Rev(`t${logId}`);
}
function videoFullStem(logId) {
  return sha1Rev(`v${logId}`);
}
function albumFullStem(logId, idx) {
  return sha1Rev(`p${idx}_${logId}`);
}
function albumThumbStem(logId, idx) {
  return sha1Rev(`t${idx}_${logId}`);
}

function mediaKeyString(logId) {
  return `#${logId}%`.split('').reverse().join('');
}

/** 解密 Pkv2 .img/.thm/.vid → 媒体明文 */
function decryptPkv2(fileBytes, logId) {
  if (!Buffer.isBuffer(fileBytes)) fileBytes = Buffer.from(fileBytes);
  if (fileBytes.length < 4 + 16 + 16 || !fileBytes.subarray(0, 4).equals(PKV2_MAGIC)) {
    throw new Error('不是 Pkv2 文件');
  }
  const iv = fileBytes.subarray(4, 20);
  const ciphertext = fileBytes.subarray(20);
  if (ciphertext.length % 16 !== 0) throw new Error('密文长度未按块对齐');
  const aesKey = crypto.createHash('sha256').update(mediaKeyString(logId), 'utf8').digest();
  const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  if (plain.length < PLAINTEXT_HEADER_LEN) throw new Error('明文缺少媒体头');
  return plain.subarray(PLAINTEXT_HEADER_LEN);
}

/** 扫描容器下 40 位 hex 账号目录（仅一层） */
function discoverAccountRoots() {
  let entries;
  try {
    entries = fs.readdirSync(DB_DIR, { withFileTypes: true });
  } catch {
    return [];
  }
  const roots = [];
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    if (/^[0-9a-f]{40}$/.test(e.name)) roots.push(path.join(DB_DIR, e.name));
  }
  roots.sort();
  return roots;
}

function findCachedFile(roots, chatId, stem, ext) {
  const chat = chatDirName(chatId);
  const name = stem + ext;
  for (const root of roots) {
    const p = path.join(root, chat, name);
    try {
      if (fs.statSync(p).isFile()) return p;
    } catch {
      /* 继续 */
    }
  }
  return null;
}

function sniffMime(buf, fallbackName) {
  if (!buf || buf.length < 4) return guessMimeFromName(fallbackName) || 'application/octet-stream';
  if (buf[0] === 0xff && buf[1] === 0xd8) return 'image/jpeg';
  if (buf[0] === 0x89 && buf[1] === 0x50) return 'image/png';
  if (buf[0] === 0x47 && buf[1] === 0x49) return 'image/gif';
  if (buf[0] === 0x52 && buf[1] === 0x49 && buf[8] === 0x57) return 'image/webp';
  if (buf.length > 8 && buf.subarray(4, 8).toString() === 'ftyp') return 'video/mp4';
  if (buf[0] === 0x1a && buf[1] === 0x45) return 'video/webm';
  return guessMimeFromName(fallbackName) || 'application/octet-stream';
}

function guessMimeFromName(name) {
  if (!name) return null;
  const n = String(name).toLowerCase();
  if (n.endsWith('.jpg') || n.endsWith('.jpeg')) return 'image/jpeg';
  if (n.endsWith('.png')) return 'image/png';
  if (n.endsWith('.gif')) return 'image/gif';
  if (n.endsWith('.webp')) return 'image/webp';
  if (n.endsWith('.mp4')) return 'video/mp4';
  if (n.endsWith('.m4a') || n.endsWith('.aac')) return 'audio/mp4';
  if (n.endsWith('.mp3')) return 'audio/mpeg';
  if (n.endsWith('.ogg')) return 'audio/ogg';
  if (n.endsWith('.wav')) return 'audio/wav';
  return null;
}

function parseAttachment(raw) {
  if (raw == null || raw === '') return {};
  if (typeof raw === 'object') return raw;
  try {
    const o = JSON.parse(String(raw));
    return o && typeof o === 'object' ? o : {};
  } catch {
    return {};
  }
}

function urlExpires(url) {
  const m = /[?&]expires=(\d+)/.exec(String(url));
  return m ? Number(m[1]) : null;
}

function isCdnExpired(url, nowSec) {
  const exp = urlExpires(url);
  return exp != null && exp < nowSec;
}

function fetchUrl(url, maxBytes = MAX_CDN_BYTES) {
  return new Promise((resolve, reject) => {
    const lib = String(url).startsWith('http://') ? http : https;
    const req = lib.get(
      url,
      { headers: { 'User-Agent': 'KakaoTalk' }, timeout: CDN_TIMEOUT_MS },
      (res) => {
        if (res.statusCode && res.statusCode >= 400) {
          res.resume();
          return reject(new Error(`CDN HTTP ${res.statusCode}`));
        }
        const chunks = [];
        let size = 0;
        res.on('data', (c) => {
          size += c.length;
          if (size > maxBytes) {
            req.destroy();
            reject(new Error('CDN 体积超限'));
            return;
          }
          chunks.push(c);
        });
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
      }
    );
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('CDN 超时'));
    });
    req.on('error', reject);
  });
}

function toResult(body, tier, reason, name) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
  return {
    ok: true,
    tier,
    reason,
    name: name || null,
    mime: sniffMime(buf, name),
    base64: buf.toString('base64'),
    size: buf.length,
  };
}

function stub(reason, extra = {}) {
  return { ok: false, tier: 'stub', reason, mime: null, base64: null, size: 0, ...extra };
}

/**
 * 解析单帧：本地 full → CDN → 本地 thumb → stub
 */
async function resolveFrame({
  chatId,
  logId,
  kind, // photo | video | file
  idx = 0,
  fullStem,
  fullExt,
  thumbStem,
  checksum,
  sizeBytes,
  cdnUrl,
  filename,
  allowCdn,
  roots,
  nowSec,
  fetchImpl,
}) {
  const reasons = [];
  const doFetch = typeof fetchImpl === 'function' ? fetchImpl : fetchUrl;

  if (kind !== 'file' && fullStem && fullExt) {
    const fullPath = findCachedFile(roots, chatId, fullStem, fullExt);
    if (fullPath) {
      try {
        const raw = fs.readFileSync(fullPath);
        const body = decryptPkv2(raw, logId);
        return toResult(body, 'full', 'local-full', filename);
      } catch (e) {
        reasons.push('decrypt-failed:' + e.message);
      }
    } else {
      reasons.push('not-cached');
    }
  } else if (kind === 'file') {
    reasons.push('no-local-cache');
  }

  if (allowCdn && cdnUrl) {
    if (isCdnExpired(cdnUrl, nowSec)) {
      reasons.push('cdn-expired');
    } else if (!checksum) {
      reasons.push('cdn-unverifiable');
    } else if (sizeBytes != null && Number(sizeBytes) > MAX_CDN_BYTES) {
      reasons.push('cdn-too-large');
    } else {
      try {
        const body = await doFetch(cdnUrl);
        if (sha1Hex(body).toLowerCase() !== String(checksum).toLowerCase()) {
          reasons.push('cdn-checksum-mismatch');
        } else {
          return toResult(body, 'cdn', 'cdn', filename);
        }
      } catch (e) {
        reasons.push('cdn-failed:' + e.message);
      }
    }
  } else if (allowCdn && !cdnUrl) {
    reasons.push('no-cdn-url');
  } else if (!allowCdn) {
    reasons.push('cdn-disabled');
  }

  if (kind !== 'file' && thumbStem) {
    const thumbPath = findCachedFile(roots, chatId, thumbStem, '.thm');
    if (thumbPath) {
      try {
        const raw = fs.readFileSync(thumbPath);
        const body = decryptPkv2(raw, logId);
        return toResult(body, 'thumb', reasons.join('+') + '+thumb', filename);
      } catch (e) {
        reasons.push('thumb-decrypt-failed:' + e.message);
      }
    }
  }

  return stub(reasons.join('+') || 'unavailable', { name: filename || null });
}

function buildFrames(type, logId, att) {
  const t = Number(type);
  // 相册
  if (t === 27 && Array.isArray(att.csl) && att.csl.length) {
    return att.csl.map((_, idx) => ({
      kind: 'photo',
      idx,
      fullStem: albumFullStem(logId, idx),
      fullExt: '.img',
      thumbStem: albumThumbStem(logId, idx),
      checksum: Array.isArray(att.csl) ? att.csl[idx] : null,
      sizeBytes: Array.isArray(att.sl) ? att.sl[idx] : null,
      cdnUrl: Array.isArray(att.imageUrls) ? att.imageUrls[idx] : null,
      filename: null,
    }));
  }
  // 图片
  if (t === 2) {
    return [{
      kind: 'photo',
      idx: 0,
      fullStem: photoFullStem(logId),
      fullExt: '.img',
      thumbStem: photoThumbStem(logId),
      checksum: att.cs || null,
      sizeBytes: att.s ?? att.size ?? null,
      cdnUrl: att.url || null,
      filename: null,
    }];
  }
  // 视频
  if (t === 3) {
    return [{
      kind: 'video',
      idx: 0,
      fullStem: videoFullStem(logId),
      fullExt: '.vid',
      thumbStem: photoThumbStem(logId),
      checksum: att.cs || null,
      sizeBytes: att.s ?? att.size ?? null,
      cdnUrl: att.url || null,
      filename: null,
    }];
  }
  // 语音 / 通用文件 / 其它带 url 的附件
  if (t === 4 || t === 18 || att.url) {
    return [{
      kind: 'file',
      idx: 0,
      fullStem: '',
      fullExt: '',
      thumbStem: '',
      checksum: att.cs || null,
      sizeBytes: att.s ?? att.size ?? null,
      cdnUrl: att.url || null,
      filename: att.name || null,
    }];
  }
  return [];
}

/**
 * 解析一条消息的媒体
 * @param {{
 *   chatId:number, logId:number, type:number, attachment:any, allowCdn?:boolean,
 *   accountRoots?: string[], nowSec?: number, fetchImpl?: Function
 * }} opts
 */
async function resolveMedia(opts) {
  const chatId = Number(opts.chatId);
  const logId = Number(opts.logId);
  const type = Number(opts.type);
  const allowCdn = opts.allowCdn !== false;
  const att = parseAttachment(opts.attachment);
  const nowSec = opts.nowSec != null ? Number(opts.nowSec) : Math.floor(Date.now() / 1000);
  const fetchImpl = typeof opts.fetchImpl === 'function' ? opts.fetchImpl : fetchUrl;

  if (!Number.isFinite(chatId) || !Number.isFinite(logId)) {
    return { frames: [stub('invalid-ids')] };
  }

  const framesSpec = buildFrames(type, logId, att);
  if (!framesSpec.length) {
    return { frames: [stub('unsupported-type')] };
  }

  const roots = Array.isArray(opts.accountRoots) ? opts.accountRoots : discoverAccountRoots();
  const frames = [];
  for (const f of framesSpec) {
    // eslint-disable-next-line no-await-in-loop
    frames.push(
      await resolveFrame({
        chatId,
        logId,
        allowCdn,
        roots,
        nowSec,
        fetchImpl,
        ...f,
      })
    );
  }
  return { frames, accountRoots: roots.length };
}

module.exports = {
  resolveMedia,
  decryptPkv2,
  sha1Rev,
  sha1Hex,
  photoFullStem,
  photoThumbStem,
  videoFullStem,
  albumFullStem,
  albumThumbStem,
  chatDirName,
  mediaKeyString,
  isCdnExpired,
  urlExpires,
  buildFrames,
  parseAttachment,
  MAX_CDN_BYTES,
  DB_DIR,
};
