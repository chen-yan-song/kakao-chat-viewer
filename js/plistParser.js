/**
 * KakaoTalk 偏好设置 plist 解析与 userId 提取
 *
 * 支持两种 plist 格式：
 * - XML plist（老版本 KakaoTalk）
 * - 二进制 bplist00（新版 KakaoTalk）
 *
 * userId 提取策略与 kakaocli DeviceInfo.swift 一致：
 * 1. FSChatWindowTransparency 键的共同后缀
 * 2. userId / user_id 等直接键
 * 3. DESIGNATEDFRIENDSREVISION:<sha512hex> 键 → SHA-512 爆破
 * 4. NSWindow Frame FSChatWindowFrame_ 键的共同后缀
 * 5. AlertKakaoIDsList 候选列表
 */
import { sha512Hex, bruteForceUserId } from './sha512.js';

/** SHA-512("0")——空账号哈希，kakaocli 中用于排除默认账号 */
const EMPTY_ACCOUNT_HASH =
  '31bca02094eb78126a517b206a88c73cfa9ec6f704c7030d18212cace820f025f00bf0ea68dbf3f3a5436ca63b53bf7bf80ad8d5de7d8359d0b7fed9dbc3ab99';

/** 解析 plist 文件（自动识别 XML / 二进制格式） */
export function parsePlist(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  if (bytes.length >= 8 && bytesToAscii(bytes, 0, 8) === 'bplist00') {
    return parseBinaryPlist(bytes);
  }
  // XML plist
  const text = new TextDecoder('utf-8').decode(bytes);
  if (text.includes('<plist')) {
    return parseXmlPlist(text);
  }
  return null;
}

function bytesToAscii(bytes, start, end) {
  let s = '';
  for (let i = start; i < end; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

/** 解析 XML plist 为 JS 对象 */
function parseXmlPlist(text) {
  const doc = new DOMParser().parseFromString(text, 'application/xml');
  if (doc.getElementsByTagName('parsererror').length) return null;
  const root = doc.getElementsByTagName('plist')[0];
  if (!root) return null;
  const container = root.firstElementChild;
  return container ? parseXmlValue(container) : null;
}

function parseXmlValue(node) {
  switch (node.tagName) {
    case 'dict': {
      const obj = {};
      const children = Array.from(node.children);
      for (let i = 0; i < children.length; i += 2) {
        const keyNode = children[i];
        const valNode = children[i + 1];
        if (keyNode && keyNode.tagName === 'key' && valNode) {
          obj[keyNode.textContent] = parseXmlValue(valNode);
        }
      }
      return obj;
    }
    case 'array':
      return Array.from(node.children).map(parseXmlValue);
    case 'string':
      return node.textContent || '';
    case 'integer':
      return parseInt(node.textContent, 10);
    case 'real':
      return parseFloat(node.textContent);
    case 'true':
      return true;
    case 'false':
      return false;
    case 'date':
      return node.textContent || '';
    case 'data':
      return node.textContent || '';
    default:
      return null;
  }
}

/** 解析二进制 bplist00 为 JS 对象 */
function parseBinaryPlist(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const trailerStart = bytes.length - 32;
  const offsetIntSize = bytes[trailerStart + 6];
  const objectRefSize = bytes[trailerStart + 7];
  const numObjects = view.getBigUint64(trailerStart + 8, false);
  const topObject = view.getBigUint64(trailerStart + 16, false);
  const offsetTableStart = Number(view.getBigUint64(trailerStart + 24, false));
  if (numObjects > 1000000) return null; // 防御异常数据

  const refs = (offset) => {
    let v = 0n;
    for (let i = 0; i < objectRefSize; i++) {
      v = (v << 8n) | BigInt(bytes[offset + i]);
    }
    return v;
  };

  // 对象偏移表
  const offsets = [];
  for (let i = 0; i < numObjects; i++) {
    const off = offsetTableStart + i * offsetIntSize;
    let v = 0;
    for (let j = 0; j < offsetIntSize; j++) v = v * 256 + bytes[off + j];
    offsets.push(v);
  }

  const cache = new Map();
  const readLength = (marker, pos) => {
    const low = marker & 0x0f;
    if (low !== 0x0f) return { len: low, pos };
    // 长度是随后的整数对象
    const intMarker = bytes[pos];
    const intSize = 1 << (intMarker & 0x0f);
    let len = 0;
    for (let i = 1; i <= intSize; i++) len = len * 256 + bytes[pos + i];
    return { len, pos: pos + intSize + 1 };
  };

  const parseObject = (index) => {
    if (cache.has(index)) return cache.get(index);
    const pos = offsets[Number(index)];
    const marker = bytes[pos];
    const type = marker >> 4;
    let result;

    switch (type) {
      case 0x0: {
        // simple：0x00=null 0x08=false 0x09=true
        if (marker === 0x00) result = null;
        else if (marker === 0x08) result = false;
        else if (marker === 0x09) result = true;
        else result = null;
        break;
      }
      case 0x1: {
        // integer
        const size = 1 << (marker & 0x0f);
        let v = 0;
        for (let i = 1; i <= size; i++) v = v * 256 + bytes[pos + i];
        result = v;
        break;
      }
      case 0x2: {
        // real
        const size = 1 << (marker & 0x0f);
        const dv = new DataView(bytes.buffer, bytes.byteOffset + pos + 1, size);
        result = size === 8 ? dv.getFloat64(0, false) : dv.getFloat32(0, false);
        break;
      }
      case 0x3: {
        // date：8 字节浮点（距 2001-01-01 秒数）
        const dv = new DataView(bytes.buffer, bytes.byteOffset + pos + 1, 8);
        const secs = dv.getFloat64(0, false);
        result = new Date(978307200000 + secs * 1000).toISOString();
        break;
      }
      case 0x4: {
        // data
        const { len, pos: p } = readLength(marker, pos + 1);
        result = bytes.slice(p, p + len);
        break;
      }
      case 0x5: {
        // ASCII string
        const { len, pos: p } = readLength(marker, pos + 1);
        result = bytesToAscii(bytes, p, p + len);
        break;
      }
      case 0x6: {
        // UTF-16BE string
        const { len, pos: p } = readLength(marker, pos + 1);
        result = new TextDecoder('utf-16be').decode(bytes.subarray(p, p + len * 2));
        break;
      }
      case 0x8: {
        // UID
        const size = marker & 0x0f;
        let v = 0;
        for (let i = 1; i <= size + 1; i++) v = v * 256 + bytes[pos + i];
        result = v;
        break;
      }
      case 0xa: {
        // array
        const { len, pos: p } = readLength(marker, pos + 1);
        result = [];
        for (let i = 0; i < len; i++) {
          result.push(parseObject(refs(p + i * objectRefSize)));
        }
        break;
      }
      case 0xd: {
        // dict：需兼容两种引用布局
        // - 新版格式（macOS 现行 plutil）：先全部 key 引用，再全部 value 引用
        // - 旧版格式：key/value 引用交替
        // 通过探测 key 位置的对象类型自动识别（plist 的 dict key 必为字符串）
        const { len, pos: p } = readLength(marker, pos + 1);
        result = {};
        const step = objectRefSize;
        const isStringObj = (idx) => {
          const m = bytes[offsets[Number(idx)]] >> 4;
          return m === 0x5 || m === 0x6; // ASCII / UTF-16
        };
        let keysFirstOk = true;
        let alternatingOk = true;
        for (let i = 0; i < len; i++) {
          if (!isStringObj(refs(p + i * step))) keysFirstOk = false;
          if (!isStringObj(refs(p + i * 2 * step))) alternatingOk = false;
          if (!keysFirstOk && !alternatingOk) break;
        }
        const keysFirst = keysFirstOk || !alternatingOk;
        if (keysFirst) {
          for (let i = 0; i < len; i++) {
            const key = parseObject(refs(p + i * step));
            const value = parseObject(refs(p + (len + i) * step));
            result[String(key)] = value;
          }
        } else {
          for (let i = 0; i < len; i++) {
            const key = parseObject(refs(p + i * 2 * step));
            const value = parseObject(refs(p + i * 2 * step + step));
            result[String(key)] = value;
          }
        }
        break;
      }
      default:
        result = null;
    }
    cache.set(index, result);
    return result;
  };

  return parseObject(topObject);
}

/**
 * 从 plist 对象提取 userId 信息
 * @returns {{direct: number|null, hash: string|null, candidates: number[]}}
 *   direct 直接找到的 userId；hash 需要爆破的 SHA-512 哈希；candidates 候选列表
 */
export function extractUserIdInfo(plist) {
  if (!plist || typeof plist !== 'object') {
    return { direct: null, hash: null, candidates: [] };
  }

  // 策略 2：直接键
  for (const key of ['userId', 'user_id', 'KAKAO_USER_ID', 'userID']) {
    const v = plist[key];
    if (typeof v === 'number' && v > 0) return { direct: v, hash: null, candidates: [v] };
    if (typeof v === 'string' && /^\d+$/.test(v) && parseInt(v, 10) > 0) {
      return { direct: parseInt(v, 10), hash: null, candidates: [parseInt(v, 10)] };
    }
  }

  // 策略 1：FSChatWindowTransparency 共同后缀
  const transparencySuffix = commonSuffixOfKeys(plist, 'FSChatWindowTransparency');
  if (transparencySuffix) {
    return { direct: transparencySuffix, hash: null, candidates: [transparencySuffix] };
  }

  // 策略 4：NSWindow Frame FSChatWindowFrame_ 共同后缀
  const frameSuffix = commonSuffixOfKeys(plist, 'NSWindow Frame FSChatWindowFrame_');
  if (frameSuffix) {
    return { direct: frameSuffix, hash: null, candidates: [frameSuffix] };
  }

  // 策略 3：DESIGNATEDFRIENDSREVISION:<sha512hex>（活跃账号）
  const prefix = 'DESIGNATEDFRIENDSREVISION:';
  for (const [key, val] of Object.entries(plist)) {
    if (!key.startsWith(prefix)) continue;
    const hash = key.slice(prefix.length);
    if (hash.length !== 128) continue;
    if (hash === EMPTY_ACCOUNT_HASH) continue;
    const intVal = typeof val === 'number' ? val : parseInt(String(val), 10) || 0;
    if (intVal !== 0) {
      return { direct: null, hash, candidates: [] };
    }
  }

  // 策略 5：AlertKakaoIDsList 候选
  const list = plist['AlertKakaoIDsList'];
  const candidates = [];
  if (Array.isArray(list)) {
    for (const item of list) {
      if (typeof item === 'number' && item > 0) candidates.push(item);
      else if (typeof item === 'string' && /^\d+$/.test(item) && parseInt(item, 10) > 0) {
        candidates.push(parseInt(item, 10));
      }
    }
  }

  return { direct: null, hash: null, candidates };
}

/** 提取以某前缀开头的一组键的共同后缀（纯数字） */
function commonSuffixOfKeys(obj, prefix) {
  const keys = Object.keys(obj).filter((k) => k.startsWith(prefix));
  if (keys.length < 2) return null;
  const suffixes = keys.map((k) => k.slice(prefix.length));
  let commonLen = 0;
  const first = suffixes[0];
  outer: for (let i = first.length - 1; i >= 0; i--) {
    const ch = first[i];
    for (const s of suffixes) {
      if (s[s.length - 1 - commonLen] !== ch) break outer;
    }
    commonLen++;
  }
  if (commonLen === 0) return null;
  const suffix = first.slice(first.length - commonLen);
  const id = parseInt(suffix, 10);
  return Number.isFinite(id) && id > 0 ? id : null;
}

/**
 * 从 plist 哈希推导 userId（SHA-512 爆破），支持进度回调
 * @returns {Promise<number|null>}
 */
export async function bruteUserIdFromHash(hash, { onProgress, maxId = 1000000000 } = {}) {
  return bruteForceUserId(hash, { start: 0, end: maxId, chunk: 50000, onProgress });
}

/** 校验给定的 userId 是否匹配哈希（供候选列表快速验证） */
export function verifyUserIdHash(userId, hash) {
  return sha512Hex(String(userId)) === hash.toLowerCase();
}
