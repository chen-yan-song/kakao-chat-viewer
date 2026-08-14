/**
 * KakaoTalk Mac 数据库密钥派生
 *
 * 算法与 kakaocli（silver-flight-group/kakaocli）的 KeyDerivation.swift 完全一致，
 * 原始研究来源：https://gist.github.com/blluv/8418e3ef4f4aa86004657ea524f2de14
 *
 * - secureKey: PBKDF2-HMAC-SHA256，100,000 次迭代，128 字节输出，hex 编码（256 字符）
 * - databaseName: 同上 PBKDF2，取 hex 第 28..106 位（78 字符），用于定位数据库文件名
 *
 * 全部基于浏览器 WebCrypto API，无外部依赖。
 */

const encoder = new TextEncoder();

/** 将字节数组转成 hex 字符串 */
export function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/** 将字符串按 UTF-8 编码为 Uint8Array */
function toBytes(str) {
  return encoder.encode(str);
}

/** Base64 编码（不带换行） */
export function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

/**
 * PBKDF2-HMAC-SHA256
 * @param {string} password 口令
 * @param {string} salt 盐
 * @param {number} iterations 迭代次数（100000）
 * @param {number} keyLength 输出长度（字节，128）
 */
async function pbkdf2Sha256(password, salt, iterations, keyLength) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    toBytes(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: toBytes(salt),
      iterations,
    },
    keyMaterial,
    keyLength * 8
  );
  return new Uint8Array(bits);
}

/** SHA-1 + SHA-256 摘要拼接后 Base64（与 Swift hashedDeviceUUID 一致） */
async function hashedDeviceUUID(uuid) {
  const data = toBytes(uuid);
  const [sha1, sha256] = await Promise.all([
    crypto.subtle.digest('SHA-1', data),
    crypto.subtle.digest('SHA-256', data),
  ]);
  const combined = new Uint8Array(sha1.byteLength + sha256.byteLength);
  combined.set(new Uint8Array(sha1), 0);
  combined.set(new Uint8Array(sha256), sha1.byteLength);
  return bytesToBase64(combined);
}

/** 字符串反转 */
function reverseStr(str) {
  return str.split('').reverse().join('');
}

/**
 * 派生 SQLCipher 加密密钥（hex 字符串）
 * @param {number|string} userId KakaoTalk 用户 ID
 * @param {string} uuid 设备 IOPlatformUUID
 */
export async function deriveSecureKey(userId, uuid) {
  const hashed = await hashedDeviceUUID(uuid);
  // Swift: ["A", hashed, "|", "F", uuid.prefix(5), "H", userId, "|", uuid.dropFirst(7)].joined("F")
  const parts = ['A', hashed, '|', 'F', uuid.slice(0, 5), 'H', String(userId), '|', uuid.slice(7)];
  const hawawa = parts.join('F');
  // Swift: salt 起点 = Int(Double(uuid.count) * 0.3)
  const saltStart = Math.floor(uuid.length * 0.3);
  const salt = uuid.slice(saltStart);

  const derived = await pbkdf2Sha256(reverseStr(hawawa), salt, 100000, 128);
  return bytesToHex(derived);
}

/**
 * 派生加密数据库文件名（不含扩展名）
 * 用于在 KakaoTalk 容器目录中定位数据库文件
 */
export async function deriveDatabaseName(userId, uuid) {
  // Swift: ["." , "F", userId, "A", "F", reverse(uuid), ".", "|"].joined(".")
  const hawawa = ['.', 'F', String(userId), 'A', 'F', reverseStr(uuid), '.', '|'].join('.');
  const salt = reverseStr(await hashedDeviceUUID(uuid));
  const derived = await pbkdf2Sha256(hawawa, salt, 100000, 128);
  const hex = bytesToHex(derived);
  // Swift: hex[28 ..< 28+78]
  return hex.slice(28, 28 + 78);
}

/**
 * 校验 UUID 格式（8-4-4-4-12 十六进制）
 */
export function isValidUUID(uuid) {
  return /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/.test(uuid.trim());
}
