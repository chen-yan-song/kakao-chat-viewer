/**
 * 纯 JavaScript SHA-512 实现（无外部依赖，无每轮对象分配）
 * 用于从 KakaoTalk plist 中的 SHA-512(userId) 哈希爆破恢复 userId
 * （与 kakaocli DeviceInfo.swift 的 recoverUserIdFromSHA512 逻辑一致）
 *
 * 性能优化：核心压缩循环完全内联为 32 位标量运算，W 调度与常量表
 * 使用模块级 Int32Array 缓存，避免 GC 压力。
 */

// SHA-512 初始哈希值 H[0..7]（高 32 位 / 低 32 位）
const H_HI = new Int32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
const H_LO = new Int32Array([0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1, 0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179]);

// 轮常量 K[0..79]（64 位，拆成高低 32 位）
const K_HI = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  0xca273ece, 0xd186b8c7, 0xeada7dd6, 0xf57d4f7f, 0x06f067aa, 0x0a637dc5, 0x113f9804, 0x1b710b35,
  0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 0x431d67c4, 0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c,
]);
const K_LO = new Int32Array([
  0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc, 0xf348b538, 0xb605d019, 0xaf194f9b, 0xda6d8118,
  0xa3030242, 0x45706fbe, 0x4ee4b28c, 0xd5ffb4e2, 0xf27b896f, 0x3b1696b1, 0x25c71235, 0xcf692694,
  0x9ef14ad2, 0x384f25e3, 0x8b8cd5b5, 0x77ac9c65, 0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5,
  0xee66dfab, 0x2db43210, 0x98fb213f, 0xbeef0ee4, 0x3da88fc2, 0x930aa725, 0xe003826f, 0x0a0e6e70,
  0x46d22ffc, 0x5c26c926, 0x5ac42aed, 0x9d95b3df, 0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b,
  0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30, 0xd6ef5218, 0x5565a910, 0x5771202a, 0x32bbd1b8,
  0xb8d2d0c8, 0x5141ab53, 0xdf8eeb99, 0xe19b48a8, 0xc5c95a63, 0xe3418acb, 0x7763e373, 0xd6b2b8a3,
  0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec, 0x23631e28, 0xde82bde9, 0xb2c67915, 0xe372532b,
  0xea26619c, 0x21c0c207, 0xcde0eb1e, 0xee6ed178, 0x72176fba, 0xa2c898a6, 0xbef90dae, 0x131c471b,
  0x23047d84, 0x40c72493, 0x15c9bebc, 0x9c100d4c, 0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817,
]);

// 消息调度缓存（单线程重入安全：sha512Bytes 为同步函数）
const W_HI = new Int32Array(80);
const W_LO = new Int32Array(80);

/**
 * 对 128 字节块做压缩，将结果累加到 h（8 对 hi/lo）
 */
function compressBlock(block, hHi, hLo) {
  // 消息调度 W[0..15]
  for (let t = 0; t < 16; t++) {
    const o = t * 8;
    W_HI[t] = (block[o] << 24) | (block[o + 1] << 16) | (block[o + 2] << 8) | block[o + 3];
    W_LO[t] = (block[o + 4] << 24) | (block[o + 5] << 16) | (block[o + 6] << 8) | block[o + 7];
  }
  // 消息调度 W[16..79]
  for (let t = 16; t < 80; t++) {
    const xh = W_HI[t - 15], xl = W_LO[t - 15];
    const yh = W_HI[t - 2], yl = W_LO[t - 2];
    // s0 = ROTR(x,1) ^ ROTR(x,8) ^ SHR(x,7)
    const s0hi = ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7);
    const s0lo = ((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25));
    // s1 = ROTR(y,19) ^ ROTR(y,61) ^ SHR(y,6)
    const s1hi = ((yh >>> 19) | (yl << 13)) ^ ((yl >>> 29) | (yh << 3)) ^ (yh >>> 6);
    const s1lo = ((yl >>> 19) | (yh << 13)) ^ ((yh >>> 29) | (yl << 3)) ^ ((yl >>> 6) | (yh << 26));
    // W[t] = W[t-16] + s0 + W[t-7] + s1
    let lo = (W_LO[t - 16] + s0lo) >>> 0;
    let hi = ((W_HI[t - 16] + s0hi + (lo < (W_LO[t - 16] >>> 0) ? 1 : 0)) | 0);
    let lo2 = (lo + W_LO[t - 7]) >>> 0;
    hi = (hi + W_HI[t - 7] + (lo2 < lo ? 1 : 0)) | 0;
    let lo3 = (lo2 + s1lo) >>> 0;
    hi = (hi + s1hi + (lo3 < lo2 ? 1 : 0)) | 0;
    W_HI[t] = hi;
    W_LO[t] = lo3 | 0;
  }

  let aHi = hHi[0], aLo = hLo[0];
  let bHi = hHi[1], bLo = hLo[1];
  let cHi = hHi[2], cLo = hLo[2];
  let dHi = hHi[3], dLo = hLo[3];
  let eHi = hHi[4], eLo = hLo[4];
  let fHi = hHi[5], fLo = hLo[5];
  let gHi = hHi[6], gLo = hLo[6];
  let hhHi = hHi[7], hhLo = hLo[7];

  for (let t = 0; t < 80; t++) {
    // S1 = ROTR(e,14) ^ ROTR(e,18) ^ ROTR(e,41)
    const S1hi = ((eHi >>> 14) | (eLo << 18)) ^ ((eHi >>> 18) | (eLo << 14)) ^ ((eLo >>> 9) | (eHi << 23));
    const S1lo = ((eLo >>> 14) | (eHi << 18)) ^ ((eLo >>> 18) | (eHi << 14)) ^ ((eHi >>> 9) | (eLo << 23));
    // ch = (e & f) ^ (~e & g)
    const chHi = ((eHi & fHi) ^ (~eHi & gHi)) | 0;
    const chLo = ((eLo & fLo) ^ (~eLo & gLo)) | 0;
    // T1 = h + S1 + ch + K[t] + W[t]
    let t1Lo = (hhLo + S1lo) >>> 0;
    let t1Hi = (hhHi + S1hi + (t1Lo < (hhLo >>> 0) ? 1 : 0)) | 0;
    let t1Lo2 = (t1Lo + chLo) >>> 0;
    t1Hi = (t1Hi + chHi + (t1Lo2 < t1Lo ? 1 : 0)) | 0;
    let t1Lo3 = (t1Lo2 + K_LO[t]) >>> 0;
    t1Hi = (t1Hi + K_HI[t] + (t1Lo3 < t1Lo2 ? 1 : 0)) | 0;
    let t1Lo4 = (t1Lo3 + W_LO[t]) >>> 0;
    t1Hi = (t1Hi + W_HI[t] + (t1Lo4 < t1Lo3 ? 1 : 0)) | 0;
    // S0 = ROTR(a,28) ^ ROTR(a,34) ^ ROTR(a,39)
    const S0hi = ((aHi >>> 28) | (aLo << 4)) ^ ((aLo >>> 2) | (aHi << 30)) ^ ((aLo >>> 7) | (aHi << 25));
    const S0lo = ((aLo >>> 28) | (aHi << 4)) ^ ((aHi >>> 2) | (aLo << 30)) ^ ((aHi >>> 7) | (aLo << 25));
    // maj = (a & b) ^ (a & c) ^ (b & c)
    const majHi = ((aHi & bHi) ^ (aHi & cHi) ^ (bHi & cHi)) | 0;
    const majLo = ((aLo & bLo) ^ (aLo & cLo) ^ (bLo & cLo)) | 0;
    // T2 = S0 + maj
    let t2Lo = (S0lo + majLo) >>> 0;
    const t2Hi = (S0hi + majHi + (t2Lo < (S0lo >>> 0) ? 1 : 0)) | 0;

    hhHi = gHi; hhLo = gLo;
    gHi = fHi; gLo = fLo;
    fHi = eHi; fLo = eLo;
    // e = d + T1
    let eLo2 = (dLo + t1Lo4) >>> 0;
    eHi = (dHi + t1Hi + (eLo2 < (dLo >>> 0) ? 1 : 0)) | 0;
    eLo = eLo2 | 0;
    dHi = cHi; dLo = cLo;
    cHi = bHi; cLo = bLo;
    bHi = aHi; bLo = aLo;
    // a = T1 + T2
    let aLo2 = (t1Lo4 + t2Lo) >>> 0;
    aHi = (t1Hi + t2Hi + (aLo2 < t1Lo4 ? 1 : 0)) | 0;
    aLo = aLo2 | 0;
  }

  // 累加（注意 low→high 进位）
  for (let i = 0; i < 8; i++) {
    const loSum = (hLo[i] + [aLo, bLo, cLo, dLo, eLo, fLo, gLo, hhLo][i]) >>> 0;
    const carry = loSum < (hLo[i] >>> 0) ? 1 : 0;
    hHi[i] = (hHi[i] + [aHi, bHi, cHi, dHi, eHi, fHi, gHi, hhHi][i] + carry) | 0;
    hLo[i] = loSum | 0;
  }
}

/** 计算输入字节数组的 SHA-512，返回 64 字节 Uint8Array */
export function sha512Bytes(data) {
  const len = data.length;
  const bitLenHi = Math.floor(len / 0x20000000); // len*8 的高 32 位
  const bitLenLo = (len << 3) >>> 0;
  // 填充后总长度 = ceil((len + 1 + 16) / 128) * 128（1 字节 0x80 + 16 字节长度字段）
  const totalLen = Math.ceil((len + 17) / 128) * 128;
  const padded = new Uint8Array(totalLen);
  padded.set(data);
  padded[len] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, bitLenHi, false);
  view.setUint32(padded.length - 4, bitLenLo, false);

  const hHi = new Int32Array(H_HI);
  const hLo = new Int32Array(H_LO);
  for (let i = 0; i < padded.length; i += 128) {
    compressBlock(padded.subarray(i, i + 128), hHi, hLo);
  }

  const out = new Uint8Array(64);
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) {
    outView.setUint32(i * 8, hHi[i] >>> 0, false);
    outView.setUint32(i * 8 + 4, hLo[i] >>> 0, false);
  }
  return out;
}

/** 计算字符串的 SHA-512，返回 64 字节 Uint8Array */
export function sha512(str) {
  return sha512Bytes(new TextEncoder().encode(str));
}

/** 计算字符串的 SHA-512 hex（128 字符，小写） */
export function sha512Hex(str) {
  const bytes = sha512(str);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * 爆破 SHA-512(userId) 的前像
 * @param {string} hexHash 128 字符 hex 哈希
 * @param {Object} opts {start, end, chunk, onProgress}
 *   onProgress(checkedSoFar) 每 chunk 回调一次；返回 true 表示中止
 * @returns {Promise<number|null>}
 */
export async function bruteForceUserId(hexHash, { start = 0, end = 100000000, chunk = 50000, onProgress } = {}) {
  if (hexHash.length !== 128) throw new Error('无效的 SHA-512 哈希长度');
  const target = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    target[i] = parseInt(hexHash.slice(i * 2, i * 2 + 2), 16);
  }
  for (let i = start; i <= end; i += chunk) {
    const stop = Math.min(i + chunk - 1, end);
    for (let n = i; n <= stop; n++) {
      const digest = sha512(String(n));
      let match = true;
      for (let j = 0; j < 64; j++) {
        if (digest[j] !== target[j]) { match = false; break; }
      }
      if (match) return n;
    }
    if (onProgress) {
      const abort = await onProgress(stop);
      if (abort === true) return null; // 用户中止
    }
    // 让出主线程，避免页面卡死
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  return null;
}
