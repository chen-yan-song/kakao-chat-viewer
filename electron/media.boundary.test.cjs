/**
 * 媒体解析边界测试（无需真实 KakaoTalk 目录 / 外网）
 *
 * 覆盖：路径哈希、Pkv2 加解密、本地命中/未命中、缩略图回退、
 * CDN 过期/无 cs/超大/校验失败/成功、语音无本地缓存、相册多帧、非法 ID、关闭 CDN。
 *
 * 用法：node electron/media.boundary.test.cjs
 */
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const media = require('./media.cjs');
const {
  resolveMedia,
  decryptPkv2,
  sha1Rev,
  sha1Hex,
  photoFullStem,
  photoThumbStem,
  videoFullStem,
  albumFullStem,
  chatDirName,
  mediaKeyString,
  isCdnExpired,
  urlExpires,
  buildFrames,
  parseAttachment,
  MAX_CDN_BYTES,
} = media;

let passed = 0;
let failed = 0;

function caseName(name) {
  return name;
}

async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ✓ ${name}`);
  } catch (e) {
    failed += 1;
    console.error(`  ✗ ${name}`);
    console.error(`    ${e && e.stack ? e.stack.split('\n').slice(0, 3).join('\n    ') : e}`);
  }
}

/** 构造合法 Pkv2 文件（与生产算法一致） */
function makePkv2(logId, imageBuf) {
  const keyString = mediaKeyString(logId);
  const aesKey = crypto.createHash('sha256').update(keyString, 'utf8').digest();
  const iv = Buffer.alloc(16, 0);
  for (let i = 0; i < 16; i++) iv[i] = i;
  const header = Buffer.from('0123456789abcdef'.repeat(16)); // 256
  const plain = Buffer.concat([header, imageBuf]);
  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([Buffer.from('Pkv2'), iv, ct]);
}

function makeTinyJpeg() {
  // 最小可识别 JPEG 头 + 测试载荷
  return Buffer.from('ffd8ffe04b41544f4b2d424f554e44415259ffd9', 'hex');
}

function tmpRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'kkv-media-bound-'));
}

function writeCache(root, chatId, stem, ext, bytes) {
  const dir = path.join(root, chatDirName(chatId));
  fs.mkdirSync(dir, { recursive: true });
  const p = path.join(dir, stem + ext);
  fs.writeFileSync(p, bytes);
  return p;
}

async function main() {
  console.log('媒体边界测试\n');

  // ---------- 路径 / 密钥边界 ----------
  await test(caseName('路径：官方向量 photo/chat stem'), () => {
    assert.strictEqual(sha1Rev('p1234567890123'), '6a57dbd91a25d5f1e503c316e13487b6abd8de5c');
    assert.strictEqual(chatDirName(1234567890123), 'f3040a56bce932b9fe31cf4e68a2eae23c33165b');
    assert.strictEqual(photoFullStem(1234567890123), '6a57dbd91a25d5f1e503c316e13487b6abd8de5c');
  });

  await test(caseName('路径：chatId 数字与字符串等价'), () => {
    assert.strictEqual(chatDirName(42), chatDirName('42'));
    assert.notStrictEqual(chatDirName(42), chatDirName(24)); // reverse 后不同
  });

  await test(caseName('路径：相册帧 stem ≠ 单图 stem'), () => {
    const logId = 999;
    assert.notStrictEqual(albumFullStem(logId, 0), photoFullStem(logId));
    assert.notStrictEqual(albumFullStem(logId, 0), albumFullStem(logId, 1));
  });

  await test(caseName('路径：视频 stem 前缀 v'), () => {
    assert.strictEqual(videoFullStem(77), sha1Rev('v77'));
    assert.notStrictEqual(videoFullStem(77), photoFullStem(77));
  });

  await test(caseName('密钥：mediaKeyString 反转边界'), () => {
    assert.strictEqual(mediaKeyString(1234567890123), '%3210987654321#');
    assert.strictEqual(mediaKeyString(0), '%0#');
    assert.strictEqual(mediaKeyString(1), '%1#');
  });

  // ---------- Pkv2 加解密边界 ----------
  await test(caseName('Pkv2：正确解密'), () => {
    const logId = 424242;
    const img = makeTinyJpeg();
    const file = makePkv2(logId, img);
    assert.deepStrictEqual(decryptPkv2(file, logId), img);
  });

  await test(caseName('Pkv2：错误 magic 抛错'), () => {
    assert.throws(() => decryptPkv2(Buffer.from('XXXX' + '0'.repeat(64)), 1), /不是 Pkv2/);
  });

  await test(caseName('Pkv2：密文未对齐抛错'), () => {
    const bad = Buffer.concat([Buffer.from('Pkv2'), Buffer.alloc(16), Buffer.alloc(17)]);
    assert.throws(() => decryptPkv2(bad, 1), /未按块对齐/);
  });

  await test(caseName('Pkv2：错误 logId 无法解密'), () => {
    const file = makePkv2(100, makeTinyJpeg());
    assert.throws(() => decryptPkv2(file, 101));
  });

  // ---------- CDN URL 过期边界 ----------
  await test(caseName('CDN：expires 解析'), () => {
    assert.strictEqual(urlExpires('https://x/?expires=1700000000&s=1'), 1700000000);
    assert.strictEqual(urlExpires('https://x/no-exp'), null);
  });

  await test(caseName('CDN：刚好过期 / 刚好未过期'), () => {
    const now = 1_700_000_000;
    assert.strictEqual(isCdnExpired(`https://cdn/?expires=${now - 1}`, now), true);
    assert.strictEqual(isCdnExpired(`https://cdn/?expires=${now}`, now), false); // expires == now：未过期
    assert.strictEqual(isCdnExpired(`https://cdn/?expires=${now + 1}`, now), false);
  });

  // ---------- buildFrames / attachment 边界 ----------
  await test(caseName('attachment：非法 JSON → 空对象'), () => {
    assert.deepStrictEqual(parseAttachment('{bad'), {});
    assert.deepStrictEqual(parseAttachment(null), {});
    assert.deepStrictEqual(parseAttachment(''), {});
  });

  await test(caseName('buildFrames：type2 / 3 / 4 / 18 / 27 / 未知'), () => {
    assert.strictEqual(buildFrames(2, 1, { cs: 'aa' }).length, 1);
    assert.strictEqual(buildFrames(2, 1, { cs: 'aa' })[0].kind, 'photo');
    assert.strictEqual(buildFrames(3, 1, {}).length, 1);
    assert.strictEqual(buildFrames(3, 1, {})[0].kind, 'video');
    assert.strictEqual(buildFrames(4, 1, { url: 'https://x' })[0].kind, 'file');
    assert.strictEqual(buildFrames(18, 1, { name: 'a.zip' })[0].kind, 'file');
    assert.strictEqual(buildFrames(27, 9, { csl: ['a', 'b'], imageUrls: ['u0', 'u1'] }).length, 2);
    assert.strictEqual(buildFrames(1, 1, {}).length, 0);
    assert.strictEqual(buildFrames(20, 1, {}).length, 0);
  });

  // ---------- resolveMedia 端到端边界（注入 roots / fetch） ----------
  await test(caseName('resolve：非法 chatId/logId'), async () => {
    const r = await resolveMedia({ chatId: NaN, logId: 1, type: 2, attachment: {} });
    assert.strictEqual(r.frames[0].reason, 'invalid-ids');
  });

  await test(caseName('resolve：不支持的类型'), async () => {
    const r = await resolveMedia({ chatId: 1, logId: 1, type: 1, attachment: {} });
    assert.strictEqual(r.frames[0].reason, 'unsupported-type');
  });

  await test(caseName('resolve：本地 full 命中'), async () => {
    const root = tmpRoot();
    const chatId = 1001;
    const logId = 2002;
    const img = makeTinyJpeg();
    writeCache(root, chatId, photoFullStem(logId), '.img', makePkv2(logId, img));
    const r = await resolveMedia({
      chatId,
      logId,
      type: 2,
      attachment: {},
      allowCdn: false,
      accountRoots: [root],
    });
    assert.strictEqual(r.frames[0].ok, true);
    assert.strictEqual(r.frames[0].tier, 'full');
    assert.strictEqual(Buffer.from(r.frames[0].base64, 'base64').equals(img), true);
    fs.rmSync(root, { recursive: true, force: true });
  });

  await test(caseName('resolve：未缓存 + 关 CDN → not-cached+cdn-disabled'), async () => {
    const root = tmpRoot();
    const r = await resolveMedia({
      chatId: 7,
      logId: 8,
      type: 2,
      attachment: { url: 'https://x/?expires=9999999999', cs: 'abc' },
      allowCdn: false,
      accountRoots: [root],
    });
    assert.strictEqual(r.frames[0].ok, false);
    assert.ok(r.frames[0].reason.includes('not-cached'));
    assert.ok(r.frames[0].reason.includes('cdn-disabled'));
    fs.rmSync(root, { recursive: true, force: true });
  });

  await test(caseName('resolve：CDN 已过期（不发请求）'), async () => {
    let fetched = false;
    const r = await resolveMedia({
      chatId: 1,
      logId: 2,
      type: 2,
      attachment: { url: 'https://cdn.example/img?expires=100', cs: 'aa'.repeat(20) },
      accountRoots: [],
      nowSec: 200,
      fetchImpl: async () => {
        fetched = true;
        return Buffer.from('x');
      },
    });
    assert.strictEqual(fetched, false);
    assert.ok(r.frames[0].reason.includes('cdn-expired'));
  });

  await test(caseName('resolve：CDN 无 cs → cdn-unverifiable'), async () => {
    let fetched = false;
    const r = await resolveMedia({
      chatId: 1,
      logId: 2,
      type: 2,
      attachment: { url: 'https://cdn.example/img?expires=9999999999' },
      accountRoots: [],
      nowSec: 1,
      fetchImpl: async () => {
        fetched = true;
        return Buffer.from('x');
      },
    });
    assert.strictEqual(fetched, false);
    assert.ok(r.frames[0].reason.includes('cdn-unverifiable'));
  });

  await test(caseName('resolve：CDN 声明体积超限'), async () => {
    let fetched = false;
    const r = await resolveMedia({
      chatId: 1,
      logId: 2,
      type: 2,
      attachment: {
        url: 'https://cdn.example/img?expires=9999999999',
        cs: 'aa'.repeat(20),
        s: MAX_CDN_BYTES + 1,
      },
      accountRoots: [],
      nowSec: 1,
      fetchImpl: async () => {
        fetched = true;
        return Buffer.from('x');
      },
    });
    assert.strictEqual(fetched, false);
    assert.ok(r.frames[0].reason.includes('cdn-too-large'));
  });

  await test(caseName('resolve：CDN 校验失败'), async () => {
    const body = Buffer.from('hello-cdn');
    const r = await resolveMedia({
      chatId: 1,
      logId: 2,
      type: 2,
      attachment: {
        url: 'https://cdn.example/img?expires=9999999999',
        cs: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
      },
      accountRoots: [],
      nowSec: 1,
      fetchImpl: async () => body,
    });
    assert.strictEqual(r.frames[0].ok, false);
    assert.ok(r.frames[0].reason.includes('cdn-checksum-mismatch'));
  });

  await test(caseName('resolve：CDN 成功（大小写 cs）'), async () => {
    const body = Buffer.from('hello-cdn-ok');
    const cs = sha1Hex(body).toUpperCase();
    const r = await resolveMedia({
      chatId: 1,
      logId: 2,
      type: 4,
      attachment: {
        url: 'https://cdn.example/a.m4a?expires=9999999999',
        cs,
        name: 'voice.m4a',
      },
      accountRoots: [],
      nowSec: 1,
      fetchImpl: async () => body,
    });
    assert.strictEqual(r.frames[0].ok, true);
    assert.strictEqual(r.frames[0].tier, 'cdn');
    assert.strictEqual(r.frames[0].name, 'voice.m4a');
    // 语音无本地档
    assert.ok(!r.frames[0].reason || r.frames[0].reason === 'cdn');
  });

  await test(caseName('resolve：语音无本地缓存标记'), async () => {
    const r = await resolveMedia({
      chatId: 1,
      logId: 2,
      type: 4,
      attachment: {},
      allowCdn: true,
      accountRoots: [],
    });
    assert.strictEqual(r.frames[0].ok, false);
    assert.ok(r.frames[0].reason.includes('no-local-cache'));
    assert.ok(r.frames[0].reason.includes('no-cdn-url'));
  });

  await test(caseName('resolve：仅缩略图回退'), async () => {
    const root = tmpRoot();
    const chatId = 55;
    const logId = 66;
    const thumb = makeTinyJpeg();
    writeCache(root, chatId, photoThumbStem(logId), '.thm', makePkv2(logId, thumb));
    const r = await resolveMedia({
      chatId,
      logId,
      type: 2,
      attachment: {},
      allowCdn: false,
      accountRoots: [root],
    });
    assert.strictEqual(r.frames[0].ok, true);
    assert.strictEqual(r.frames[0].tier, 'thumb');
    fs.rmSync(root, { recursive: true, force: true });
  });

  await test(caseName('resolve：相册多帧，仅第 0 帧本地命中'), async () => {
    const root = tmpRoot();
    const chatId = 70;
    const logId = 80;
    const img0 = makeTinyJpeg();
    writeCache(root, chatId, albumFullStem(logId, 0), '.img', makePkv2(logId, img0));
    const body1 = Buffer.from('frame1-bytes');
    const r = await resolveMedia({
      chatId,
      logId,
      type: 27,
      attachment: {
        csl: [sha1Hex(img0), sha1Hex(body1)],
        imageUrls: [
          'https://cdn/?expires=9999999999',
          'https://cdn/?expires=9999999999',
        ],
        sl: [img0.length, body1.length],
      },
      accountRoots: [root],
      nowSec: 1,
      fetchImpl: async () => body1,
    });
    assert.strictEqual(r.frames.length, 2);
    assert.strictEqual(r.frames[0].tier, 'full');
    assert.strictEqual(r.frames[1].tier, 'cdn');
    fs.rmSync(root, { recursive: true, force: true });
  });

  await test(caseName('resolve：损坏本地 full → decrypt-failed 后仍可 CDN'), async () => {
    const root = tmpRoot();
    const chatId = 11;
    const logId = 22;
    writeCache(root, chatId, photoFullStem(logId), '.img', Buffer.from('not-pkv2-garbage'));
    const body = Buffer.from('from-cdn');
    const r = await resolveMedia({
      chatId,
      logId,
      type: 2,
      attachment: {
        url: 'https://cdn/?expires=9999999999',
        cs: sha1Hex(body),
      },
      accountRoots: [root],
      nowSec: 1,
      fetchImpl: async () => body,
    });
    assert.strictEqual(r.frames[0].ok, true);
    assert.strictEqual(r.frames[0].tier, 'cdn');
    assert.ok(String(r.frames[0].reason) === 'cdn');
    fs.rmSync(root, { recursive: true, force: true });
  });

  console.log(`\n结果：通过 ${passed}，失败 ${failed}`);
  if (failed > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
