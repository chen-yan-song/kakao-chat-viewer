/**
 * 媒体路径 / Pkv2 解密冒烟测试（Node 直接跑）
 * 用法：node electron/media.selftest.cjs
 */
const crypto = require('crypto');
const {
  decryptPkv2,
  sha1Rev,
  photoFullStem,
  chatDirName,
  mediaKeyString,
} = require('./media.cjs');

function assert(cond, msg) {
  if (!cond) throw new Error(msg || '断言失败');
}

assert(sha1Rev('p1234567890123') === '6a57dbd91a25d5f1e503c316e13487b6abd8de5c', 'photo stem');
assert(chatDirName(1234567890123) === 'f3040a56bce932b9fe31cf4e68a2eae23c33165b', 'chat dir');
assert(photoFullStem(1234567890123) === '6a57dbd91a25d5f1e503c316e13487b6abd8de5c', 'photoFullStem');
assert(mediaKeyString(1234567890123) === '%3210987654321#', 'media key');

const logId = 1234567890123;
const parts = [
  '506b7632000102030405060708090a0b0c0d0e0f554b63056928134b57397f6a2e06f1f04',
  'faf2ce5a3905914af3afabf90b8605bc39e6f7ffe132a0bd65963bc6fdbc111d283724581',
  'b869f60e1c85fedaf14265380a50c41ab3efa9a46bade5e1bce7dc175f8fc5d06a29cc',
  '14bb8afbe382eb5bba3e676fd35b0c002fdf5621adedc2d344db8c97873ae4c62769b',
  '38524501062322c5258f86688e325f549a11696b3e68ed354979c4df585732c1d42b',
  '49afe3ac97b46997e39c43e9818cdd9870b7032d8da56cfe0663201a1daa321ad7',
  'a1ee6bbdb584d7b76ca562e05d26eeb3dd7b777c01c18e091bb177fef85bb1013c',
  '6b632c75112780f8f1b423dc5587e17ca1aacc3c8a585373fe2142cd299303fd1',
  'ec64340e58e9dabd4c6f1b2d5298eab53a925efb785f0eac9961d736046ba914fd',
];
const file = Buffer.from(parts.join(''), 'hex');
const image = decryptPkv2(file, logId);
assert(image.toString('hex') === 'ffd8ffe04b41544f4b2d504b56322d54455354ffd9', 'decrypt image');
assert(
  crypto.createHash('sha1').update(image).digest('hex') === '91ed9414d7eb34fe648db42be27a0b7847dc8c8e',
  'sha1'
);

console.log('media.selftest 全部通过');
