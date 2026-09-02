/**
 * SHA-512 userId 爆破 worker 线程
 *
 * 与主进程约定：
 * - workerData: { hash, start, end, flag }（flag 为 SharedArrayBuffer 中止标志）
 * - 消息：progress（节流上报）/ found（命中）/ done（扫描完成）/ aborted
 */
const { parentPort, workerData } = require('worker_threads');
const crypto = require('crypto');

const flag = new Int32Array(workerData.flag);
const target = Buffer.from(workerData.hash, 'hex');
const start = workerData.start;
const end = workerData.end;

let lastReport = 0;

for (let i = start; i < end; i++) {
  // 每 32768 个候选检查一次中止标志并节流上报进度
  if ((i & 0x7fff) === 0) {
    if (Atomics.load(flag, 0) === 1) {
      parentPort.postMessage({ type: 'aborted' });
      process.exit(0);
    }
    const now = Date.now();
    if (now - lastReport > 120) {
      lastReport = now;
      parentPort.postMessage({ type: 'progress', checked: i - start });
    }
  }
  const digest = crypto.createHash('sha512').update(String(i)).digest();
  if (digest.equals(target)) {
    parentPort.postMessage({ type: 'found', value: i });
    process.exit(0);
  }
}

parentPort.postMessage({ type: 'done', checked: end - start });
