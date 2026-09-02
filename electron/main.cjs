/**
 * KakaoChat Viewer — Electron 主进程
 *
 * 职责：
 * 1. 创建窗口并加载界面
 * 2. 自动发现：设备 UUID（ioreg）、KakaoTalk 偏好设置 plist、加密数据库文件
 * 3. 多线程 SHA-512 爆破 userId（worker_threads + SharedArrayBuffer 中止控制）
 * 4. 导出：保存单个文件 / 批量导出全部聊天记录
 *
 * 安全策略：contextIsolation 开启，渲染进程无 Node 权限；
 * 文件读取仅允许 KakaoTalk 容器目录。
 */
const { app, BrowserWindow, ipcMain, dialog, shell, protocol, net } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFile } = require('child_process');
const { Worker } = require('worker_threads');
const { pathToFileURL } = require('url');

// 前端资源根目录（index.html / js / vendor / css）
const APP_ROOT = path.join(__dirname, '..');

// 自定义 scheme：file:// 下的 ES module 会被 CORS 静默阻断，
// 必须用 standard + supportFetchAPI 的自定义协议承载前端资源
protocol.registerSchemesAsPrivileged([
  {
    scheme: 'app',
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
      corsEnabled: true,
    },
  },
]);

// 扩展名 → MIME 映射（ESM 模块必须是 text/javascript）
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.wasm': 'application/wasm',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.icns': 'application/octet-stream',
};

/** 把 app://local/<path> 映射到项目目录文件 */
function handleAppScheme(request) {
  const url = new URL(request.url);
  let pathname = decodeURIComponent(url.pathname);
  if (pathname === '/' || pathname === '') pathname = '/index.html';
  const filePath = path.normalize(path.join(APP_ROOT, pathname));
  // 防路径穿越：只允许 APP_ROOT 内的文件
  if (!filePath.startsWith(APP_ROOT + path.sep)) {
    return new Response('Forbidden', { status: 403 });
  }
  try {
    const data = fs.readFileSync(filePath);
    const mime = MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
    return new Response(data, { headers: { 'content-type': mime } });
  } catch {
    return new Response('Not Found', { status: 404 });
  }
}

// KakaoTalk 沙盒容器内的关键路径
const KAKAO_CONTAINER = path.join(
  os.homedir(), 'Library', 'Containers', 'com.kakao.KakaoTalkMac', 'Data', 'Library'
);
const PLIST_PATH = path.join(KAKAO_CONTAINER, 'Preferences', 'com.kakao.KakaoTalkMac.plist');
const DB_DIR = path.join(KAKAO_CONTAINER, 'Application Support', 'com.kakao.KakaoTalkMac');
const SIDE_SUFFIX_RE = /-(wal|shm|journal)$/;
// 主库文件名：80 位左右的长十六进制（PBKDF2 派生命名）
const MAIN_NAME_RE = /^[0-9a-f]{40,}$/i;

/** 通过 ioreg 获取本机 IOPlatformUUID */
function getPlatformUUID() {
  return new Promise((resolve) => {
    execFile('ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'], { timeout: 8000 }, (err, stdout) => {
      if (err) return resolve(null);
      const m = /"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"/.exec(stdout || '');
      resolve(m ? m[1] : null);
    });
  });
}

/** 检测 KakaoTalk 是否正在运行（运行中意味着最新记录可能尚未合并进主库） */
function isKakaoTalkRunning() {
  return new Promise((resolve) => {
    execFile('pgrep', ['-xq', 'KakaoTalk'], { timeout: 5000 }, (err) => resolve(!err));
  });
}

/** 扫描数据库目录：主库 + 伴随文件（-wal/-shm/-journal） */
function scanDbDir() {
  let entries;
  try {
    entries = fs.readdirSync(DB_DIR, { withFileTypes: true });
  } catch {
    return [];
  }
  const out = [];
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const name = entry.name;
    const isSide = SIDE_SUFFIX_RE.test(name);
    // 主库只收录长十六进制文件名；伴随文件只收录主库同名的
    if (!isSide && !MAIN_NAME_RE.test(name)) continue;
    let size = 0;
    try {
      size = fs.statSync(path.join(DB_DIR, name)).size;
    } catch {
      continue;
    }
    out.push({ name, size, isSide, path: path.join(DB_DIR, name) });
  }
  out.sort((a, b) => b.size - a.size);
  return out;
}

// 渲染进程日志通道（console-message 事件在 Electron 33 不可靠，改用 IPC）
ipcMain.on('renderer-log', (_e, msg) => {
  console.log('[renderer]', msg);
});

// ============ IPC：自动发现 ============
ipcMain.handle('discover', async () => {
  // 自动发现依赖 macOS 专属路径（沙盒容器）与命令（ioreg/pgrep），非 Mac 平台直接拒绝
  if (process.platform !== 'darwin') {
    throw new Error('自动发现仅支持 macOS 版本；Windows 版请使用「使用手动模式」加载数据库文件');
  }
  const [uuid, running] = await Promise.all([getPlatformUUID(), isKakaoTalkRunning()]);
  let plist = null;
  let plistExists = false;
  try {
    plist = fs.readFileSync(PLIST_PATH);
    plistExists = true;
  } catch {
    /* plist 不存在或不可读 */
  }
  return {
    uuid,
    running,
    plist,
    plistExists,
    plistPath: PLIST_PATH,
    dbDir: DB_DIR,
    dbFiles: scanDbDir(),
  };
});

/** 读取数据库文件（仅允许 KakaoTalk 容器目录内路径） */
function isAllowedPath(p) {
  const abs = path.resolve(String(p));
  const container = path.join(os.homedir(), 'Library', 'Containers', 'com.kakao.KakaoTalkMac');
  return abs.startsWith(container + path.sep);
}

ipcMain.handle('read-db-file', (_e, p) => {
  if (typeof p !== 'string' || !isAllowedPath(p)) {
    throw new Error('路径不在允许范围内');
  }
  const buf = fs.readFileSync(p);
  // 拷贝为独立的 ArrayBuffer，避免 Buffer 池共享导致 IPC 传输异常
  const copy = new Uint8Array(buf.byteLength);
  copy.set(buf);
  return copy.buffer;
});

ipcMain.handle('show-in-folder', (_e, p) => {
  if (typeof p === 'string' && fs.existsSync(p)) shell.showItemInFolder(p);
});

// ============ IPC：多线程 SHA-512 爆破 userId ============
// plist 中只存 SHA-512(String(userId)) 哈希，需要遍历数字空间还原。
// Node 原生 crypto + 多 worker 线程，比浏览器端快一个数量级以上。
let bruteState = null; // 当前爆破任务状态（单任务模式，新任务会取消旧任务）

function stopBruteWorkers(state) {
  if (!state) return;
  Atomics.store(state.flag, 0, 1); // 通知所有 worker 中止
  for (const w of state.workers) {
    try { w.terminate(); } catch { /* 忽略 */ }
  }
  state.workers = [];
}

ipcMain.handle('brute-start', (event, { hash, start = 0, end = 1_000_000_000 }) => {
  if (typeof hash !== 'string' || !/^[0-9a-fA-F]{128}$/.test(hash)) {
    return Promise.resolve({ found: null, error: '哈希格式不合法' });
  }
  // 已有任务在跑：静默取消
  if (bruteState) {
    stopBruteWorkers(bruteState);
    bruteState.stale = true;
  }

  const sender = event.sender;
  const flag = new SharedArrayBuffer(4);
  new Int32Array(flag)[0] = 0;

  const nThreads = Math.min(12, Math.max(2, os.cpus().length - 1));
  const total = Math.max(1, end - start);
  const chunk = Math.ceil(total / nThreads);

  const state = {
    flag,
    workers: [],
    positions: new Array(nThreads).fill(0),
    total,
    finished: 0,
    resolve: null,
    lastSend: 0,
    stale: false,
    sender,
  };
  bruteState = state;

  const finish = (result) => {
    if (state.stale || state.resolved) return;
    state.resolved = true;
    stopBruteWorkers(state);
    try { state.resolve(result); } catch { /* 忽略 */ }
  };

  const sendProgress = (force = false) => {
    if (state.stale || !state.sender) return;
    const now = Date.now();
    if (!force && now - state.lastSend < 150) return;
    state.lastSend = now;
    const checked = state.positions.reduce((a, b) => a + b, 0);
    if (!state.sender.isDestroyed()) {
      state.sender.send('brute-progress', { checked, total, elapsed: now - state.startedAt });
    }
  };
  state.startedAt = Date.now();
  state.sendProgress = sendProgress;

  return new Promise((resolve) => {
    state.resolve = resolve;
    let launched = 0;
    for (let t = 0; t < nThreads; t++) {
      const wStart = start + t * chunk;
      const wEnd = Math.min(end, wStart + chunk);
      if (wStart >= wEnd) { state.finished++; continue; }
      launched++;
      const worker = new Worker(path.join(__dirname, 'brute-worker.cjs'), {
        workerData: { hash: hash.toLowerCase(), start: wStart, end: wEnd, flag },
      });
      const idx = t;
      worker.on('message', (msg) => {
        if (state.stale) return;
        if (msg.type === 'progress') {
          state.positions[idx] = msg.checked;
          sendProgress();
        } else if (msg.type === 'found') {
          state.positions[idx] = msg.value - wStart;
          finish({ found: msg.value, checked: state.positions.reduce((a, b) => a + b, 0) });
        } else if (msg.type === 'done') {
          state.positions[idx] = msg.checked;
          state.finished++;
          if (state.finished >= launched) {
            sendProgress(true);
            finish({ found: null, checked: state.positions.reduce((a, b) => a + b, 0) });
          }
        }
      });
      worker.on('error', () => {
        state.finished++;
        if (state.finished >= launched && !state.resolved) {
          finish({ found: null, checked: state.positions.reduce((a, b) => a + b, 0) });
        }
      });
      state.workers.push(worker);
    }
    if (launched === 0) finish({ found: null, checked: 0 });
  });
});

ipcMain.handle('brute-stop', () => {
  if (bruteState && !bruteState.resolved) {
    finishBruteAborted(bruteState);
  }
  return true;
});

function finishBruteAborted(state) {
  if (state.stale || state.resolved) return;
  state.resolved = true;
  stopBruteWorkers(state);
  const checked = state.positions.reduce((a, b) => a + b, 0);
  try { state.resolve({ found: null, aborted: true, checked }); } catch { /* 忽略 */ }
}

// ============ IPC：导出 ============
ipcMain.handle('save-text', async (event, { defaultName, content }) => {
  const win = BrowserWindow.fromWebContents(event.sender);
  const opts = { defaultPath: defaultName };
  if (win) {
    const { canceled, filePath } = await dialog.showSaveDialog(win, opts);
    if (canceled || !filePath) return { saved: false };
    fs.writeFileSync(filePath, String(content), 'utf8');
    return { saved: true, path: filePath };
  }
  return { saved: false };
});

ipcMain.handle('export-all', async (event, { files }) => {
  const win = BrowserWindow.fromWebContents(event.sender);
  const opts = {
    properties: ['openDirectory', 'createDirectory'],
    buttonLabel: '导出到此文件夹',
    message: '选择用于存放全部聊天记录的文件夹',
  };
  const { canceled, filePaths } = win
    ? await dialog.showOpenDialog(win, opts)
    : await dialog.showOpenDialog(opts);
  if (canceled || !filePaths || !filePaths.length) return { saved: false };
  const dir = filePaths[0];
  let count = 0;
  for (const f of files || []) {
    if (!f || typeof f.name !== 'string' || typeof f.content !== 'string') continue;
    // 文件名做基础防路径穿越处理
    const safeName = f.name.replace(/[/\\:]/g, '_');
    fs.writeFileSync(path.join(dir, safeName), f.content, 'utf8');
    count++;
  }
  return { saved: true, dir, count };
});

// ============ 窗口 ============
function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 860,
    minWidth: 980,
    minHeight: 640,
    show: false,
    backgroundColor: '#f6f7f9',
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      spellcheck: false,
    },
  });
  win.once('ready-to-show', () => win.show());
  win.loadURL('app://local/index.html').catch((err) => {
    console.error('页面加载失败：', err);
  });
}

app.whenReady().then(() => {
  protocol.handle('app', handleAppScheme);
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (bruteState) stopBruteWorkers(bruteState);
  if (process.platform !== 'darwin') app.quit();
});
