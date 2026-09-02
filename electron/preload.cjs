/**
 * Preload 桥接：以最小 API 面暴露主进程能力给渲染进程
 */
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('kakaoApp', {
  /** 渲染进程日志转发到主进程（诊断用） */
  log: (msg) => ipcRenderer.send('renderer-log', String(msg)),

  /** 自动发现：UUID、plist 内容、数据库文件列表 */
  discover: () => ipcRenderer.invoke('discover'),

  /** 读取 KakaoTalk 容器内的数据库文件（主进程校验路径白名单） */
  readDbFile: (p) => ipcRenderer.invoke('read-db-file', p),

  /** 启动多线程 SHA-512 爆破；进度经 onBruteProgress 事件回传 */
  bruteStart: (opts) => ipcRenderer.invoke('brute-start', opts),
  bruteStop: () => ipcRenderer.invoke('brute-stop'),
  onBruteProgress: (cb) => {
    ipcRenderer.removeAllListeners('brute-progress');
    ipcRenderer.on('brute-progress', (_e, d) => cb(d));
  },

  /** 保存单个文本文件（系统保存对话框） */
  saveText: (defaultName, content) =>
    ipcRenderer.invoke('save-text', { defaultName, content }),

  /** 批量导出：选择目标文件夹后写入全部文件 */
  exportAll: (files) => ipcRenderer.invoke('export-all', { files }),

  /** 在 Finder 中显示文件 */
  showInFolder: (p) => ipcRenderer.invoke('show-in-folder', p),
});
