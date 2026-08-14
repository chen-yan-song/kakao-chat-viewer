/**
 * KakaoChat Viewer 交互逻辑
 *
 * 流程：输入 UUID / 提取 userId → 选择加密数据库 → WASM 解密 → 聊天室列表 → 消息查看
 * 所有处理均在浏览器本地内存完成。
 */
import { KakaoDB } from './kakaoDb.js';
import { deriveSecureKey, isValidUUID } from './keyDerivation.js';
import {
  parseMessage,
  renderMessageText,
  messageTypeInfo,
  serializeExport,
} from './messageParser.js';
import {
  parsePlist,
  extractUserIdInfo,
  bruteUserIdFromHash,
  verifyUserIdHash,
} from './plistParser.js';

// ============ DOM 引用 ============
const $ = (id) => document.getElementById(id);
const el = {
  uuidInput: $('uuidInput'),
  userIdInput: $('userIdInput'),
  plistDrop: $('plistDrop'),
  plistFile: $('plistFile'),
  plistResult: $('plistResult'),
  brutePanel: $('brutePanel'),
  bruteStart: $('bruteStart'),
  bruteEnd: $('bruteEnd'),
  bruteBtn: $('bruteBtn'),
  bruteAbortBtn: $('bruteAbortBtn'),
  bruteProgress: $('bruteProgress'),
  bruteStatus: $('bruteStatus'),
  candidatePanel: $('candidatePanel'),
  candidateSelect: $('candidateSelect'),
  dbDrop: $('dbDrop'),
  dbFile: $('dbFile'),
  dbList: $('dbList'),
  openBtn: $('openBtn'),
  openHint: $('openHint'),
  progressArea: $('progressArea'),
  progressText: $('progressText'),
  progressBar: $('progressBar'),
  errorMsg: $('errorMsg'),
  setup: $('setup'),
  viewer: $('viewer'),
  chatSearch: $('chatSearch'),
  searchBtn: $('searchBtn'),
  statsBar: $('statsBar'),
  chatList: $('chatList'),
  chatTitle: $('chatTitle'),
  chatMeta: $('chatMeta'),
  exportBtn: $('exportBtn'),
  msgList: $('msgList'),
  msgEmpty: $('msgEmpty'),
  loadMoreBtn: $('loadMoreBtn'),
};

// ============ 全局状态 ============
const state = {
  uuid: '',
  userId: null,          // 最终使用的 userId
  plistHash: null,       // 待爆破的 SHA-512 哈希
  bruteAborted: false,
  mainCandidates: [],    // 用户选中的主库候选文件
  mainFile: null,        // 当前选中的主库
  sideFiles: [],         // -wal/-shm 伴随文件
  db: null,              // KakaoDB 实例
  chats: [],             // 聊天室列表
  chatMap: new Map(),    // chatId → chat
  activeChat: null,
  messages: [],          // 当前消息（按时间倒序）
  messageOffset: 0,
  hasMore: false,
  loadingMore: false,
  myId: null,
  searchMode: false,
};

// ============ 工具函数 ============
/** 智能时间戳：兼容秒 / 毫秒 / 微秒 */
function normTs(ts) {
  if (ts == null) return null;
  if (ts >= 1e14) return ts / 1e6; // 微秒
  if (ts >= 1e11) return ts / 1e3; // 毫秒
  return ts; // 秒
}

function pad2(n) {
  return String(n).padStart(2, '0');
}

/** 格式化为 YYYY-MM-DD HH:MM */
function formatDateTime(ts) {
  const t = normTs(ts);
  if (t === null || !Number.isFinite(t)) return '';
  const d = new Date(t * 1000);
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
}

/** 只取日期部分 YYYY-MM-DD（用于消息日期分隔） */
function formatDay(ts) {
  const t = normTs(ts);
  if (t === null || !Number.isFinite(t)) return '';
  const d = new Date(t * 1000);
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
}

function showError(msg) {
  el.errorMsg.textContent = msg;
  el.errorMsg.hidden = false;
}

/** HTML 转义（plist 内容属于本地用户数据，仍做防御性转义） */
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function clearError() {
  el.errorMsg.hidden = true;
  el.errorMsg.textContent = '';
}

function validUserId() {
  const v = el.userIdInput.value.trim();
  if (!/^\d+$/.test(v)) return null;
  const n = Number(v);
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

/** 根据输入状态刷新「解密」按钮 */
function refreshOpenBtn() {
  const uuidOk = isValidUUID(el.uuidInput.value);
  const uidOk = validUserId() !== null;
  const fileOk = state.mainFile !== null;
  const ok = uuidOk && uidOk && fileOk;
  el.openBtn.disabled = !ok;
  const missing = [];
  if (!uuidOk) missing.push('UUID');
  if (!uidOk) missing.push('用户 ID');
  if (!fileOk) missing.push('数据库文件');
  el.openHint.textContent = ok
    ? '准备就绪，点击开始解密（首次加载 WASM 需几秒）'
    : `请填写：${missing.join('、')}`;
}

// ============ plist 上传与 userId 提取 ============
function setupPlistDrop() {
  el.plistDrop.addEventListener('click', () => el.plistFile.click());
  el.plistFile.addEventListener('change', () => {
    if (el.plistFile.files.length) handlePlistFile(el.plistFile.files[0]);
    el.plistFile.value = '';
  });
  for (const evt of ['dragover', 'dragenter']) {
    el.plistDrop.addEventListener(evt, (e) => {
      e.preventDefault();
      el.plistDrop.classList.add('dragover');
    });
  }
  for (const evt of ['dragleave', 'drop']) {
    el.plistDrop.addEventListener(evt, (e) => {
      e.preventDefault();
      el.plistDrop.classList.remove('dragover');
    });
  }
  el.plistDrop.addEventListener('drop', (e) => {
    const f = e.dataTransfer.files[0];
    if (f) handlePlistFile(f);
  });
}

function showPlistResult(cls, html) {
  el.plistResult.className = 'plist-result ' + cls;
  el.plistResult.innerHTML = html;
  el.plistResult.hidden = false;
}

async function handlePlistFile(file) {
  clearError();
  el.brutePanel.hidden = true;
  el.candidatePanel.hidden = true;
  state.plistHash = null;
  try {
    const buf = await file.arrayBuffer();
    const plist = parsePlist(buf);
    if (!plist) {
      showPlistResult('err', '无法解析该 plist 文件（不是合法的 XML / bplist00 格式）');
      return;
    }
    const info = extractUserIdInfo(plist);
    if (info.direct !== null) {
      el.userIdInput.value = String(info.direct);
      showPlistResult(
        'ok',
        `✅ 已从 plist 提取用户 ID：<span class="uid">${escapeHtml(info.direct)}</span>（来源：偏好设置键名）`
      );
    } else if (info.hash) {
      state.plistHash = info.hash;
      showPlistResult(
        'warn',
        'plist 中未直接存 userId，但找到其 <b>SHA-512 哈希</b>，可尝试爆破还原（下方面板）'
      );
      el.brutePanel.hidden = false;
      el.bruteStatus.textContent = '';
      el.bruteProgress.hidden = true;
    } else if (info.candidates.length > 0) {
      el.candidateSelect.innerHTML = '';
      for (const c of info.candidates) {
        const opt = document.createElement('option');
        opt.value = String(c);
        opt.textContent = String(c);
        el.candidateSelect.appendChild(opt);
      }
      el.candidatePanel.hidden = false;
      el.userIdInput.value = String(info.candidates[0]);
      showPlistResult('warn', `找到 ${info.candidates.length} 个候选账号，请在下方选择（已默认选第一个）`);
    } else {
      showPlistResult('warn', '未能从 plist 中提取用户 ID，请手动填写');
    }
  } catch (e) {
    showPlistResult('err', '读取 plist 失败：' + e.message);
  }
  refreshOpenBtn();
}

function setupBruteForce() {
  el.bruteBtn.addEventListener('click', async () => {
    if (!state.plistHash) return;
    const start = Math.max(0, Number(el.bruteStart.value) || 0);
    const end = Math.max(1, Number(el.bruteEnd.value) || 0);
    if (end <= start) {
      showPlistResult('err', '爆破范围不合法：结束值必须大于起始值');
      return;
    }
    // 先快速验证几个常见范围外的小值（0、1…9）不必单独处理，直接跑
    state.bruteAborted = false;
    el.bruteBtn.hidden = true;
    el.bruteAbortBtn.hidden = false;
    el.bruteProgress.hidden = false;
    el.bruteProgress.querySelector('.progress-bar').style.width = '0%';
    const total = end - start + 1;
    const t0 = performance.now();
    el.bruteStatus.textContent = `开始爆破（范围 ${start} ~ ${end}，共 ${total.toLocaleString()} 个候选）…`;

    const found = await bruteUserIdFromHash(state.plistHash, {
      maxId: end,
      onProgress: (checked) => {
        if (state.bruteAborted) return true;
        const pct = Math.min(100, ((checked - start + 1) / total) * 100);
        el.bruteProgress.querySelector('.progress-bar').style.width = pct.toFixed(2) + '%';
        const elapsed = (performance.now() - t0) / 1000;
        const speed = Math.round((checked - start + 1) / Math.max(0.1, elapsed));
        const remain = Math.round((total - (checked - start + 1)) / Math.max(1, speed));
        el.bruteStatus.textContent =
          `已尝试 ${checked.toLocaleString()} / ${total.toLocaleString()}（${pct.toFixed(1)}%）` +
          ` · ${speed.toLocaleString()} 次/秒 · 预计剩余 ${remain} 秒`;
        return false;
      },
    });

    el.bruteBtn.hidden = false;
    el.bruteAbortBtn.hidden = true;
    if (found !== null) {
      el.userIdInput.value = String(found);
      showPlistResult('ok', `🎉 爆破成功！用户 ID：<span class="uid">${escapeHtml(found)}</span>`);
      el.bruteStatus.textContent = '';
    } else if (state.bruteAborted) {
      el.bruteStatus.textContent = '已手动停止';
    } else {
      el.bruteStatus.textContent = '在指定范围内未找到匹配的 userId，可扩大范围重试或手动填写';
    }
    refreshOpenBtn();
  });

  el.bruteAbortBtn.addEventListener('click', () => {
    state.bruteAborted = true;
    el.bruteAbortBtn.disabled = true;
  });

  el.candidateSelect.addEventListener('change', () => {
    el.userIdInput.value = el.candidateSelect.value;
    refreshOpenBtn();
  });
}

// ============ 数据库文件选择 ============
function setupDbDrop() {
  el.dbDrop.addEventListener('click', () => el.dbFile.click());
  el.dbFile.addEventListener('change', () => {
    if (el.dbFile.files.length) handleDbFiles(Array.from(el.dbFile.files));
    el.dbFile.value = '';
  });
  for (const evt of ['dragover', 'dragenter']) {
    el.dbDrop.addEventListener(evt, (e) => {
      e.preventDefault();
      el.dbDrop.classList.add('dragover');
    });
  }
  for (const evt of ['dragleave', 'drop']) {
    el.dbDrop.addEventListener(evt, (e) => {
      e.preventDefault();
      el.dbDrop.classList.remove('dragover');
    });
  }
  el.dbDrop.addEventListener('drop', (e) => {
    const files = Array.from(e.dataTransfer.files);
    if (files.length) handleDbFiles(files);
  });
}

const SIDE_SUFFIXES = ['-wal', '-shm', '-journal'];

function handleDbFiles(files) {
  clearError();
  const sides = [];
  const mains = [];
  for (const f of files) {
    const isSide = SIDE_SUFFIXES.some((s) => f.name.endsWith(s));
    if (isSide) sides.push(f);
    else mains.push(f);
  }
  if (mains.length === 0) {
    showError('所选文件中没有主数据库文件（不含 -wal/-shm/-journal 后缀的文件）');
    return;
  }
  state.mainCandidates = mains.sort((a, b) => b.size - a.size);
  state.mainFile = state.mainCandidates[0];
  state.sideFiles = sides;
  renderDbList();
  refreshOpenBtn();
}

function renderDbList() {
  el.dbList.innerHTML = '';
  el.dbList.hidden = false;
  const rows = [];
  for (const f of state.mainCandidates) {
    rows.push(fileRow(f.name, f.size, f === state.mainFile ? '主库' : '候选', f));
  }
  for (const f of state.sideFiles) {
    rows.push(fileRow(f.name, f.size, f.name.match(/-(wal|shm|journal)$/)?.[1]?.toUpperCase() || '伴随', null, 'side'));
  }
  for (const r of rows) el.dbList.appendChild(r);
}

function fileRow(name, size, tag, file, tagCls = '') {
  const li = document.createElement('li');
  const spanName = document.createElement('span');
  spanName.className = 'fname';
  spanName.textContent = name;
  const spanSize = document.createElement('span');
  spanSize.style.cssText = 'font-size:11px;color:#999;flex-shrink:0';
  spanSize.textContent = (size / 1024 / 1024).toFixed(1) + ' MB';
  const spanTag = document.createElement('span');
  spanTag.className = 'ftag' + (tagCls ? ' ' + tagCls : '');
  spanTag.textContent = tag;
  li.append(spanName, spanSize, spanTag);
  if (file) {
    li.style.cursor = 'pointer';
    li.title = '点击设为要解密的主库';
    li.addEventListener('click', () => {
      if (state.mainFile === file) return;
      state.mainFile = file;
      renderDbList();
      refreshOpenBtn();
    });
  }
  return li;
}

// ============ 打开数据库 ============
async function openDatabase() {
  clearError();
  const uuid = el.uuidInput.value.trim();
  const userId = validUserId();
  if (!isValidUUID(uuid) || userId === null || !state.mainFile) return;

  state.uuid = uuid;
  state.userId = userId;
  el.openBtn.disabled = true;
  el.progressArea.hidden = false;
  el.progressBar.className = 'progress-bar indeterminate';
  el.progressText.textContent = '正在派生加密密钥（PBKDF2 100,000 次迭代）…';

  try {
    const key = await deriveSecureKey(userId, uuid);
    el.progressText.textContent = '密钥派生完成，加载 SQLCipher WASM 并解密数据库…';

    const db = new KakaoDB();
    await db.open({
      file: state.mainFile,
      sideFiles: state.sideFiles,
      key,
      onProgress: (stage, detail) => {
        if (stage === 'wasm' || stage === 'write' || stage === 'decrypt') {
          el.progressText.textContent = detail;
        } else if (stage === 'done') {
          el.progressBar.className = 'progress-bar';
          el.progressBar.style.width = '100%';
          el.progressText.textContent = '✅ ' + detail;
        }
      },
    });

    state.db = db;
    state.myId = db.myUserId() ?? userId;
    await enterViewer();
  } catch (e) {
    el.progressBar.className = 'progress-bar';
    el.progressBar.style.width = '0%';
    el.progressArea.hidden = true;
    showError('解密失败：' + e.message);
    el.openBtn.disabled = false;
  }
}

/** 解密成功后切换到查看界面 */
async function enterViewer() {
  const db = state.db;
  el.setup.hidden = true;
  el.viewer.hidden = false;

  // 统计信息
  const stats = db.stats();
  const parts = [];
  if (stats.chatCount != null) parts.push(`${stats.chatCount} 个聊天室`);
  if (stats.messageCount != null) parts.push(`${stats.messageCount.toLocaleString()} 条消息`);
  if (stats.userCount != null) parts.push(`${stats.userCount} 位用户`);
  el.statsBar.textContent = parts.join(' · ') + ` · 当前账号 ID ${state.myId ?? '未知'}`;

  // 加载聊天室列表
  state.chats = db.listChats(500);
  state.chatMap = new Map(state.chats.map((c) => [c.chatId, c]));
  renderChatList();

  if (state.chats.length > 0) {
    openChat(state.chats[0]);
  }
}

// ============ 聊天室列表 ============
function chatAvatar(type) {
  return type === 1 ? '👤' : type === 2 ? '👥' : '💬';
}

function chatDisplayName(chat) {
  if (chat.chatName) return chat.chatName;
  if (chat.directMemberName) return chat.directMemberName;
  return `聊天室 ${chat.chatId}`;
}

function renderChatList() {
  el.chatList.innerHTML = '';
  const frag = document.createDocumentFragment();
  for (const chat of state.chats) {
    const li = document.createElement('li');
    li.className = 'chat-item' + (state.activeChat && state.activeChat.chatId === chat.chatId ? ' active' : '');
    li.dataset.chatId = chat.chatId;

    const avatar = document.createElement('span');
    avatar.className = 'chat-avatar';
    avatar.textContent = chatAvatar(chat.type);

    const info = document.createElement('div');
    info.className = 'chat-info';
    const name = document.createElement('div');
    name.className = 'chat-name';
    name.textContent = chatDisplayName(chat);
    const meta = document.createElement('div');
    meta.className = 'chat-meta';
    const memberTxt = chat.memberCount != null ? `${chat.memberCount} 人` : '';
    const timeTxt = chat.lastUpdatedAt != null ? formatDateTime(chat.lastUpdatedAt) : '';
    meta.textContent = [memberTxt, timeTxt].filter(Boolean).join(' · ');
    info.append(name, meta);

    li.append(avatar, info);
    if (chat.unreadCount > 0) {
      const badge = document.createElement('span');
      badge.className = 'chat-badge';
      badge.textContent = chat.unreadCount > 99 ? '99+' : String(chat.unreadCount);
      li.appendChild(badge);
    }

    li.addEventListener('click', () => {
      state.searchMode = false;
      openChat(chat);
    });
    frag.appendChild(li);
  }
  el.chatList.appendChild(frag);
}

function setActiveChat(chat) {
  state.activeChat = chat;
  for (const li of el.chatList.children) {
    li.classList.toggle('active', Number(li.dataset.chatId) === chat.chatId);
  }
}

// ============ 消息加载与渲染 ============
async function openChat(chat) {
  setActiveChat(chat);
  state.messages = [];
  state.messageOffset = 0;
  state.hasMore = false;
  state.loadingMore = false;

  const isGroup = chat.type !== 1;
  const name = chatDisplayName(chat);
  el.chatTitle.textContent = name;
  el.chatMeta.textContent = [
    isGroup ? '群聊' : '私聊',
    chat.memberCount != null ? `${chat.memberCount} 人` : '',
    `ID: ${chat.chatId}`,
  ]
    .filter(Boolean)
    .join(' · ');
  el.exportBtn.hidden = false;

  el.msgList.innerHTML = '';
  el.msgEmpty.textContent = '加载中…';
  el.msgEmpty.hidden = false;
  el.loadMoreBtn.hidden = true;

  try {
    const { rows, hasMore } = state.db.getMessages(chat.chatId, { offset: 0, limit: 50 });
    state.messages = rows;
    state.messageOffset = rows.length;
    state.hasMore = hasMore;
    renderMessages({ scrollBottom: true });
    el.loadMoreBtn.hidden = !hasMore;
  } catch (e) {
    el.msgEmpty.textContent = '加载消息失败：' + e.message;
  }
}

async function loadMore() {
  if (state.loadingMore || !state.hasMore || !state.activeChat) return;
  state.loadingMore = true;
  el.loadMoreBtn.textContent = '加载中…';
  try {
    const { rows, hasMore } = state.db.getMessages(state.activeChat.chatId, {
      offset: state.messageOffset,
      limit: 50,
    });
    // rows 为更旧的消息（倒序），追加到数组尾部
    state.messages = state.messages.concat(rows);
    state.messageOffset += rows.length;
    state.hasMore = hasMore;
    renderMessages({ keepScroll: true });
    el.loadMoreBtn.hidden = !hasMore;
  } catch (e) {
    showError('加载更多失败：' + e.message);
  } finally {
    state.loadingMore = false;
    el.loadMoreBtn.textContent = '加载更早的消息 ↑';
  }
}

/**
 * 渲染消息列表
 * @param {{scrollBottom?: boolean, keepScroll?: boolean}} opts
 */
function renderMessages({ scrollBottom = false, keepScroll = false } = {}) {
  const prevScrollHeight = el.msgList.scrollHeight;
  const prevScrollTop = el.msgList.scrollTop;

  el.msgList.innerHTML = '';
  if (state.messages.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'msg-empty';
    empty.textContent = '该聊天室暂无消息';
    el.msgList.appendChild(empty);
    return;
  }

  const chat = state.activeChat;
  const isGroup = chat.type !== 1;
  const frag = document.createDocumentFragment();
  let prevDay = null;

  // messages 为时间倒序，渲染时反向遍历得到时间正序
  for (let i = state.messages.length - 1; i >= 0; i--) {
    const m = state.messages[i];

    // 日期分隔
    const day = formatDay(m.sentAt);
    if (day && day !== prevDay) {
      const sep = document.createElement('div');
      sep.className = 'msg-day-sep';
      sep.textContent = day;
      frag.appendChild(sep);
      prevDay = day;
    }

    const row = document.createElement('div');
    const parsed = parseMessage(m.message, m.type);
    const mine = state.myId !== null && m.authorId === state.myId;

    if (m.type === 0) {
      row.className = 'msg-row system';
      const bubble = document.createElement('div');
      bubble.className = 'msg-bubble';
      bubble.textContent = renderMessageText(parsed, m.type) || '系统消息';
      row.appendChild(bubble);
    } else {
      row.className = 'msg-row ' + (mine ? 'mine' : 'other');

      // 群聊中显示发送者昵称
      if (!mine && isGroup) {
        const sender = document.createElement('div');
        sender.className = 'msg-sender';
        sender.textContent = m.senderName || (m.authorId != null ? String(m.authorId) : '未知');
        row.appendChild(sender);
      }

      const bubble = document.createElement('div');
      bubble.className = 'msg-bubble';
      bubble.textContent = renderMessageText(parsed, m.type);

      // 结构化 JSON / 二进制摘要
      if (parsed.kind === 'json' && parsed.detail && !parsed.text) {
        const detail = document.createElement('div');
        detail.className = 'msg-detail';
        detail.textContent = parsed.detail;
        bubble.appendChild(detail);
      } else if (parsed.kind === 'nontext' && parsed.detail) {
        const detail = document.createElement('div');
        detail.className = 'msg-detail';
        detail.textContent = parsed.detail;
        bubble.appendChild(detail);
      }
      row.appendChild(bubble);

      const time = document.createElement('div');
      time.className = 'msg-time';
      time.textContent = formatDateTime(m.sentAt);
      row.appendChild(time);
    }
    frag.appendChild(row);
  }
  el.msgList.appendChild(frag);

  if (scrollBottom) {
    el.msgList.scrollTop = el.msgList.scrollHeight;
  } else if (keepScroll) {
    el.msgList.scrollTop = el.msgList.scrollHeight - prevScrollHeight + prevScrollTop;
  }
}

// ============ 搜索 ============
async function doSearch() {
  const keyword = el.chatSearch.value.trim();
  if (!keyword) {
    // 空关键词：退出搜索模式，回到聊天室列表
    state.searchMode = false;
    el.chatSearch.value = '';
    renderChatList();
    if (state.activeChat) {
      setActiveChat(state.activeChat);
      openChat(state.activeChat);
    } else {
      el.chatTitle.textContent = '选择一个聊天室';
      el.chatMeta.textContent = '';
      el.msgList.innerHTML = '';
      el.exportBtn.hidden = true;
      el.loadMoreBtn.hidden = true;
    }
    return;
  }

  if (!state.db) return;
  state.searchMode = true;
  el.chatTitle.textContent = `搜索：“${keyword}”`;
  el.chatMeta.textContent = '搜索结果（点击「查看」跳转到对应聊天室）';
  el.exportBtn.hidden = true;
  el.loadMoreBtn.hidden = true;

  el.msgList.innerHTML = '';
  el.msgEmpty.textContent = '搜索中…';
  el.msgEmpty.hidden = false;

  try {
    const results = state.db.searchMessages(keyword, 100);
    if (results.length === 0) {
      el.msgEmpty.textContent = '未找到匹配的消息';
      return;
    }
    el.msgEmpty.hidden = true;
    const frag = document.createDocumentFragment();
    let prevDay = null;
    for (let i = results.length - 1; i >= 0; i--) {
      const m = results[i];
      const day = formatDay(m.sentAt);
      if (day && day !== prevDay) {
        const sep = document.createElement('div');
        sep.className = 'msg-day-sep';
        sep.textContent = day;
        frag.appendChild(sep);
        prevDay = day;
      }

      const row = document.createElement('div');
      row.className = 'msg-row other';
      const sender = document.createElement('div');
      sender.className = 'msg-sender';
      const roomName = state.chatMap.get(m.chatId)?.chatName || `聊天室 ${m.chatId}`;
      sender.textContent = `${m.senderName || m.authorId || '未知'} · ${roomName}`;
      row.appendChild(sender);

      const bubble = document.createElement('div');
      bubble.className = 'msg-bubble';
      const parsed = parseMessage(m.message, m.type);
      bubble.textContent = renderMessageText(parsed, m.type) || messageTypeInfo(m.type).label;
      row.appendChild(bubble);

      const time = document.createElement('div');
      time.className = 'msg-time';
      time.textContent = formatDateTime(m.sentAt);
      row.appendChild(time);

      const jump = document.createElement('button');
      jump.className = 'btn btn-plain';
      jump.style.cssText = 'align-self:flex-start;margin:4px 0 0 6px;font-size:12px;padding:4px 10px';
      jump.textContent = '在聊天室中查看 →';
      jump.addEventListener('click', () => {
        const chat = state.chatMap.get(m.chatId);
        if (chat) openChat(chat);
      });
      row.appendChild(jump);

      frag.appendChild(row);
    }
    el.msgList.appendChild(frag);
    el.msgList.scrollTop = el.msgList.scrollHeight;
  } catch (e) {
    el.msgEmpty.textContent = '搜索失败：' + e.message;
  }
}

// ============ 导出 ============
function exportChat() {
  if (!state.activeChat || state.messages.length === 0) return;
  const chat = {
    chatId: state.activeChat.chatId,
    chatName: chatDisplayName(state.activeChat),
    type: state.activeChat.type,
    memberCount: state.activeChat.memberCount,
  };
  // 导出为时间正序
  const ordered = state.messages.slice().reverse();
  const json = serializeExport(chat, ordered);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `kakao-chat-${chat.chatId}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ============ 事件绑定 ============
function bindEvents() {
  el.uuidInput.addEventListener('input', refreshOpenBtn);
  el.userIdInput.addEventListener('input', refreshOpenBtn);
  el.openBtn.addEventListener('click', openDatabase);
  el.loadMoreBtn.addEventListener('click', loadMore);
  el.exportBtn.addEventListener('click', exportChat);
  el.searchBtn.addEventListener('click', doSearch);
  el.chatSearch.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doSearch();
  });
  el.chatSearch.addEventListener('input', () => {
    // 清空输入即退出搜索
    if (el.chatSearch.value.trim() === '' && state.searchMode) doSearch();
  });

  setupPlistDrop();
  setupBruteForce();
  setupDbDrop();
}

bindEvents();
refreshOpenBtn();
