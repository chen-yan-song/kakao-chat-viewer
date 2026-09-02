/**
 * KakaoTalk 数据库解密与查询封装
 *
 * 基于 @7mind.io/sqlcipher-wasm（SQLCipher v4.9.0 的 WebAssembly 构建），
 * 在浏览器内存中解密 KakaoTalk Mac 的 SQLCipher 加密数据库并查询聊天记录。
 * 所有操作仅发生在本地浏览器内存中，数据库内容不会离开本机。
 */
import initSqlcipher from '../vendor/sqlcipher.mjs';
import { SQLiteAPI } from '../vendor/sqlite-api.mjs';

const DB_PATH = '/kakao.db';

/** WASM 模块单例 */
let modulePromise = null;
let moduleInstance = null;

async function getModule() {
  if (moduleInstance) return moduleInstance;
  if (!modulePromise) {
    modulePromise = initSqlcipher().then((m) => {
      moduleInstance = m;
      return m;
    });
  }
  return modulePromise;
}

/**
 * 直接用底层 C API 执行查询，支持 BLOB 完整读取
 * （vendor/sqlite-api.mjs 的 query 用 column_text 读值，二进制会被截断）
 */
function queryRaw(module, dbPtr, sql, params = []) {
  const sqlPtr = module.allocateUTF8(sql);
  const stmtPtrPtr = module._malloc(4);
  try {
    const prep = module._sqlite3_prepare_v2(dbPtr, sqlPtr, -1, stmtPtrPtr, 0);
    if (prep !== 0) {
      const errMsg = module._sqlite3_errmsg(dbPtr);
      throw new Error('SQL 预处理失败: ' + (errMsg ? module.UTF8ToString(errMsg) : '未知错误'));
    }
    const stmt = module.getValue(stmtPtrPtr, 'i32');

    try {
      // 绑定参数
      for (let i = 0; i < params.length; i++) {
        const p = params[i];
        const idx = i + 1;
        if (p === null || p === undefined) {
          module._sqlite3_bind_null(stmt, idx);
        } else if (typeof p === 'number') {
          if (Number.isInteger(p)) {
            // WASM_BIGINT 构建：int64 参数必须是 BigInt
            module._sqlite3_bind_int64(stmt, idx, BigInt(p));
          } else {
            module._sqlite3_bind_double(stmt, idx, p);
          }
        } else if (typeof p === 'bigint') {
          module._sqlite3_bind_int64(stmt, idx, p);
        } else if (typeof p === 'string') {
          const pPtr = module.allocateUTF8(p);
          // SQLITE_TRANSIENT = -1，让 SQLite 自行拷贝
          module._sqlite3_bind_text(stmt, idx, pPtr, -1, -1);
          module._free(pPtr);
        } else if (p instanceof Uint8Array) {
          const pPtr = module._malloc(p.length);
          module.HEAPU8.set(p, pPtr);
          module._sqlite3_bind_blob(stmt, idx, pPtr, p.length, -1);
          module._free(pPtr);
        } else {
          throw new Error('不支持的参数类型: ' + typeof p);
        }
      }

      const colCount = module._sqlite3_column_count(stmt);
      const columns = [];
      for (let i = 0; i < colCount; i++) {
        columns.push(module.UTF8ToString(module._sqlite3_column_name(stmt, i)));
      }

      const rows = [];
      while (true) {
        const step = module._sqlite3_step(stmt);
        if (step === 101 /* SQLITE_DONE */) break;
        if (step !== 100 /* SQLITE_ROW */) {
          const errMsg = module._sqlite3_errmsg(dbPtr);
          throw new Error('SQL 执行失败: ' + (errMsg ? module.UTF8ToString(errMsg) : '未知错误'));
        }
        const row = {};
        for (let i = 0; i < colCount; i++) {
          const type = module._sqlite3_column_type(stmt, i);
          if (type === 5 /* NULL */) {
            row[columns[i]] = null;
          } else if (type === 1 /* INTEGER */) {
            row[columns[i]] = module._sqlite3_column_int64(stmt, i);
          } else if (type === 2 /* FLOAT */) {
            row[columns[i]] = module._sqlite3_column_double(stmt, i);
          } else if (type === 4 /* BLOB */) {
            const bytes = module._sqlite3_column_bytes(stmt, i);
            const ptr = module._sqlite3_column_blob(stmt, i);
            // 该 WASM 构建未导出 HEAPU8，需经 getValue 读取内存
            // 用 i32 批量读（快 4 倍），剩余尾部逐字节读
            const buf = new Uint8Array(bytes);
            const words = bytes >>> 2;
            let j = 0;
            for (let w = 0; w < words; w++) {
              const v = module.getValue(ptr + (w << 2), 'i32') >>> 0;
              buf[j++] = v & 0xff;
              buf[j++] = (v >>> 8) & 0xff;
              buf[j++] = (v >>> 16) & 0xff;
              buf[j++] = (v >>> 24) & 0xff;
            }
            for (; j < bytes; j++) {
              buf[j] = module.getValue(ptr + j, 'i8') & 0xff;
            }
            row[columns[i]] = buf;
          } else {
            const ptr = module._sqlite3_column_text(stmt, i);
            row[columns[i]] = ptr ? module.UTF8ToString(ptr) : '';
          }
        }
        rows.push(row);
      }
      return { columns, rows };
    } finally {
      module._sqlite3_finalize(stmt);
    }
  } finally {
    module._free(stmtPtrPtr);
    module._free(sqlPtr);
  }
}

export class KakaoDB {
  constructor() {
    this.module = null;
    this.api = null;
    this.db = null;
    this.myId = null;
  }

  /**
   * 打开并解密数据库
   * @param {Object} opts
   * @param {Uint8Array} opts.data 数据库文件原始字节
   * @param {Uint8Array[]} [opts.sideDatas] 可选的 -wal/-shm 伴随文件字节
   * @param {string} [opts.sideSuffixes] 与 sideDatas 对应的后缀名（如 '-wal'）
   * @param {string} opts.key SQLCipher 密钥（hex 字符串）
   * @param {Function} [opts.onProgress] 进度回调 (stage, detail)
   */
  async open({ data, sideDatas = [], sideSuffixes = [], key, onProgress }) {
    const report = (stage, detail) => onProgress && onProgress(stage, detail);

    report('wasm', '加载 SQLCipher WebAssembly 模块…');
    this.module = await getModule();
    this.api = new SQLiteAPI(this.module);

    // 将数据库文件写入 Emscripten 内存文件系统（MEMFS）
    report('write', `写入数据库文件（${(data.byteLength / 1024 / 1024).toFixed(1)} MB）…`);
    this.module.FS.writeFile(DB_PATH, data);
    for (let i = 0; i < sideDatas.length; i++) {
      const bytes = sideDatas[i];
      if (bytes && bytes.byteLength > 0) {
        this.module.FS.writeFile(DB_PATH + (sideSuffixes[i] || ''), bytes);
      }
    }

    // 依次尝试不同的兼容模式 / 页面大小组合（对齐 kakaocli 的做法）
    report('decrypt', '解密数据库…');
    const attempts = [
      { compat: 3, pageSize: null },
      { compat: 3, pageSize: 1024 },
      { compat: 3, pageSize: 4096 },
      { compat: 4, pageSize: null },
      { compat: 4, pageSize: 4096 },
      { compat: 4, pageSize: 1024 },
    ];

    let lastError = null;
    for (const attempt of attempts) {
      try {
        const db = this.api.open(DB_PATH);
        db.exec(`PRAGMA cipher_default_compatibility = ${attempt.compat}`);
        if (attempt.pageSize) {
          db.exec(`PRAGMA cipher_page_size = ${attempt.pageSize}`);
        }
        db.setKey(key);
        // 触发真实读取以校验密钥
        const probe = queryRaw(this.module, db.dbPtr, 'SELECT count(*) AS c FROM sqlite_master');
        if (probe.rows.length > 0 && Number(probe.rows[0].c) > 0) {
          this.db = db;
          report('done', '数据库解密成功');
          return { compat: attempt.compat, pageSize: attempt.pageSize };
        }
        db.close();
      } catch (e) {
        lastError = e;
        if (this.db) { try { this.db.close(); } catch { /* 忽略 */ } this.db = null; }
      }
    }
    throw new Error('数据库解密失败：密钥错误或文件不完整。' + (lastError ? `（${lastError.message}）` : ''));
  }

  /** 执行任意查询（只读用途） */
  raw(sql, params = []) {
    this._ensureOpen();
    return queryRaw(this.module, this.db.dbPtr, sql, params);
  }

  /**
   * Windows 模式：把多份已解密的 EDB（明文 SQLite 字节）汇总为统一结构库后打开
   *
   * 思路：wasm 内存文件系统写入每份明文库 → ATTACH ... KEY '' 挂接明文库 →
   * 按启发式列映射导入 NTUser/NTChatRoom/NTChatMessage 统一表 →
   * 导出统一库字节后复用现有 open() 流程，上层 UI 零改动。
   *
   * @param {Array<{name:string, chatId:?string, data:Uint8Array}>} edbs
   * @param {string} key SQLCipher 密钥（hex 字符串）
   * @param {?number} myId 当前登录用户 ID（可选，写入 NTChatContext）
   * @param {Function} [onProgress] (stage, detail)
   */
  async openUnifiedWindows(edbs, key, myId = null, onProgress) {
    const report = (stage, detail) => onProgress && onProgress(stage, detail);
    const qid = (s) => '"' + String(s).replace(/"/g, '""') + '"';
    const qlit = (v) => (v == null ? 'NULL' : "'" + String(v).replace(/'/g, "''") + "'");

    report('wasm', '加载 SQLCipher WebAssembly 模块…');
    this.module = await getModule();
    this.api = new SQLiteAPI(this.module);
    const FS = this.module.FS;

    // 写入明文库到 wasm 内存文件系统
    report('write', `写入 ${edbs.length} 份明文库…`);
    const plains = [];
    edbs.forEach((edb, i) => {
      if (!edb.data || edb.data.byteLength === 0) return;
      const p = `/edb-plain-${i}.db`;
      FS.writeFile(p, edb.data);
      plains.push({ path: p, edb });
    });

    // 构建统一结构库（列名对齐 mac 端动态列探测候选）
    report('build', '构建统一查询库…');
    const U = '/unified.db';
    try { FS.unlink(U); } catch { /* 不存在则忽略 */ }
    const udb = this.api.open(U);
    udb.setKey(key);
    udb.exec(`
      CREATE TABLE NTUser (userId INTEGER PRIMARY KEY, displayName TEXT, nickName TEXT, friendNickName TEXT, accountId TEXT, linkId INTEGER DEFAULT 0);
      CREATE TABLE NTChatRoom (chatId INTEGER PRIMARY KEY, type INTEGER DEFAULT 2, chatName TEXT, activeMembersCount INTEGER, lastLogId INTEGER, lastUpdatedAt INTEGER, countOfNewMessage INTEGER DEFAULT 0, directChatMemberUserId INTEGER);
      CREATE TABLE NTChatMessage (logId INTEGER PRIMARY KEY AUTOINCREMENT, chatId INTEGER, authorId INTEGER, message TEXT, attachment TEXT, type INTEGER, sentAt INTEGER);
      CREATE TABLE NTChatContext (userId INTEGER);
    `);

    let msgCount = 0;
    let userCount = 0;
    for (const { path: p, edb } of plains) {
      report('ingest', `导入 ${edb.name}…`);
      udb.exec(`ATTACH DATABASE '${p}' AS src KEY '';`);
      try {
        const srcTables = udb
          .query("SELECT name FROM src.sqlite_master WHERE type='table'")
          .map((r) => r.name);

        // ---- 消息表（chatLogs_{chatId}.edb 的主体）----
        const logTable = srcTables.find((t) => /chatlog/i.test(t));
        if (logTable) {
          const cols = udb.query(`PRAGMA src.table_info(${qid(logTable)})`).map((r) => r.name);
          const pick = (cands) => {
            const hit = cands.find((c) => cols.some((x) => x.toLowerCase() === c.toLowerCase()));
            return hit ? 's.' + qid(hit) : 'NULL';
          };
          const chatId = edb.chatId ? Number(edb.chatId) : null;
          udb.exec(`
            INSERT INTO NTChatMessage (chatId, authorId, message, type, sentAt)
            SELECT ${chatId == null ? 'NULL' : Number(chatId)},
                   ${pick(['authorId', 'from', 'senderId', 'userId'])},
                   ${pick(['message', 'msg', 'content', 'text'])},
                   ${pick(['type', 'msgType', 'messageType'])},
                   ${pick(['sendAt', 'time', 'timestamp', 'createdAt', 'date'])}
            FROM src.${qid(logTable)} s
          `);
          const stat = udb.query(`SELECT count(*) AS c FROM src.${qid(logTable)}`)[0];
          msgCount += Number(stat.c);
          if (chatId != null) {
            const agg = udb.query(`
              SELECT max(${pick(['_id', 'id', 'msgId', 'logId']).replace(/^s\./, 's.')}) AS lastLogId,
                     max(${pick(['sendAt', 'time', 'timestamp', 'createdAt', 'date'])}) AS lastAt,
                     count(DISTINCT ${pick(['authorId', 'from', 'senderId', 'userId'])}) AS members
              FROM src.${qid(logTable)} s
            `)[0] || {};
            udb.exec(`
              INSERT INTO NTChatRoom (chatId, type, chatName, activeMembersCount, lastLogId, lastUpdatedAt)
              VALUES (${Number(chatId)}, 0, ${qlit('聊天室 ' + chatId)},
                      ${agg.members == null ? 'NULL' : Number(agg.members)},
                      ${agg.lastLogId == null ? 'NULL' : Number(agg.lastLogId)},
                      ${agg.lastAt == null ? 'NULL' : Number(agg.lastAt)})
              ON CONFLICT(chatId) DO UPDATE SET
                lastLogId = COALESCE(excluded.lastLogId, lastLogId),
                lastUpdatedAt = COALESCE(excluded.lastUpdatedAt, lastUpdatedAt),
                activeMembersCount = COALESCE(excluded.activeMembersCount, activeMembersCount)
            `);
          }
        }

        // ---- 用户表（TalkUserDB.edb 的 talkUser）----
        const userTable = srcTables.find((t) => /talkuser|^user/i.test(t) && !/chatlog/i.test(t));
        if (userTable) {
          const cols = udb.query(`PRAGMA src.table_info(${qid(userTable)})`).map((r) => r.name);
          const pick = (cands) => {
            const hit = cands.find((c) => cols.some((x) => x.toLowerCase() === c.toLowerCase()));
            return hit ? 's.' + qid(hit) : 'NULL';
          };
          const uidCol = ['userId', 'user_id', 'userid', 'id'].find((c) =>
            cols.some((x) => x.toLowerCase() === c.toLowerCase())
          );
          if (uidCol) {
            udb.exec(`
              INSERT OR IGNORE INTO NTUser (userId, displayName, nickName, friendNickName)
              SELECT DISTINCT s.${qid(uidCol)},
                     ${pick(['nickName', 'nickname', 'displayName', 'name'])},
                     ${pick(['nickName', 'nickname'])},
                     ${pick(['friendNickName', 'friendNickname'])}
              FROM src.${qid(userTable)} s
              WHERE s.${qid(uidCol)} IS NOT NULL
            `);
          }
        }

        // ---- 房间列表（chatListInfo.edb / TalkUserDB 内的 chatList）----
        const listTable = srcTables.find((t) => /chatlist|chat_list/i.test(t));
        if (listTable) {
          const cols = udb.query(`PRAGMA src.table_info(${qid(listTable)})`).map((r) => r.name);
          const pick = (cands) => {
            const hit = cands.find((c) => cols.some((x) => x.toLowerCase() === c.toLowerCase()));
            return hit ? 's.' + qid(hit) : 'NULL';
          };
          const idCol = ['chatId', 'id', 'roomId'].find((c) =>
            cols.some((x) => x.toLowerCase() === c.toLowerCase())
          );
          if (idCol) {
            udb.exec(`
              INSERT INTO NTChatRoom (chatId, type, chatName)
              SELECT s.${qid(idCol)}, 2, ${pick(['name', 'title', 'roomName'])}
              FROM src.${qid(listTable)} s
              WHERE s.${qid(idCol)} IS NOT NULL
              ON CONFLICT(chatId) DO UPDATE SET
                chatName = COALESCE(excluded.chatName, chatName),
                type = COALESCE(excluded.type, type)
            `);
          }
        }
      } finally {
        udb.exec('DETACH DATABASE src;');
      }
    }

    userCount = Number(
      (udb.query('SELECT count(*) AS c FROM NTUser')[0] || { c: 0 }).c
    );
    if (myId != null) {
      udb.exec(`INSERT INTO NTChatContext (userId) VALUES (${Number(myId)})`);
    }
    udb.close();

    const unified = FS.readFile(U);
    for (const { path: p } of plains) { try { FS.unlink(p); } catch { /* 忽略 */ } }
    try { FS.unlink(U); } catch { /* 忽略 */ }

    report('done', `统一库构建完成：${msgCount} 条消息 / ${userCount} 位联系人`);
    return await this.open({ data: unified, key, onProgress });
  }

  /** 获取所有表名 */
  tableNames() {
    const res = this.raw("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
    return res.rows.map((r) => r.name);
  }

  /** 获取表的列名集合 */
  tableColumns(table) {
    const res = this.raw(`PRAGMA table_info(${table.replace(/[^a-zA-Z0-9_]/g, '')})`);
    return new Set(res.rows.map((r) => r.name));
  }

  /** 当前登录用户 ID */
  myUserId() {
    if (this.myId !== null) return this.myId;
    try {
      const res = this.raw('SELECT userId FROM NTChatContext LIMIT 1');
      this.myId = res.rows.length ? Number(res.rows[0].userId) : null;
    } catch {
      this.myId = null;
    }
    return this.myId;
  }

  /**
   * 聊天室列表（按最后活动时间倒序）
   * 动态适配不同版本的表结构
   */
  listChats(limit = 100) {
    this._ensureOpen();
    const cols = this.tableColumns('NTChatRoom');
    const has = (name) => cols.has(name);

    // 按候选列名动态组装 SELECT 字段
    const pick = (names) => {
      for (const n of names) if (cols.has(n)) return 'r.' + n;
      return 'NULL';
    };
    const fields = {
      chatId: pick(['chatId', 'id']),
      type: pick(['type']),
      chatName: pick(['chatName', 'title', 'name']),
      activeMembersCount: pick(['activeMembersCount', 'membersCount', 'memberCount', 'membershipCount']),
      lastLogId: pick(['lastLogId', 'lastMessageId', 'lastMsgId']),
      lastUpdatedAt: pick(['lastUpdatedAt', 'lastMessageAt', 'updatedAt']),
      countOfNewMessage: pick(['countOfNewMessage', 'unreadCount', 'newMessageCount']),
      directChatMemberUserId: pick(['directChatMemberUserId', 'directMemberUserId']),
    };

    const userCols = this.tableColumns('NTUser');
    const uName = (() => {
      const names = ['displayName', 'friendNickName', 'nickName'];
      const parts = [];
      for (const n of names) {
        if (userCols.has(n)) parts.push(`u.${n}`);
      }
      return parts.length ? 'COALESCE(' + parts.join(', ') + ')' : 'NULL';
    })();

    const sql = `
      SELECT ${fields.chatId} AS chatId,
             ${fields.type} AS type,
             ${fields.chatName} AS chatName,
             ${fields.activeMembersCount} AS memberCount,
             ${fields.lastLogId} AS lastLogId,
             ${fields.lastUpdatedAt} AS lastUpdatedAt,
             ${fields.countOfNewMessage} AS unreadCount,
             ${fields.directChatMemberUserId} AS directChatMemberUserId,
             ${uName} AS directMemberName
      FROM NTChatRoom r
      LEFT JOIN NTUser u ON ${fields.directChatMemberUserId} = u.userId AND u.linkId = 0
      ORDER BY ${fields.lastUpdatedAt} DESC
      LIMIT ?
    `;
    const res = this.raw(sql, [limit]);
    return res.rows.map((r) => ({
      chatId: Number(r.chatId),
      type: Number(r.type || 0),
      chatName: r.chatName || null,
      memberCount: r.memberCount == null ? null : Number(r.memberCount),
      lastLogId: r.lastLogId == null ? null : Number(r.lastLogId),
      lastUpdatedAt: r.lastUpdatedAt == null ? null : Number(r.lastUpdatedAt),
      unreadCount: r.unreadCount == null ? 0 : Number(r.unreadCount),
      directMemberName: r.directMemberName || null,
    }));
  }

  /**
   * 获取指定聊天室的消息（倒序，支持分页）
   * @returns {{rows: Array, hasMore: boolean}}
   */
  getMessages(chatId, { offset = 0, limit = 50 } = {}) {
    this._ensureOpen();
    const cols = this.tableColumns('NTChatMessage');
    const pick = (names) => {
      for (const n of names) if (cols.has(n)) return 'm.' + n;
      return 'NULL';
    };
    const fields = {
      logId: pick(['logId', 'id', 'msgId']),
      chatId: pick(['chatId', 'chatRoomId']),
      authorId: pick(['authorId', 'userId', 'senderId']),
      message: pick(['message', 'content', 'msg']),
      type: pick(['type', 'msgType', 'messageType']),
      sentAt: pick(['sentAt', 'timestamp', 'createdAt', 'createdTime']),
    };

    const userCols = this.tableColumns('NTUser');
    const uName = (() => {
      const names = ['displayName', 'friendNickName', 'nickName'];
      const parts = [];
      for (const n of names) {
        if (userCols.has(n)) parts.push(`u.${n}`);
      }
      return parts.length ? 'COALESCE(' + parts.join(', ') + ')' : 'NULL';
    })();

    const sql = `
      SELECT ${fields.logId} AS logId,
             ${fields.chatId} AS chatId,
             ${fields.authorId} AS authorId,
             ${uName} AS senderName,
             u.accountId AS senderAccountId,
             m.message AS message,
             m.attachment AS attachment,
             ${fields.type} AS type,
             ${fields.sentAt} AS sentAt
      FROM NTChatMessage m
      LEFT JOIN NTUser u ON ${fields.authorId} = u.userId AND u.linkId = 0
      WHERE ${fields.chatId} = ?
      ORDER BY ${fields.sentAt} DESC, ${fields.logId} DESC
      LIMIT ? OFFSET ?
    `;
    const res = this.raw(sql, [chatId, limit + 1, offset]);
    const hasMore = res.rows.length > limit;
    const rows = res.rows.slice(0, limit).map((r) => ({
      logId: r.logId == null ? null : Number(r.logId),
      chatId: Number(r.chatId),
      authorId: r.authorId == null ? null : Number(r.authorId),
      senderName: r.senderName || null,
      senderAccountId: r.senderAccountId == null ? null : Number(r.senderAccountId),
      message: r.message, // string 或 Uint8Array
      attachment: r.attachment || null, // 贴纸/附件等非文本类型的 JSON 描述
      type: r.type == null ? 0 : Number(r.type),
      sentAt: r.sentAt == null ? null : Number(r.sentAt),
    }));
    return { rows, hasMore };
  }

  /** 全文搜索消息 */
  searchMessages(keyword, limit = 100) {
    this._ensureOpen();
    const cols = this.tableColumns('NTChatMessage');
    const pick = (names) => {
      for (const n of names) if (cols.has(n)) return 'm.' + n;
      return 'NULL';
    };
    const fields = {
      logId: pick(['logId', 'id', 'msgId']),
      chatId: pick(['chatId', 'chatRoomId']),
      authorId: pick(['authorId', 'userId', 'senderId']),
      message: pick(['message', 'content', 'msg']),
      type: pick(['type', 'msgType', 'messageType']),
      sentAt: pick(['sentAt', 'timestamp', 'createdAt', 'createdTime']),
    };

    const userCols = this.tableColumns('NTUser');
    const uName = (() => {
      const names = ['displayName', 'friendNickName', 'nickName'];
      const parts = [];
      for (const n of names) {
        if (userCols.has(n)) parts.push(`u.${n}`);
      }
      return parts.length ? 'COALESCE(' + parts.join(', ') + ')' : 'NULL';
    })();

    // 兼容新版本 message 为 JSON 文本、旧版本为二进制的情况
    const searchExpr = cols.has('message') && cols.has('text')
      ? `(m.message LIKE ? OR m.text LIKE ?)`
      : `m.message LIKE ?`;

    const sql = `
      SELECT ${fields.logId} AS logId,
             ${fields.chatId} AS chatId,
             ${fields.authorId} AS authorId,
             ${uName} AS senderName,
             u.accountId AS senderAccountId,
             m.message AS message,
             m.attachment AS attachment,
             ${fields.type} AS type,
             ${fields.sentAt} AS sentAt
      FROM NTChatMessage m
      LEFT JOIN NTUser u ON ${fields.authorId} = u.userId AND u.linkId = 0
      WHERE ${searchExpr}
      ORDER BY ${fields.sentAt} DESC
      LIMIT ?
    `;
    const like = `%${keyword}%`;
    const params = cols.has('text') ? [like, like, limit] : [like, limit];
    const res = this.raw(sql, params);
    return res.rows.map((r) => ({
      logId: r.logId == null ? null : Number(r.logId),
      chatId: Number(r.chatId),
      authorId: r.authorId == null ? null : Number(r.authorId),
      senderName: r.senderName || null,
      senderAccountId: r.senderAccountId == null ? null : Number(r.senderAccountId),
      message: r.message,
      attachment: r.attachment || null, // 贴纸/附件等非文本类型的 JSON 描述
      type: r.type == null ? 0 : Number(r.type),
      sentAt: r.sentAt == null ? null : Number(r.sentAt),
    }));
  }

  /** 聊天室名称（用于搜索结果里显示房间名） */
  chatNameOf(chatId) {
    const cols = this.tableColumns('NTChatRoom');
    const pick = (names) => {
      for (const n of names) if (cols.has(n)) return n;
      return null;
    };
    const nameCol = pick(['chatName', 'title', 'name']);
    const idCol = pick(['chatId', 'id']);
    if (!nameCol || !idCol) return null;
    const res = this.raw(`SELECT ${nameCol} AS n FROM NTChatRoom WHERE ${idCol} = ? LIMIT 1`, [chatId]);
    return res.rows.length ? res.rows[0].n : null;
  }

  /** 数据库统计信息 */
  stats() {
    const out = {};
    try {
      out.chatCount = Number(this.raw('SELECT count(*) AS c FROM NTChatRoom').rows[0].c);
    } catch { out.chatCount = null; }
    try {
      out.messageCount = Number(this.raw('SELECT count(*) AS c FROM NTChatMessage').rows[0].c);
    } catch { out.messageCount = null; }
    try {
      out.userCount = Number(this.raw('SELECT count(*) AS c FROM NTUser').rows[0].c);
    } catch { out.userCount = null; }
    return out;
  }

  /**
   * 诊断扫描：列出所有表及行数（用于排查「解密成功但查不到数据」）
   * @returns {{pageSize: number|null, pageCount: number|null, tables: Array<{name:string, count:number|null}>}}
   */
  diagnose() {
    this._ensureOpen();
    const out = { pageSize: null, pageCount: null, tables: [] };
    try {
      const pr = this.raw('PRAGMA page_size');
      // SQLCipher 构建中该 PRAGMA 返回列名为 cipher_page_size，需兼容两种列名
      const r = pr.rows.length ? pr.rows[0] : {};
      out.pageSize = Number(r.page_size ?? r.cipher_page_size) || null;
    } catch { /* 忽略 */ }
    try {
      const pc = this.raw('PRAGMA page_count');
      out.pageCount = pc.rows.length ? Number(pc.rows[0].page_count) : null;
    } catch { /* 忽略 */ }
    const res = this.raw("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
    for (const { name } of res.rows) {
      let count = null;
      try {
        const q = `SELECT count(*) AS c FROM "${String(name).replace(/"/g, '""')}"`;
        count = Number(this.raw(q).rows[0].c);
      } catch { count = null; }
      out.tables.push({ name, count });
    }
    out.tables.sort((a, b) => (b.count ?? -1) - (a.count ?? -1));
    return out;
  }

  /**
   * 通用数据表查询：任意表的全部数据（分页 + 可选关键字过滤）
   * @param {string} tableName 表名（必须在当前数据库中存在）
   * @param {{offset?: number, limit?: number, keyword?: string}} opts
   * @returns {{columns: string[], rows: Array<Object>, total: number}}
   */
  queryTable(tableName, { offset = 0, limit = 100, keyword = '' } = {}) {
    this._ensureOpen();
    // 表名白名单校验（防拼接注入）
    if (!this.tableNames().includes(tableName)) {
      throw new Error('表不存在: ' + tableName);
    }
    const safeTable = `"${tableName.replace(/"/g, '""')}"`;

    const cols = [...this.tableColumns(tableName)];
    let where = '';
    let likeParams = [];
    if (keyword) {
      // 对所有列做 CAST AS TEXT LIKE（兼容数字列与文本列）
      const kw = `%${keyword}%`;
      const exprs = cols.map((c) => `CAST("${c.replace(/"/g, '""')}" AS TEXT) LIKE ?`);
      if (exprs.length) {
        where = 'WHERE ' + exprs.join(' OR ');
        likeParams = cols.map(() => kw);
      }
    }

    const total = Number(
      this.raw(`SELECT COUNT(*) AS c FROM ${safeTable} ${where}`, likeParams).rows[0].c
    );
    const res = this.raw(
      `SELECT * FROM ${safeTable} ${where} ORDER BY rowid LIMIT ? OFFSET ?`.trim(),
      [...likeParams, limit, offset]
    );
    return { columns: res.columns, rows: res.rows, total };
  }

  _ensureOpen() {
    if (!this.db) throw new Error('数据库尚未打开');
  }

  close() {
    if (this.db) {
      try { this.db.close(); } catch { /* 忽略 */ }
      this.db = null;
    }
    try { this.module.FS.unlink(DB_PATH); } catch { /* 忽略 */ }
  }
}

/** 从伴随文件名提取后缀（-wal / -shm） */
function suffixOf(name) {
  if (name.endsWith('-wal')) return '-wal';
  if (name.endsWith('-shm')) return '-shm';
  if (name.endsWith('-journal')) return '-journal';
  return '';
}

export { suffixOf };
