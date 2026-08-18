/**
 * KakaoTalk 消息内容解析
 *
 * 新版 KakaoTalk Mac（NT 架构）的 NTChatMessage.message 字段是 JSON 文本，
 * 旧版本为 protobuf 二进制。这里做多格式兼容解析：
 * 1. JSON → 提取文本字段
 * 2. 二进制 → 提取其中可读的 UTF-8 文本片段（尽力而为）
 */

/** 消息类型映射（与 kakaocli Message.swift 一致，另补充 NT 架构新类型） */
export const MESSAGE_TYPES = {
  0: { label: '系统', emoji: '⚙' },
  1: { label: '文本', emoji: '💬' },
  2: { label: '图片', emoji: '🖼' },
  3: { label: '视频', emoji: '🎬' },
  4: { label: '语音', emoji: '🎤' },
  5: { label: '表情', emoji: '😀' },
  6: { label: '文件', emoji: '📎' },
  7: { label: '位置', emoji: '📍' },
  20: { label: '表情贴纸', emoji: '🎴' },   // 动态贴纸，内容在 attachment JSON
  1999: { label: '系统记录', emoji: '⚙' }, // 无内容系统占位消息（如已读边界）
};

export function messageTypeInfo(type) {
  return MESSAGE_TYPES[type] || { label: `类型${type}`, emoji: '📄' };
}

/** 判断字节数组是否为合法 UTF-8 文本 */
function looksLikeUtf8(bytes) {
  if (!bytes || bytes.length === 0) return false;
  // 快速排除：二进制通常包含大量 0x00 或控制字符
  let printable = 0;
  const sample = bytes.subarray(0, Math.min(bytes.length, 256));
  if (sample.length === 0) return false;
  for (let i = 0; i < sample.length; i++) {
    const b = sample[i];
    if (b === 0) return false;
    if (b >= 0x20 && b !== 0x7f) printable++;
  }
  return printable / sample.length > 0.6;
}

/** 将任意字节序列解码为文本（非法序列用替换符） */
export function decodeUtf8(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } catch {
    return '';
  }
}

/**
 * 从二进制 protobuf 中提取可读文本片段
 * 提取连续 >= 2 字符的 UTF-8 序列
 */
export function extractTextFromBinary(bytes) {
  if (!bytes || bytes.length === 0) return '';
  const decoder = new TextDecoder('utf-8', { fatal: false });
  const chunks = [];
  let start = -1;
  let run = [];

  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    // 韩文/中文/日文等多字节字符会落在 0x80-0xFF，无法单字节判断，
    // 这里按"可打印 ASCII 或高位字节"收集片段，再统一解码过滤
    if ((b >= 0x20 && b < 0x7f) || b >= 0x80) {
      if (start === -1) start = i;
      run.push(b);
      if (run.length > 4096) {
        chunks.push(decoder.decode(Uint8Array.from(run)));
        run = [];
        start = -1;
      }
    } else {
      if (run.length > 0) {
        chunks.push(decoder.decode(Uint8Array.from(run)));
        run = [];
        start = -1;
      }
    }
  }
  if (run.length > 0) chunks.push(decoder.decode(Uint8Array.from(run)));

  return chunks
    .map((c) => c.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').trim())
    .filter((c) => {
      // 过滤无意义的控制符残留，保留至少 2 个字符且包含一定可见内容的片段
      if (c.length < 2) return false;
      let letters = 0;
      for (const ch of c) {
        if (ch.charCodeAt(0) > 0x1f) letters++;
      }
      return letters >= 2;
    })
    .join(' ⏎ ');
}

/** JSON 消息中常见的文本字段（按优先级） */
const JSON_TEXT_FIELDS = ['text', 'message', 'content', 'msg', 'body'];

/**
 * 解析消息原始内容，返回展示信息
 * @param {string|Uint8Array|null} raw NTChatMessage.message 原始值
 * @param {number} type 消息类型
 * @param {string|null} attachment NTChatMessage.attachment（贴纸/附件等 JSON 描述）
 * @returns {{text: string, kind: 'text'|'json'|'binary'|'empty'|'nontext'|'attachment', detail: string|null}}
 */
export function parseMessage(raw, type, attachment = null) {
  // message 为空但有 attachment（贴纸/图片等）：从 attachment JSON 提取描述
  const hasAttachment = typeof attachment === 'string' && attachment.trim().length > 0;
  if (raw === null || raw === undefined || raw === '') {
    if (hasAttachment) {
      const att = tryParseAttachment(attachment, type);
      if (att !== null) return att;
    }
    return { text: '', kind: 'empty', detail: null };
  }

  // BLOB → 尝试 UTF-8 解码
  if (raw instanceof Uint8Array) {
    if (raw.length === 0) {
      return { text: '', kind: 'empty', detail: null };
    }
    const text = decodeUtf8(raw);
    const jsonText = looksLikeUtf8(raw) ? tryParseJsonText(text) : null;
    if (jsonText !== null) {
      return jsonText;
    }
    // 二进制：非文本类型直接归类，文本类型尽力提取
    if (type !== 1) {
      return { text: '', kind: 'nontext', detail: `二进制内容（${raw.length} 字节）` };
    }
    const extracted = extractTextFromBinary(raw);
    return {
      text: extracted,
      kind: extracted ? 'binary' : 'nontext',
      detail: extracted ? null : `二进制内容（${raw.length} 字节）`,
    };
  }

  // 字符串 → 尝试 JSON
  const s = String(raw);
  const parsed = tryParseJsonText(s);
  if (parsed !== null) return parsed;
  return { text: s, kind: 'text', detail: null };
}

/**
 * 解析 attachment JSON（贴纸、图片、文件等非文本消息的描述）
 * 例如：{"path":"4449277.emot_002.webp","alt":"카카오 이모티콘","name":"(이모티콘)",
 *       "type":"animated-sticker/digital-item","width":"360","height":"360"}
 */
function tryParseAttachment(attachment, type) {
  try {
    const obj = JSON.parse(attachment);
    if (obj === null || typeof obj !== 'object') return null;
    // 优先取 alt（无障碍描述，如「카카오 이모티콘」）
    const alt = typeof obj.alt === 'string' && obj.alt.trim() ? obj.alt.trim() : null;
    const name = typeof obj.name === 'string' && obj.name.trim() ? obj.name.trim() : null;
    const path = typeof obj.path === 'string' && obj.path.trim() ? obj.path.trim() : null;
    const parts = [alt, name && name !== alt ? name : null].filter(Boolean);
    return {
      text: parts.length ? parts.join(' ') : (alt || name || path || ''),
      kind: 'attachment',
      detail: path || (parts.length ? null : JSON.stringify(obj)),
    };
  } catch {
    return null;
  }
}

/** 尝试把字符串当 JSON 解析并提取文本；失败返回 null */
function tryParseJsonText(s) {
  const t = s.trim();
  if (!t.startsWith('{')) return null;
  try {
    const obj = JSON.parse(t);
    if (obj === null || typeof obj !== 'object') return null;
    // 纯文本 JSON：直接取字段
    for (const field of JSON_TEXT_FIELDS) {
      if (typeof obj[field] === 'string' && obj[field].length > 0) {
        return { text: obj[field], kind: 'json', detail: null };
      }
    }
    // 没有文本字段：可能是富文本或系统消息，保留结构化信息
    return { text: '', kind: 'json', detail: JSON.stringify(obj) };
  } catch {
    return null;
  }
}

/** 将消息解析结果渲染为聊天框展示文本 */
export function renderMessageText(parsed, type) {
  const info = messageTypeInfo(type);
  if (parsed.text) {
    // 贴纸类：正文带描述时加类型前缀，一眼区分贴纸与普通文本
    if (type === 20 && parsed.kind === 'attachment') return `[${info.label}] ${parsed.text}`;
    return parsed.text;
  }
  if (type === 1) return parsed.kind === 'empty' ? '' : '[不可读内容]';
  return `[${info.label}]`;
}

/**
 * 导出聊天记录为 JSON 字符串
 */
export function serializeExport(chat, messages) {
  return JSON.stringify(
    {
      exportedAt: new Date().toISOString(),
      chat,
      messages: messages.map((m) => ({
        logId: m.logId,
        authorId: m.authorId,
        senderName: m.senderName,
        senderAccountId: m.senderAccountId ?? null,
        text: parseMessage(m.message, m.type, m.attachment).text,
        type: m.type,
        sentAt: m.sentAt,
        sentAtISO: m.sentAt ? new Date(m.sentAt * 1000).toISOString() : null,
      })),
    },
    null,
    2
  );
}
