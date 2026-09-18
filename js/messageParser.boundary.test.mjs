/**
 * 系统消息 / 消息解析边界测试
 *
 * 用法：node js/messageParser.boundary.test.mjs
 */
import assert from 'assert';
import {
  parseMessage,
  parseSystemFeed,
  renderMessageText,
  messageTypeInfo,
} from './messageParser.js';

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ✓ ${name}`);
  } catch (e) {
    failed += 1;
    console.error(`  ✗ ${name}`);
    console.error(`    ${e && e.message}`);
  }
}

console.log('系统消息 / 解析边界测试\n');

await test('系统 feed：邀请入群完整字段', () => {
  const raw = JSON.stringify({
    feedType: 1,
    inviter: { nickName: '甲' },
    members: [{ nickName: '乙' }, { nickName: '丙' }],
  });
  const text = parseSystemFeed(raw);
  assert.ok(text.includes('邀请入群'));
  assert.ok(text.includes('甲'));
  assert.ok(text.includes('乙、丙'));
});

await test('系统 feed：未知 feedType 数字', () => {
  const text = parseSystemFeed({ feedType: 999 });
  assert.strictEqual(text, '系统事件(999)');
});

await test('系统 feed：无 feed 特征 → null', () => {
  assert.strictEqual(parseSystemFeed({ foo: 1 }), null);
  assert.strictEqual(parseSystemFeed('not-json'), null);
  assert.strictEqual(parseSystemFeed(''), null);
  assert.strictEqual(parseSystemFeed(null), null);
});

await test('系统 feed：仅 leaver / member', () => {
  const t1 = parseSystemFeed({ feedType: 2, leaver: { nickName: '丁' } });
  assert.ok(t1.includes('退出聊天室'));
  assert.ok(t1.includes('丁'));
  const t2 = parseSystemFeed({ feedType: 3, member: { name: '戊' } });
  assert.ok(t2.includes('被踢出'));
  assert.ok(t2.includes('戊'));
});

await test('系统 feed：群名变更带 chatName', () => {
  const text = parseSystemFeed({ feedType: 5, chatName: '新群名' });
  assert.ok(text.includes('群名变更'));
  assert.ok(text.includes('新群名'));
});

await test('parseMessage type=0：走 system kind', () => {
  const p = parseMessage(JSON.stringify({ feedType: 1, inviter: { nickName: '甲' } }), 0);
  assert.strictEqual(p.kind, 'system');
  assert.ok(p.text.includes('邀请入群'));
});

await test('parseMessage type=1999：空占位', () => {
  const p = parseMessage(null, 1999);
  assert.strictEqual(p.kind, 'system');
  assert.strictEqual(p.text, '');
  assert.ok(p.detail.includes('占位'));
  assert.ok(renderMessageText(p, 1999).includes('系统记录'));
});

await test('parseMessage type=0：非 feed JSON 不误判为 system 文案优先', () => {
  // 无 feed 字段时，回落到后续 JSON 文本提取
  const p = parseMessage(JSON.stringify({ text: '普通内容' }), 0);
  // feed 解析返回 null，然后走 JSON text 字段
  assert.strictEqual(p.text, '普通内容');
});

await test('renderMessageText：空系统消息', () => {
  assert.strictEqual(renderMessageText({ text: '', kind: 'system', detail: null }, 0), '[系统]');
});

await test('图片空 message + attachment 描述', () => {
  const att = JSON.stringify({ path: 'a.jpg', alt: '照片', name: 'photo' });
  const p = parseMessage('', 2, att);
  assert.strictEqual(p.kind, 'attachment');
  assert.ok(p.text.includes('照片') || p.detail === 'a.jpg');
});

await test('messageTypeInfo：已知 / 未知类型', () => {
  assert.strictEqual(messageTypeInfo(2).label, '图片');
  assert.strictEqual(messageTypeInfo(27).label, '相册');
  assert.strictEqual(messageTypeInfo(18).label, '文件');
  assert.ok(messageTypeInfo(12345).label.includes('12345'));
});

await test('二进制非文本类型 → nontext', () => {
  const bytes = new Uint8Array([0, 1, 2, 3, 0, 0, 0]);
  const p = parseMessage(bytes, 2);
  assert.strictEqual(p.kind, 'nontext');
});

console.log(`\n结果：通过 ${passed}，失败 ${failed}`);
if (failed > 0) process.exit(1);
